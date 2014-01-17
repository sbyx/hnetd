/*
 * $Id: hcp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 14:04:22 2014 mstenber
 * Last modified: Fri Jan 17 12:16:45 2014 mstenber
 * Edit time:     232 min
 *
 */

/* This module implements the HCP-based service discovery support.
 *
 * By default, if this isn't enabled, _normal_ DNS based activity
 * across a network should still work (thanks to DNS servers being
 * transmitted as part of prefix options for delegated prefixes and
 * configured appropriately to the clients), but this module provides
 * two extra 'features':
 *
 * - dns-sd configuration for dnsmasq (both records and remote servers)
 *
 * - maintenance of running hybrid proxy on the desired interfaces
 *
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "hcp_sd.h"
#include "hcp_i.h"
#include "dns_util.h"

#define LOCAL_OHP_ADDRESS "127.0.0.2"
#define OHP_ARGS_MAX_LEN 512
#define OHP_ARGS_MAX_COUNT 64

/* How long a timeout we schedule for the actual reconfiguration. This
 * effectively sets an upper bound on how frequently the dnsmasq/ohp
 * scripts are called too. */
#define RECONFIGURE_TIMEOUT 100

#define TIMEOUT_FLAG_DNSMASQ 1
#define TIMEOUT_FLAG_OHP 2
#define TIMEOUT_FLAG_ALL 3

struct hcp_sd_struct
{
  hcp hcp;

  /* HCP notification subscriber structure */
  hcp_subscriber_s subscriber;

  /* Should republish ddz's (during the next self-publish callback) */
  bool should_republish_ddz;

  /* Mask of what we need to reconfigure (in a timeout). */
  int should_timeout;
  struct uloop_timeout timeout;

  /* What we were given as router name base (or just 'r' by default). */
  char router_name_base[DNS_MAX_ESCAPED_L_LEN];
  char router_name[DNS_MAX_ESCAPED_L_LEN];
  /* how many iterations we've added to routername to get our current one. */
  int router_name_iteration;

  char domain[DNS_MAX_ESCAPED_LEN];
  char *dnsmasq_script;
  char *dnsmasq_bonus_file;
  char *ohp_script;
};


/* Utility function glommed from platform-generic platform_exec/call. */
static void _fork_execv(char *argv[])
{
  pid_t pid = vfork();

  L_DEBUG("hcp_sd calling %s", argv[0]);
  if (pid == 0) {
    execv(argv[0], argv);
    _exit(128);
  }
  waitpid(pid, NULL, 0);
}

static void _should_timeout(hcp_sd sd, int v)
{
  L_DEBUG("hcp_sd/should_timeout:%d", v);
  if ((sd->should_timeout & v) == v)
    return;
  sd->should_timeout |= v;
  /* Schedule the timeout (note: we won't configure anything until the
   * churn slows down. This is intentional.) */
  uloop_timeout_set(&sd->timeout, RECONFIGURE_TIMEOUT);
}

static int _push_reverse_ll(struct prefix *p, uint8_t *buf, int buf_len)
{
  uint8_t *obuf = buf;
  int i;

  if (prefix_is_ipv4(p))
    {
      /* XXX - not sure what plen should be for IPv4 :p */
      /* We care only about last 4 bytes, and only full ones at that
       * (hopefully that will never be a problem). */
      for (i = p->plen / 8 - 1 ; i >= 12 ; i--)
        {
          unsigned char c = p->prefix.s6_addr[i];
          char tbuf[4];
          sprintf(tbuf, "%d", c);

          DNS_PUSH_LABEL_STRING(buf, buf_len, tbuf);
        }
      DNS_PUSH_LABEL_STRING(buf, buf_len, "in-addr");
    }
  else
    {
      for (i = p->plen / 4 ; i >= 0 ; i--)
        {
          unsigned char c = p->prefix.s6_addr[i / 2];
          char tbuf[2];

          if (i % 2)
            c = c & 0xF;
          else
            c = c >> 4;
          sprintf(tbuf, "%x", c);

          DNS_PUSH_LABEL_STRING(buf, buf_len, tbuf);
        }
      DNS_PUSH_LABEL_STRING(buf, buf_len, "ip6");
    }
  DNS_PUSH_LABEL_STRING(buf, buf_len, "arpa");
  DNS_PUSH_LABEL(buf, buf_len, NULL, 0);
  return buf - obuf;
}

static void _republish_ddzs(hcp_sd sd)
{
  struct tlv_attr *a;
  int i;
  hcp_tlv t;
  hcp_t_assigned_prefix_header ah;

  if (!sd->should_republish_ddz)
    return;
  sd->should_republish_ddz = false;
  hcp_node_for_each_tlv_i(sd->hcp->own_node, a, i)
    if (tlv_id(a) == HCP_T_DNS_DELEGATED_ZONE)
      (void)hcp_remove_tlv(sd->hcp, a);
  vlist_for_each_element(&sd->hcp->tlvs, t, in_tlvs)
    {
      a = &t->tlv;
      if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
        {
          /* Forward DDZ handling */
          hcp_t_dns_delegated_zone dh;
          unsigned char buf[sizeof(struct tlv_attr) +
                            sizeof(*dh) +
                            DNS_MAX_ESCAPED_LEN];
          struct tlv_attr *na;
          int r, flen;
          char tbuf[DNS_MAX_ESCAPED_LEN];
          char link_name[10];
          struct in6_addr our_addr;
          char ifname_buf[IFNAMSIZ];

          if (!hcp_tlv_ap_valid(a))
            continue;

          ah = tlv_data(a);
          /* Should publish DDZ entry. */
          uint32_t link_id = be32_to_cpu(ah->link_id);

          sprintf(link_name, "i%d", link_id);
          sprintf(tbuf, "%s.%s.%s", link_name, sd->router_name, sd->domain);

          if (!hcp_io_get_ipv6(&our_addr, if_indextoname(link_id, ifname_buf)))
            continue;

          na = (struct tlv_attr *)buf;
          dh = tlv_data(na);
          memset(dh, 0, sizeof(*dh));
          memcpy(dh->address, &our_addr, 16);
          r = escaped2ll(tbuf, dh->ll, DNS_MAX_ESCAPED_LEN);
          if (r < 0)
            continue;
          flen = TLV_SIZE + sizeof(*dh) + r;
          dh->flags = HCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE;
          tlv_init(na, HCP_T_DNS_DELEGATED_ZONE, flen);
          tlv_fill_pad(na);
          hcp_add_tlv(sd->hcp, na);

          /* Reverse DDZ handling */
          /* (no BROWSE flag, .ip6.arpa. or .in-addr.arpa.). */
          struct prefix p;
          p.plen = ah->prefix_length_bits;
          memcpy(&p.prefix, ah->prefix_data, ROUND_BITS_TO_BYTES(p.plen));
          r = _push_reverse_ll(&p, dh->ll, DNS_MAX_ESCAPED_LEN);
          if (r < 0)
            continue;
          flen = TLV_SIZE + sizeof(*dh) + r;
          dh->flags = 0;
          tlv_init(na, HCP_T_DNS_DELEGATED_ZONE, flen);
          tlv_fill_pad(na);
          hcp_add_tlv(sd->hcp, na);
        }
    }
  /* If DDZ data changed that we publish, we should probably
   * reconfigure dnsmasq+ohp at some point too. */
  _should_timeout(sd, TIMEOUT_FLAG_ALL);
}

bool hcp_sd_write_dnsmasq_conf(hcp_sd sd, const char *filename)
{
  hcp_node n;
  struct tlv_attr *a;
  int i;
  FILE *f = fopen(filename, "w");

  /* Basic idea: Traverse through the hcp node+tlv graph _once_,
   * producing appropriate configuration file.
   *
   * What do we need to take care of?
   * - b._dns-sd._udp.<domain> => browseable domain
   * <subdomain>'s ~NS (remote, real IP)
   * <subdomain>'s ~NS (local, LOCAL_OHP_ADDRESS)
   */
  hcp_for_each_node(sd->hcp, n)
    {
      hcp_node_for_each_tlv_i(n, a, i)
        if (tlv_id(a) == HCP_T_DNS_DELEGATED_ZONE)
          {
            /* Decode the labels */
            char buf[DNS_MAX_ESCAPED_LEN];
            char buf2[256];
            char *server;
            hcp_t_dns_delegated_zone dh;

            if (tlv_len(a) < (sizeof(*dh)+1))
              continue;

            dh = tlv_data(a);
            if (ll2escaped(dh->ll, tlv_len(a) - sizeof(*dh),
                           buf, sizeof(buf)) < 0)
              continue;

            if (dh->flags & HCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE)
              fprintf(f, "ptr-record=b._dns-sd._udp.%s,%s\n",
                      sd->domain, buf);
            if (hcp_node_is_self(n))
              {
                server = LOCAL_OHP_ADDRESS;
                /* Ignore ones without flags - we just assume they're
                 * reverse .arpa. ones for now. */
                if (!dh->flags)
                  continue;
              }
            else
              {
                server = buf2;
                if (!inet_ntop(AF_INET6, dh->address,
                               buf2, sizeof(buf2)))
                  {
                    L_ERR("inet_ntop failed in hcp_sd_write_dnsmasq_conf");
                    continue;
                  }
              }
            fprintf(f, "server=/%s/%s\n", server, buf);
          }
    }
  fclose(f);
  return true;
}

bool hcp_sd_restart_dnsmasq(hcp_sd sd)
{
  char *args[] = { (char *)sd->dnsmasq_script, "restart", NULL};

  _fork_execv(args);
  return true;
}


#define PUSH_ARG(s) do                                  \
{                                                       \
  int _arg = narg++;                                    \
  if (narg == OHP_ARGS_MAX_COUNT)                       \
  {                                                     \
    L_DEBUG("too many arguments");                      \
    return false;                                       \
  }                                                     \
  if (strlen(s) + 1 + c > (buf + OHP_ARGS_MAX_LEN))     \
    {                                                   \
      L_DEBUG("out of buffer");                         \
    }                                                   \
  args[_arg] = c;                                       \
  strcpy(c, s);                                         \
  c += strlen(s) + 1;                                   \
} while(0)

bool hcp_sd_reconfigure_ohp(hcp_sd sd)
{
  char buf[OHP_ARGS_MAX_LEN];
  char *c = buf;
  char *args[OHP_ARGS_MAX_COUNT];
  int narg = 0;
  uint32_t dumped_link_id = 0;
  hcp_t_assigned_prefix_header ah;
  char tbuf[DNS_MAX_ESCAPED_LEN];
  char link_name[10];

  struct tlv_attr *a;
  int i;
  bool first = true;

  if (!sd->ohp_script)
    {
      L_ERR("no ohp_script set yet hcp_sd_reconfigure_ohp called");
      return false;
    }
  PUSH_ARG(sd->ohp_script);

  /* We're responsible only for those interfaces that we have assigned
   * prefix for. */
  hcp_node_for_each_tlv_i(sd->hcp->own_node, a, i)
    if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
      {
        char lbuf[IFNAMSIZ];

        ah = tlv_data(a);
        /* If we already dumped this link, no need to do it
         * again. (Data structure is sorted by link id -> we will get
         * them in order). */
        if (dumped_link_id == ah->link_id)
          continue;
        dumped_link_id = ah->link_id;
        uint32_t link_id = be32_to_cpu(dumped_link_id);

        /* XXX - what sort of naming scheme should we use for links? */
        sprintf(link_name, "i%d", link_id);
        if (!if_indextoname(link_id, lbuf))
          {
            L_ERR("unable to find index name for %u", link_id);
            continue;
          }
        sprintf(tbuf, "%s=%s.%s.%s",
                lbuf, link_name, sd->router_name, sd->domain);
        if (first)
          {
            PUSH_ARG("start");
            PUSH_ARG("-a");
            PUSH_ARG(LOCAL_OHP_ADDRESS);
            first = false;
          }
        PUSH_ARG(tbuf);
      }
  if (first)
    {
      PUSH_ARG("stop");
    }
  args[narg] = NULL;
  _fork_execv(args);
  return true;
}

static void
_set_router_name(hcp_sd sd, bool add)
{
  /* Set the current router name. */
  unsigned char buf[sizeof(struct tlv_attr) + DNS_MAX_ESCAPED_L_LEN + 5];
  struct tlv_attr *a = (struct tlv_attr *)buf;
  int rlen = strlen(sd->router_name);

  tlv_init(a, HCP_T_DNS_ROUTER_NAME, TLV_SIZE + rlen);
  memcpy(tlv_data(a), sd->router_name, rlen);
  tlv_fill_pad(a);
  if (add)
    {
      if (!hcp_add_tlv(sd->hcp, a))
        L_ERR("failed to add router name TLV");
      sd->should_republish_ddz = true;
    }
  else
    {
      if (!hcp_remove_tlv(sd->hcp, a))
        L_ERR("failed to remove router name TLV");
    }
}

static bool
_tlv_router_name_matches(hcp_sd sd, struct tlv_attr *a)
{
    if (tlv_id(a) == HCP_T_DNS_ROUTER_NAME)
      {
        if (tlv_len(a) == strlen(sd->router_name)
            && strncmp(tlv_data(a), sd->router_name, tlv_len(a)) == 0)
          return true;
      }
    return false;
}

static hcp_node
_find_router_name(hcp_sd sd)
{
  hcp_node n;
  struct tlv_attr *a;
  int i;

  hcp_for_each_node(sd->hcp, n)
    {
      hcp_node_for_each_tlv_i(n, a, i)
        {
          if (_tlv_router_name_matches(sd, a))
            return n;
        }
    }
    return NULL;
}

static void
_change_router_name(hcp_sd sd)
{
  /* Remove the old name. */
  _set_router_name(sd, false);

  /* Try to look for new one. */
  while (1)
    {
      sprintf(sd->router_name, "%s%d",
              sd->router_name_base, ++sd->router_name_iteration);
      if (!_find_router_name(sd))
        {
          _set_router_name(sd, true);
          return;
        }
    }
}

static void _local_tlv_cb(hcp_subscriber s,
                          struct tlv_attr *tlv, bool add __unused)
{
  hcp_sd sd = container_of(s, hcp_sd_s, subscriber);

  /* Note also assigned prefix changes here; they mean our published zone
   * information is no longer valid and should be republished at some point. */
  if (tlv_id(tlv) == HCP_T_ASSIGNED_PREFIX)
    sd->should_republish_ddz = true;
  /* This will implicitly also trigger dnsmasq+ohp reconf. */
}

static void _republish_cb(hcp_subscriber s)
{
  hcp_sd sd = container_of(s, hcp_sd_s, subscriber);

  _republish_ddzs(sd);
}

static void _tlv_cb(hcp_subscriber s,
                    hcp_node n, struct tlv_attr *tlv, bool add)
{
  hcp_sd sd = container_of(s, hcp_sd_s, subscriber);
  hcp o = sd->hcp;

  /* Handle router name collision detection; we're interested only in
   * nodes with higher router id overriding our choice. */
  if (tlv_id(tlv) == HCP_T_DNS_ROUTER_NAME)
    {
      if (add
          && _tlv_router_name_matches(sd, tlv)
          && hcp_node_cmp(n, o->own_node) > 0)
        _change_router_name(sd);
      /* Router name itself should not trigger reconfiguration unless
       * local; however, remote DDZ changes should. */
    }

  /* Local updates will cause TIMEOUT_FLAG_ALL at some
   * point from ddz update; remote ones should only reconfigure
   * dnsmasq at most. */
  if (!hcp_node_is_self(n)
      && (tlv_id(tlv) == HCP_T_ASSIGNED_PREFIX
          || tlv_id(tlv) == HCP_T_DNS_DELEGATED_ZONE))
    _should_timeout(sd, TIMEOUT_FLAG_DNSMASQ);
}

static void _timeout_cb(struct uloop_timeout *t)
{
  hcp_sd sd = container_of(t, hcp_sd_s, timeout);
  int v = sd->should_timeout;

  L_DEBUG("hcp_sd/timeout:%d", v);
  sd->should_timeout = 0;
  if (v & TIMEOUT_FLAG_DNSMASQ)
    {
      if (hcp_sd_write_dnsmasq_conf(sd, sd->dnsmasq_bonus_file))
        hcp_sd_restart_dnsmasq(sd);
    }
  if (v & TIMEOUT_FLAG_OHP)
    {
      hcp_sd_reconfigure_ohp(sd);
    }
}


hcp_sd hcp_sd_create(hcp h,
                     const char *dnsmasq_script,
                     const char *dnsmasq_bonus_file,
                     const char *ohp_script,
                     const char *router_name)
{
  hcp_sd sd = calloc(1, sizeof(*sd));

  sd->hcp = h;
  sd->timeout.cb = _timeout_cb;
  if (!sd
      || !(sd->dnsmasq_script = strdup(dnsmasq_script))
      || !(sd->dnsmasq_bonus_file = strdup(dnsmasq_bonus_file))
      || !(sd->ohp_script = strdup(ohp_script)))
    abort();
  if (router_name)
    strcpy(sd->router_name_base, router_name);
  else
    strcpy(sd->router_name_base, "r");
  strcpy(sd->router_name, sd->router_name_base);
  /* XXX - handle domain TLV for this. */
  strcpy(sd->domain, "home.");
  _set_router_name(sd, true);
  sd->subscriber.local_tlv_change_callback = _local_tlv_cb;
  sd->subscriber.tlv_change_callback = _tlv_cb;
  sd->subscriber.republish_callback = _republish_cb;
  hcp_subscribe(h, &sd->subscriber);
  return sd;
}

void hcp_sd_destroy(hcp_sd sd)
{
  uloop_timeout_cancel(&sd->timeout);
  hcp_unsubscribe(sd->hcp, &sd->subscriber);
  free(sd->dnsmasq_script);
  free(sd->dnsmasq_bonus_file);
  free(sd->ohp_script);
  free(sd);
}
