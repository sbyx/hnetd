/*
 * $Id: hcp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 14:04:22 2014 mstenber
 * Last modified: Wed Jan 15 14:55:26 2014 mstenber
 * Edit time:     170 min
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

#include "hcp_sd.h"
#include "hcp_i.h"
#include "dns_util.h"

#define LOCAL_OHP_ADDRESS "127.0.0.2"
#define OHP_ARGS_MAX_LEN 512
#define OHP_ARGS_MAX_COUNT 64

struct hcp_sd_struct
{
  hcp h;

  /* HCP notification subscriber structure */
  hcp_subscriber_s subscriber;

  /* Should republish ddz's */
  bool should_republish_ddz;

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
  if (pid == 0) {
    execv(argv[0], argv);
    _exit(128);
  }
  waitpid(pid, NULL, 0);
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
  hcp_node_for_each_tlv_i(sd->h->own_node, a, i)
    if (tlv_id(a) == HCP_T_DNS_DELEGATED_ZONE)
      (void)hcp_remove_tlv(sd->h, a);
  vlist_for_each_element(&sd->h->tlvs, t, in_tlvs)
    {
      a = &t->tlv;
      if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
        {
          hcp_t_dns_delegated_zone dh;
          unsigned char buf[sizeof(struct tlv_attr) +
                            sizeof(*dh) +
                            DNS_MAX_ESCAPED_LEN];
          struct tlv_attr *na;
          int r;
          char tbuf[DNS_MAX_ESCAPED_LEN];
          char link_name[10];
          struct in6_addr our_addr;
          char ifname_buf[IFNAMSIZ];

          /* Should publish DDZ entry. */
          ah = tlv_data(a);
          uint32_t link_id = be32_to_cpu(ah->link_id);

          sprintf(link_name, "i%d", link_id);
          sprintf(tbuf, "%s.%s.%s", link_name, sd->router_name, sd->domain);

          if (!hcp_io_get_ipv6(&our_addr, if_indextoname(link_id, ifname_buf)))
            continue;

          na = (struct tlv_attr *)buf;
          dh = tlv_data(na);
          memcpy(dh->address, &our_addr, 16);
          r = escaped2ll(tbuf, dh->ll, DNS_MAX_ESCAPED_LEN);
          if (r < 0)
            continue;
          int flen = TLV_SIZE + sizeof(*dh) + r;
          memset(dh, 0, sizeof(*dh));
          dh->flags = HCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE;
          tlv_init(a, HCP_T_DNS_DELEGATED_ZONE, flen);
          hcp_add_tlv(sd->h, na);

          /* XXX - create reverse DDZ entry too (no BROWSE flag, .ip6.arpa). */
        }
    }
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
  hcp_for_each_node(sd->h, n)
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
  char *args[] = { (char *)sd->dnsmasq_script, NULL};

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

  if (!sd->ohp_script)
    {
      L_ERR("no ohp_script set yet hcp_sd_reconfigure_ohp called");
      return false;
    }
  PUSH_ARG(sd->ohp_script);

  /* We're responsible only for those interfaces that we have assigned
   * prefix for. */
  hcp_node_for_each_tlv_i(sd->h->own_node, a, i)
    if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
      {
        ah = tlv_data(a);
        /* If we already dumped this link, no need to do it
         * again. (Data structure is sorted by link id -> we will get
         * them in order). */
        if (dumped_link_id == ah->link_id)
          continue;
        dumped_link_id = ah->link_id;
        /* XXX - what sort of naming scheme should we use for links? */
        sprintf(link_name, "i%d", be32_to_cpu(dumped_link_id));
        sprintf(tbuf, "%s.%s.%s", link_name, sd->router_name, sd->domain);
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
  if (add)
    {
      if (!hcp_add_tlv(sd->h, a))
        L_ERR("failed to add router name TLV");
      sd->should_republish_ddz = true;
    }
  else
    {
      if (!hcp_remove_tlv(sd->h, a))
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

  hcp_for_each_node(sd->h, n)
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
      sprintf(sd->router_name, "%s-%d",
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
  hcp o = sd->h;

  /* Handle router name collision detection; we're interested only in
   * nodes with higher router id overriding our choice. */
  if (add
      && _tlv_router_name_matches(sd, tlv)
      && hcp_node_cmp(n, o->own_node) > 0)
    {
      _change_router_name(sd);
    }
}

hcp_sd hcp_sd_create(hcp h,
                     const char *dnsmasq_script,
                     const char *dnsmasq_bonus_file,
                     const char *ohp_script,
                     const char *router_name)
{
  hcp_sd sd = calloc(1, sizeof(*sd));

  sd->h = h;
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
  hcp_unsubscribe(sd->h, &sd->subscriber);
  free(sd->dnsmasq_script);
  free(sd->dnsmasq_bonus_file);
  free(sd->ohp_script);
  free(sd);
}
