/*
 * $Id: hncp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 14:04:22 2014 mstenber
 * Last modified: Mon Jun 15 12:09:05 2015 mstenber
 * Edit time:     674 min
 *
 */

/* This module implements the HNCP-based service discovery support.
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
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <libubox/md5.h>

#include "hncp_sd.h"
#include "hncp_i.h"
#include "dns_util.h"
#include "iface.h"

#define DNS_PORT 53

/* Provided to ohybridproxy */
#define LOCAL_OHP_AF "-4"
#define LOCAL_OHP_ADDRESS "127.0.0.2"
#define LOCAL_OHP_PORT 54

#define ARGS_MAX_LEN 512
#define ARGS_MAX_COUNT 64

/* Different 'daemons' to be restarted/reconfigured */
#define UPDATE_FLAG_DNSMASQ 1
#define UPDATE_FLAG_OHP     2
#define UPDATE_FLAG_PCP     4

/* TLVs to be updated (and possibly other internal state) */
#define UPDATE_FLAG_DDZ     0x10
#define UPDATE_FLAG_DOMAIN  0x20
#define UPDATE_FLAG_RNAME   0x40

#define UPDATE_FLAG_ALL     0x77

/* How long a timeout we schedule for the actual update (that occurs
 * in a timeout). This effectively sets an upper bound on how
 * frequently the dnsmasq/ohp scripts are called. If there's changes
 * that mutate system state, the timer gets reset. */
#define UPDATE_TIMEOUT 3000

/* As networks grow larger, there is no real guarantee this will
 * _ever_ get executed. Therefore, provide an upper bound at which
 * point we are guaranteed one update. Otherwise e.g. address
 * information may be invalid unacceptably long.*/
#define MAXIMUM_UPDATE_DELAY 10000

struct hncp_sd_struct
{
  hncp hncp;
  dncp dncp;

  /* HNCP notification subscriber structure */
  dncp_subscriber_s subscriber;

  /* Mask of what we need to update (in a timeout or at republish(ddz)). */
  int should_update;
  struct uloop_timeout timeout;
  hnetd_time_t initial_timeout_set;

  /* What we were given as router name base (or just 'r' by default). */
  char router_name_base[DNS_MAX_ESCAPED_L_LEN];
  char router_name[DNS_MAX_ESCAPED_L_LEN];
  /* how many iterations we've added to routername to get our current one. */
  int router_name_iteration;

  /* Parameters received when created (pointers within owned by someone else) */
  hncp_sd_params_s p;

  /* State (md5) hashes used to keep track of what has been committed. */
  char dnsmasq_state[16];
  char ohp_state[16];
  char pcp_state[16];

  /* Callbacks from other modules */
  struct iface_user iface;
  struct hncp_link_user link;
};

static void _should_update(hncp_sd sd, int v)
{
  L_DEBUG("hncp_sd/should_update:%d", v);
  sd->should_update |= v;
  /* Reset the timeout. We intentionally will not configure anything
   * until the churn slows down.*/
  if (!sd->timeout.pending)
    sd->initial_timeout_set = hnetd_time();
  if ((sd->initial_timeout_set + MAXIMUM_UPDATE_DELAY) >
      (hnetd_time() + UPDATE_TIMEOUT))
    uloop_timeout_set(&sd->timeout, UPDATE_TIMEOUT);
  else
    L_DEBUG(" .. already pending, and should be run");
}

/* Convenience wrapper around MD5 hashing */
static bool _sh_changed(md5_ctx_t *ctx, void *result)
{
  char buf[16];

  md5_end(buf, ctx);
  if (memcmp(buf, result, 16))
    {
      memcpy(result, buf, 16);
      return true;
    }
  return false;
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
      for (i = p->plen / 4 - 1 ; i >= 0 ; i--)
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
  DNS_PUSH_LABEL(buf, buf_len, (void *)1, 0);
  return buf - obuf;
}

const char *_rewrite_ifname(const char *src, char *dst)
{
  if (!dst)
    return NULL;
  const char *s = src;
  char *d = dst;
  while (true)
    {
      char c = *s++;
      if (c && !(isalpha(c) || (s != (src + 1) && isalnum(c))))
        c = '_';
      *d++ = c;
      if (!c)
        break;
    }
  return dst;
}

#define REWRITE_IFNAME(ifname)                          \
  _rewrite_ifname(ifname, alloca(strlen(ifname)+1))

void hncp_sd_dump_link_fqdn(hncp_sd sd, dncp_ep ep,
                            const char *ifname, char *buf, size_t buf_len)
{
  if (ep && ep->dnsname[0])
    {
      if (strcmp(ep->ifname, ep->dnsname)
          && strchr(ep->dnsname, '.'))
        {
          strncpy(buf, ep->dnsname, buf_len);
          return;
        }
      ifname = ep->dnsname;
    }
  ifname = REWRITE_IFNAME(ifname);
  snprintf(buf, buf_len, "%s.%s.%s",
           ifname, sd->router_name, sd->hncp->domain);
}

static void _publish_ddz(hncp_sd sd, dncp_ep ep,
                         int flags_forward,
                         struct prefix *assigned_prefix)
{
  hncp_t_dns_delegated_zone dh;
  unsigned char buf[sizeof(struct tlv_attr) +
                    sizeof(*dh) +
                    DNS_MAX_ESCAPED_LEN];
  char tbuf[DNS_MAX_ESCAPED_LEN];

  /* Forward DDZ handling (note: duplication doesn't matter) */
  dh = (void *)buf;
  memset(dh, 0, sizeof(*dh));
  struct in6_addr *a = hncp_get_ipv6_address(sd->hncp, ep->ifname);
  if (!a)
    return;
  *((struct in6_addr *)dh->address) = *a;
  hncp_sd_dump_link_fqdn(sd, ep, ep->ifname, tbuf, sizeof(tbuf));
  int r = escaped2ll(tbuf, dh->ll, DNS_MAX_ESCAPED_LEN);
  if (r < 0)
    return;
  int flen = sizeof(*dh) + r;
  dh->flags = flags_forward;
  dncp_add_tlv(sd->dncp, HNCP_T_DNS_DELEGATED_ZONE, dh, flen, 0);

  /* Reverse DDZ handling */
  /* (.ip6.arpa. or .in-addr.arpa.). */
  if (assigned_prefix)
    {
      r = _push_reverse_ll(assigned_prefix, dh->ll, DNS_MAX_ESCAPED_LEN);
      if (r < 0)
        return;
      flen = sizeof(*dh) + r;
      dh->flags = 0;
      dncp_add_tlv(sd->dncp, HNCP_T_DNS_DELEGATED_ZONE, dh, flen, 0);
    }
}

static void _publish_ddzs(hncp_sd sd)
{
  dncp_tlv t;
  hncp_t_assigned_prefix_header ah;
  dncp_ep ep;

  if (!(sd->should_update & UPDATE_FLAG_DDZ))
    return;
  sd->should_update &= ~UPDATE_FLAG_DDZ;
  L_DEBUG("_publish_ddzs");
  (void)dncp_remove_tlvs_by_type(sd->dncp, HNCP_T_DNS_DELEGATED_ZONE);
  dncp_for_each_tlv(sd->dncp, t)
    if ((ah = hncp_tlv_ap(dncp_tlv_get_attr(t))))
      {
        ep = dncp_find_ep_by_id(sd->dncp, ah->ep_id);

        /* May be just race condition or whatever, silently ignore */
        if (!ep)
          continue;

        struct prefix p;
        p.plen = ah->prefix_length_bits;
        memcpy(&p.prefix, ah->prefix_data, ROUND_BITS_TO_BYTES(p.plen));

        _publish_ddz(sd, ep, HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE
                     | HNCP_T_DNS_DELEGATED_ZONE_FLAG_LEGACY_BROWSE, &p);
      }

  /*
   * Second stage: publish DDZs ALSO for any other interface, but if
   * and only if there is no corresponding DDZ already (which has
   * browse flag set -> duplicate detection would not work).
   *
   * This applies to cases where someone else publishes AP, but we
   * want old names to work (or 'all' names to work, depending on your
   * point of view).
   */
  dncp_for_each_enabled_ep(sd->dncp, ep)
    {
      bool found = false;

      dncp_for_each_tlv(sd->dncp, t)
        if ((ah = hncp_tlv_ap(dncp_tlv_get_attr(t))))
          {
            if (ah->ep_id == dncp_ep_get_id(ep))
              {
                found = true;
                break;
              }
          }
      if (found)
        continue;
      /* Not found -> produce forward DDZ only. */
      _publish_ddz(sd, ep, 0, NULL);
    }
}

bool hncp_sd_write_dnsmasq_conf(hncp_sd sd, const char *filename)
{
  dncp_node n;
  struct tlv_attr *a;
  FILE *f = fopen(filename, "w");
  md5_ctx_t ctx;

  md5_begin(&ctx);
  if (!f)
    {
      L_ERR("unable to open %s for writing dnsmasq conf", filename);
      return false;
    }
  /* Basic idea: Traverse through the hncp node+tlv graph _once_,
   * producing appropriate configuration file.
   *
   * What do we need to take care of?
   * - <routername>.<domain>
   *
   * (These are all in DNS Delegated Zone TLVs)
   * - b._dns-sd._udp.<domain> => browseable domain
   * - lb._dns-sd._udp.<domain> => (legacy) browseable domain
   *
   * <subdomain>'s ~NS (remote, real IP)
   * <subdomain>'s ~NS (local, LOCAL_OHP_ADDRESS)
   */
  md5_hash(sd->hncp->domain, strlen(sd->hncp->domain), &ctx);
  dncp_for_each_node(sd->dncp, n)
    {
      dncp_node_for_each_tlv_with_type(n, a, HNCP_T_DNS_ROUTER_NAME) {
        int namelen = tlv_len(a) - sizeof(hncp_t_dns_router_name_s);
        if (namelen > 0 && namelen <= DNS_MAX_L_LEN)
          {
            hncp_t_dns_router_name rname = tlv_data(a);
            md5_hash(rname, tlv_len(a), &ctx);
            fprintf(f, "host-record=%.*s.%s,%s\n",
                    namelen, rname->name, sd->hncp->domain,
                    ADDR_REPR(&rname->address));
          }
      }

      dncp_node_for_each_tlv_with_type(n, a, HNCP_T_DNS_DELEGATED_ZONE)
        {
          /* Decode the labels */
          char buf[DNS_MAX_ESCAPED_LEN];
          char buf2[256];
          char *server;
          int port;
          hncp_t_dns_delegated_zone dh;

          if (tlv_len(a) < (sizeof(*dh)+1))
            continue;

          dh = tlv_data(a);
          if (ll2escaped(dh->ll, tlv_len(a) - sizeof(*dh),
                         buf, sizeof(buf)) < 0)
            continue;

          md5_hash(a, tlv_raw_len(a), &ctx);

          if (dh->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE)
            fprintf(f, "ptr-record=b._dns-sd._udp.%s,%s\n",
                    sd->hncp->domain, buf);
          if (dh->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_LEGACY_BROWSE)
            fprintf(f, "ptr-record=lb._dns-sd._udp.%s,%s\n",
                    sd->hncp->domain, buf);
          if (dncp_node_is_self(n))
            {
              server = LOCAL_OHP_ADDRESS;
              port = LOCAL_OHP_PORT;
            }
          else
            {
              server = buf2;
              port = DNS_PORT;
              if (!inet_ntop(AF_INET6, dh->address,
                             buf2, sizeof(buf2)))
                {
                  L_ERR("inet_ntop failed in hncp_sd_write_dnsmasq_conf");
                  continue;
                }
            }
          fprintf(f, "server=/%s/%s#%d\n", buf, server, port);
        }
    }
  /* Default is 150. Given 0.5 second lifetime on service queries,
   * that's not much. */
  fprintf(f, "dns-forward-max=12345\n");
  fclose(f);
  return _sh_changed(&ctx, &sd->dnsmasq_state);
}

bool hncp_sd_restart_dnsmasq(hncp_sd sd)
{
  char *args[] = { (char *)sd->p.dnsmasq_script, "restart", NULL};

  hncp_run(args);
  return true;
}

#define PUSH_ARG(s) do                                  \
    {                                                   \
      int _arg = narg++;                                \
      if (narg == ARGS_MAX_COUNT)                       \
        {                                               \
          L_DEBUG("too many arguments");                \
          return false;                                 \
        }                                               \
      if (strlen(s) + 1 + c > (buf + ARGS_MAX_LEN))     \
        {                                               \
          L_DEBUG("out of buffer");                     \
        }                                               \
      args[_arg] = c;                                   \
      strcpy(c, s);                                     \
      c += strlen(s) + 1;                               \
    } while(0)

bool hncp_sd_reconfigure_ohp(hncp_sd sd)
{
  dncp_ep ep;
  char buf[ARGS_MAX_LEN];
  char *c = buf;
  char *args[ARGS_MAX_COUNT];
  int narg = 0;
  char tbuf[DNS_MAX_ESCAPED_LEN+IFNAMSIZ+1];
  bool first = true;
  md5_ctx_t ctx;

  md5_begin(&ctx);
  PUSH_ARG(sd->p.ohp_script);

  /* ohp can _always_ listen to all interfaces that have been
   * configured. Less flapping of the binary, and it hurts nobody if
   * it is active on few more interfaces (well, fine, slight overhead
   * from mdnsresponder, but who cares). */

  for (struct iface *iface = iface_next(NULL); iface; iface = iface_next(iface))
    {
      if (!(iface->internal))
        continue;

      sprintf(tbuf, "%s=", iface->ifname);
      ep = dncp_find_ep_by_name(sd->dncp, iface->ifname);
      hncp_sd_dump_link_fqdn(sd, ep, iface->ifname,
                             tbuf+strlen(tbuf), sizeof(tbuf)-strlen(tbuf));

      md5_hash(tbuf, strlen(tbuf), &ctx);
      if (first)
        {
          char port[6];
          PUSH_ARG("start");
          PUSH_ARG(LOCAL_OHP_AF);
          PUSH_ARG("-a");
          PUSH_ARG(LOCAL_OHP_ADDRESS);
          PUSH_ARG("-p");
          sprintf(port, "%d", LOCAL_OHP_PORT);
          PUSH_ARG(port);
          first = false;
        }
      PUSH_ARG(tbuf);
    }

  if (first)
    {
      PUSH_ARG("stop");
    }
  args[narg] = NULL;
  if (_sh_changed(&ctx, &sd->ohp_state))
    {
      hncp_run(args);
      return true;
    }
  return false;
}

bool hncp_sd_reconfigure_pcp(hncp_sd sd)
{
  char buf[ARGS_MAX_LEN];
  char *c = buf;
  char *args[ARGS_MAX_COUNT];
  int narg = 0;
  bool first = true;
  md5_ctx_t ctx;
  dncp_node n;
  struct tlv_attr *tlv, *a;
  hncp_t_router_address ra;
  hncp_t_delegated_prefix_header dp;
  char tbuf[123];

  md5_begin(&ctx);
  PUSH_ARG(sd->p.pcp_script);

  /* ohp can _always_ listen to all interfaces that have been
   * configured. Less flapping of the binary, and it hurts nobody if
   * it is active on few more interfaces (well, fine, slight overhead
   * from mdnsresponder, but who cares). */

  dncp_for_each_node(sd->dncp, n)
    {
      struct in6_addr *a4 = NULL, *a6 = NULL;
      dncp_node_for_each_tlv_with_type(n, tlv, HNCP_T_EXTERNAL_CONNECTION)
        {
          if (!a4 && !a6)
            {
              dncp_node_for_each_tlv(n, a)
                {
                  if ((ra = hncp_tlv_ra(a)))
                    {
                      if (IN6_IS_ADDR_V4MAPPED(&ra->address))
                        a4 = &ra->address;
                      else
                        a6 = &ra->address;
                    }
                }
              /* If we don't know address for real, might as well give up */
              if (!a4 && !a6)
                {
                  L_DEBUG("no address at all found for %s",
                          DNCP_NODE_REPR(n));
                  break;
                }
            }
          tlv_for_each_attr(a, tlv)
            {
              if ((dp = hncp_tlv_dp(a)))
                {
                  struct prefix p = {.plen = dp->prefix_length_bits };
                  bmemcpy(&p.prefix, dp->prefix_data, 0, p.plen);

                  bool is_ipv4 = prefix_is_ipv4(&p);
                  struct in6_addr *sa = is_ipv4 ? a4 : a6;
                  if (!sa)
                    {
                      L_INFO("no PCP server found for %s", PREFIX_REPR(&p));
                      continue;
                    }

                  sprintf(tbuf, "%s=%s", PREFIX_REPR(&p),
                          dncp_node_is_self(n) ?
                          is_ipv4 ? "127.0.0.1" : "::1" :
                          ADDR_REPR(sa));
                  md5_hash(tbuf, strlen(tbuf), &ctx);
                  if (first)
                    {
                      PUSH_ARG("start");
                      first = false;
                    }
                  PUSH_ARG(tbuf);
                }
            }
        }
    }

  if (first)
    PUSH_ARG("stop");

  args[narg] = NULL;
  if (_sh_changed(&ctx, &sd->pcp_state))
    {
      hncp_run(args);
      return true;
    }
  return false;
}

static void
_election_cb(struct hncp_link_user *u,
             const char *ifname __unused,
             enum hncp_link_elected elected __unused)
{
  hncp_sd sd = container_of(u, hncp_sd_s, link);
  _should_update(sd, UPDATE_FLAG_OHP | UPDATE_FLAG_DDZ);
}

static void
_set_router_name(hncp_sd sd)
{
  size_t namelen = strlen(sd->router_name);
  hncp_t_dns_router_name rname = alloca(sizeof(*rname) + namelen);
  memcpy(rname->name, sd->router_name, namelen);

  dncp_remove_tlvs_by_type(sd->dncp, HNCP_T_DNS_ROUTER_NAME);

  if (!iface_get_preferred_address(&rname->address, false, NULL))
    dncp_add_tlv(sd->dncp, HNCP_T_DNS_ROUTER_NAME,
                 rname, sizeof(*rname) + namelen, 0);

  if (!iface_get_preferred_address(&rname->address, true, NULL))
    dncp_add_tlv(sd->dncp, HNCP_T_DNS_ROUTER_NAME,
                 rname, sizeof(*rname) + namelen, 0);
}

static bool
_tlv_router_name_matches(hncp_sd sd, struct tlv_attr *a)
{
  if (tlv_id(a) == HNCP_T_DNS_ROUTER_NAME)
    {
      hncp_t_dns_router_name rname = tlv_data(a);
      int namelen = tlv_len(a) - sizeof(*rname);
      if (namelen == (int)strlen(sd->router_name)
          && memcmp(rname->name, sd->router_name, namelen) == 0)
        return true;
    }
  return false;
}

static bool
_tlv_ddz_matches(hncp_sd sd, struct tlv_attr *a)
{
  /* Create the buffer we want to match against. */
  char buf[DNS_MAX_ESCAPED_L_LEN];
  unsigned char tbuf[DNS_MAX_L_LEN];
  int len;

  sprintf(buf, "%s.%s", sd->router_name, sd->hncp->domain);
  if ((len = escaped2ll(buf, tbuf, sizeof(tbuf)))<0)
    return false;
  if (tlv_id(a) == HNCP_T_DNS_DELEGATED_ZONE)
    {
      hncp_t_dns_delegated_zone ddz = tlv_data(a);
      if (tlv_len(a) > sizeof(*ddz))
        {
          unsigned char *tbuf2 = ddz->ll;
          int len2 = tlv_len(a) - sizeof(*ddz);
          /* XXX - do we want len2 == len, or len2 >= len?  len2 >=
           * len also matches 'well behaved' routers with subdomain
           * names but no own router name TLV for some reason, so I'm
           * tempted to keep the equality to defend just the router
           * name using this logic. */
          if (len2 == len && memcmp(tbuf2 + (len2 - len), tbuf, len) == 0)
            return true;
        }
    }
  return false;
}

static dncp_node
_find_router_name(hncp_sd sd)
{
  dncp_node n;
  struct tlv_attr *a;

  dncp_for_each_node(sd->dncp, n)
    {
      dncp_node_for_each_tlv_with_type(n, a, HNCP_T_DNS_ROUTER_NAME)
        {
          if (_tlv_router_name_matches(sd, a))
            return n;
        }
    }
  return NULL;
}

static void
_change_router_name(hncp_sd sd)
{
  /* Try to look for new one. */
  while (1)
    {
      sprintf(sd->router_name, "%s%d",
              sd->router_name_base, ++sd->router_name_iteration);
      if (!_find_router_name(sd))
        {
          L_DEBUG("renamed to %s", sd->router_name);
          _set_router_name(sd);
          _should_update(sd, UPDATE_FLAG_DDZ);
          return;
        }
    }
}

static void _local_tlv_cb(dncp_subscriber s,
                          struct tlv_attr *tlv, bool add __unused)
{
  hncp_sd sd = container_of(s, hncp_sd_s, subscriber);

  /* Note also assigned prefix changes here; they mean our published
   * zone information is no longer valid and should be republished at
   * some point. OHP configuration may also change at this point. */
  if (tlv_id(tlv) == HNCP_T_ASSIGNED_PREFIX)
    {
      _should_update(sd, UPDATE_FLAG_DDZ);
    }
}

static struct tlv_attr *_get_dns_domain_tlv(hncp_sd sd)
{
  dncp_node n;
  struct tlv_attr *a, *best = NULL;

  dncp_for_each_node(sd->dncp, n)
    {
      dncp_node_for_each_tlv_with_type(n, a, HNCP_T_DNS_DOMAIN_NAME)
        best = a;
    }
  return best;
}

static void _get_dns_domain(hncp_sd sd, char *dest, int dest_len)
{
  struct tlv_attr *a = _get_dns_domain_tlv(sd);

  if (a && ll2escaped(tlv_data(a), tlv_len(a), dest, dest_len) > 0)
    return;
  strncpy(dest, HNCP_SD_DEFAULT_DOMAIN, dest_len);
}


static void _refresh_domain(hncp_sd sd)
{
  char new_domain[DNS_MAX_ESCAPED_LEN];

  if (!(sd->should_update & UPDATE_FLAG_DOMAIN))
    return;
  sd->should_update &= ~UPDATE_FLAG_DOMAIN;
  _get_dns_domain(sd, new_domain, sizeof(new_domain));
  L_DEBUG("_refresh_domain:%s", new_domain);
  if (strcmp(new_domain, sd->hncp->domain))
    {
      L_DEBUG("set sd domain to %s", new_domain);
      strcpy(sd->hncp->domain, new_domain);
      _should_update(sd, UPDATE_FLAG_ALL & ~UPDATE_FLAG_DOMAIN);
    }
}

static void _refresh_rname(hncp_sd sd)
{
  if (!(sd->should_update & UPDATE_FLAG_RNAME))
    return;
  sd->should_update &= ~UPDATE_FLAG_RNAME;
  L_DEBUG("_refresh_rname");
  _set_router_name(sd);
}

static void _tlv_cb(dncp_subscriber s,
                    dncp_node n, struct tlv_attr *tlv, bool add)
{
  hncp_sd sd = container_of(s, hncp_sd_s, subscriber);
  dncp o = sd->dncp;

  L_NOTICE("[sd]_tlv_cb %s %s %s",
           add ? "add" : "remove",
           dncp_node_is_self(n) ? "local" : DNCP_NODE_REPR(n),
           TLV_REPR(tlv));
  switch (tlv_id(tlv))
    {
    case HNCP_T_DNS_ROUTER_NAME:
      /* Handle router name collision detection; we're interested only in
       * nodes with higher router id overriding our choice. */
      if (add
          && !dncp_node_is_self(n)
          && _tlv_router_name_matches(sd, tlv))
        {
          if (dncp_node_cmp(n, dncp_get_own_node(o)) > 0)
            {
              L_DEBUG("router name conflict, we're lower, renaming");
              _change_router_name(sd);
            }
          else
            {
              L_DEBUG("router name conflict, we're higher, ignoring");
            }
        }
      /* Router name/address changes trigger dnsmasq update due to
       * synthesized <routername>.<domain> host records. */
      _should_update(sd, UPDATE_FLAG_DNSMASQ);
      break;

    case HNCP_T_DNS_DELEGATED_ZONE:
      /* Dnsmasq forwarder file reflects what's in published DDZ's. If
       * they change, it (could) change too. */
      _should_update(sd, UPDATE_FLAG_DNSMASQ);

      /* Check also if it's name matches our router name directly ->
       * rename us if it does. */
      if (_tlv_ddz_matches(sd, tlv) && !dncp_node_is_self(n))
        {
          L_DEBUG("found matching DDZ with our router name -> force rename");
          _change_router_name(sd);
        }
      break;

    case HNCP_T_DNS_DOMAIN_NAME:
      /* As the TLVs aren't _yet_ valid on the node, there's a race
       * condition potential here. So we just do things after a
       * timeout. */
      _should_update(sd, UPDATE_FLAG_DOMAIN);
      break;

    case HNCP_T_ROUTER_ADDRESS:
      /* Router name/address changes trigger dnsmasq update due to
       * synthesized <routername>.<domain> host records. */
      /* Addresses of where to find PCP server may also have changed */
      _should_update(sd, UPDATE_FLAG_DNSMASQ | UPDATE_FLAG_PCP);
      break;

    case HNCP_T_EXTERNAL_CONNECTION:
      /* Delegated prefixes may have changed -> possibly update PCP */
      _should_update(sd, UPDATE_FLAG_PCP);
      break;

    }
}


void hncp_sd_update(hncp_sd sd)
{
  L_DEBUG("hncp_sd_update:%d", sd->should_update);

  /* First the always present, internal state mutating things.. */
  _refresh_rname(sd);
  _refresh_domain(sd);
  _publish_ddzs(sd);

  /* Then play with external scripts, if they are present */
  if (sd->should_update & UPDATE_FLAG_DNSMASQ)
    {
      sd->should_update &= ~UPDATE_FLAG_DNSMASQ;
      if (sd->p.dnsmasq_script && sd->p.dnsmasq_bonus_file)
        {
          if (hncp_sd_write_dnsmasq_conf(sd, sd->p.dnsmasq_bonus_file))
            hncp_sd_restart_dnsmasq(sd);
        }
    }
  if (sd->should_update & UPDATE_FLAG_OHP)
    {
      sd->should_update &= ~UPDATE_FLAG_OHP;
      if (sd->p.ohp_script)
        hncp_sd_reconfigure_ohp(sd);
    }
  if (sd->should_update & UPDATE_FLAG_PCP)
    {
      sd->should_update &= ~UPDATE_FLAG_PCP;
      if (sd->p.pcp_script)
        hncp_sd_reconfigure_pcp(sd);
    }
  if (sd->should_update)
    L_DEBUG("hncp_sd_update leftovers:%d", sd->should_update);
}

static void _timeout_cb(struct uloop_timeout *t)
{
  hncp_sd sd = container_of(t, hncp_sd_s, timeout);

  hncp_sd_update(sd);
}


static void _republish_cb(dncp_subscriber s)
{
  hncp_sd sd = container_of(s, hncp_sd_s, subscriber);

  _refresh_domain(sd);
  _publish_ddzs(sd);
}

static void _force_republish_cb(dncp_subscriber s, dncp_ep ep __unused,
                                enum dncp_subscriber_event event __unused)
{
  hncp_sd sd = container_of(s, hncp_sd_s, subscriber);

  _should_update(sd, UPDATE_FLAG_ALL);
}

static void _intaddr_cb(struct iface_user *u, __unused const char *ifname,
                        __unused const struct prefix *addr6,
                        __unused const struct prefix *addr4)
{
  hncp_sd sd = container_of(u, hncp_sd_s, iface);

  _should_update(sd, UPDATE_FLAG_RNAME | UPDATE_FLAG_DDZ);
}


hncp_sd hncp_sd_create(hncp h, hncp_sd_params p, struct hncp_link *l)
{
  hncp_sd sd = calloc(1, sizeof(*sd));
  dncp o = h->dncp;

  sd->hncp = h;
  sd->dncp = o;
  sd->timeout.cb = _timeout_cb;
  sd->p = *p;
  if (!sd)
    return NULL;

  sd->iface.cb_intaddr = _intaddr_cb;
  sd->link.cb_elected = _election_cb;
  iface_register_user(&sd->iface);

  if (l)
    hncp_link_register(l, &sd->link);

  /* Handle domain name */
  if (p->domain_name)
    {
      uint8_t ll[DNS_MAX_LL_LEN];
      int len;
      len = escaped2ll(p->domain_name, ll, sizeof(ll));
      if (len < 0)
        {
          L_ERR("invalid domain:%s", p->domain_name);
          abort();
        }
      dncp_add_tlv(o, HNCP_T_DNS_DOMAIN_NAME, ll, len, 0);

      strncpy(sd->hncp->domain, p->domain_name, DNS_MAX_ESCAPED_LEN);
    }
  else
    strcpy(sd->hncp->domain, HNCP_SD_DEFAULT_DOMAIN);

  /* Handle router name */
  if (p->router_name)
    strcpy(sd->router_name_base, p->router_name);
  else
    strcpy(sd->router_name_base, "r");
  strcpy(sd->router_name, sd->router_name_base);
  _set_router_name(sd);

  /* Set up the hncp subscriber */
  sd->subscriber.local_tlv_change_callback = _local_tlv_cb;
  sd->subscriber.tlv_change_callback = _tlv_cb;
  sd->subscriber.republish_callback = _republish_cb;
  sd->subscriber.link_change_callback = _force_republish_cb;
  dncp_subscribe(o, &sd->subscriber);

  return sd;
}

void hncp_sd_destroy(hncp_sd sd)
{
  iface_unregister_user(&sd->iface);
  dncp_unsubscribe(sd->dncp, &sd->subscriber);
  uloop_timeout_cancel(&sd->timeout);
  free(sd);
}

bool hncp_sd_busy(hncp_sd sd)
{
  return sd->should_update;
}
