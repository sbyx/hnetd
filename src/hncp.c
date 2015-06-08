/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 14:50:58 2014 mstenber
 * Last modified: Mon Jun  8 12:17:58 2015 mstenber
 * Edit time:     69 min
 *
 */

#include "hncp_i.h"
#include "hncp_io.h"

#include <libubox/md5.h>

/* TBD - make these separate callbacks into utility library? */

static bool hncp_handle_collision_randomly(dncp_ext ext)
{
  hncp h = container_of(ext, hncp_s, ext);
  dncp o = h->dncp;
  int nilen = ext->conf.node_identifier_length;
  char *nibuf = alloca(nilen);
  int i;

  L_ERR("second+ collision -> changing node identifier");
  for (i = 0; i < nilen; i++)
    nibuf[i] = random() % 256;
  return dncp_set_own_node_identifier(o, nibuf);
}


static void hncp_hash_md5(const void *buf, size_t len, void *dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}


static struct tlv_attr *
hncp_validate_node_data(dncp_node n, struct tlv_attr *a)
{
  uint8_t version = 0;
#if L_LEVEL >= LOG_ERR
  const char *agent = NULL;
  int agent_len = 0;
#endif /* L_LEVEL >= LOG_ERR */
  struct tlv_attr *va, *a_valid = a;
  dncp o = dncp_node_get_dncp(n);
  dncp_node on = dncp_get_own_node(o);
  hncp_node onh = dncp_node_get_ext_data(on);
  hncp_node nh = dncp_node_get_ext_data(n);

  tlv_for_each_attr(va, a)
    {
      if (tlv_id(va) == HNCP_T_VERSION &&
          tlv_len(va) >= sizeof(hncp_t_version_s))
        {
          hncp_t_version v = tlv_data(va);
          version = v->version;
#if L_LEVEL >= LOG_ERR
          agent = v->user_agent;
          agent_len = tlv_len(va) - sizeof(hncp_t_version_s);
#endif /* L_LEVEL >= LOG_ERR */
          break;
        }
    }
  if (on
      && on != n
      && onh->version
      && version != onh->version)
    a_valid = NULL;
  if (a && nh->version != version)
    {
      if (!a_valid)
        L_ERR("Incompatible node: %s version %u (%.*s) != %u",
              DNCP_NODE_REPR(n), version, agent_len, agent,
              onh->version);
      else if (!nh->version)
        L_INFO("%s runs %.*s",
               DNCP_NODE_REPR(n), agent_len, agent);
      nh->version = version;
    }
  return a_valid;
}

void hncp_destroy(hncp o)
{
  if (!o)
    return;
  hncp_uninit(o);
  free(o);
}

hncp hncp_create(void)
{
  hncp o = calloc(1, sizeof(*o));

  if (o && !hncp_init(o))
    {
      hncp_destroy(o);
      return NULL;
    }
  return o;
}

struct in6_addr *hncp_get_ipv6_address(hncp h, const char *prefer_ifname)
{
  dncp o = h->dncp;
  dncp_ep ep = NULL;
  hncp_ep hl = NULL;

  if (prefer_ifname)
    {
      ep = dncp_find_ep_by_name(o, prefer_ifname);
      hl = dncp_ep_get_ext_data(ep);
    }
  if (!(hl && hl->has_ipv6_address))
    {
      /* Iterate through the links in order, stopping at one with IPv6
       * address. */
      dncp_for_each_ep(o, ep)
        if (dncp_ep_is_enabled(ep))
          {
            hl = dncp_ep_get_ext_data(ep);
            if (hl->has_ipv6_address)
              break;
          }
    }
  if (hl && hl->has_ipv6_address)
    return &hl->ipv6_address;
  return NULL;
}

void
hncp_set_ipv6_address(hncp h, const char *ifname, const struct in6_addr *addr)
{
  dncp o = h->dncp;
  bool has_addr = addr != NULL;
  dncp_ep ep = dncp_find_ep_by_name(o, ifname);
  hncp_ep hl = dncp_ep_get_ext_data(ep);

  if (hl->has_ipv6_address == has_addr &&
      (!has_addr || memcmp(&hl->ipv6_address, addr, sizeof(*addr)) == 0))
    return;
  hl->has_ipv6_address = has_addr;
  if (has_addr)
    {
      hl->ipv6_address = *addr;
      L_DEBUG("hncp_set_ipv6_address: address on %s: %s",
              ep->ifname, ADDR_REPR(addr));
    }
  else
    {
      L_DEBUG("hncp_set_ipv6_address: no %s any more", ep->ifname);
    }
  dncp_notify_subscribers_link_changed(ep, DNCP_EVENT_UPDATE);
}

bool hncp_init(hncp o)
{
  dncp_ext_s ext_s = {
    .conf = {
      .per_link = {
        .trickle_imin = HNCP_TRICKLE_IMIN,
        .trickle_imax = HNCP_TRICKLE_IMAX,
        .trickle_k = HNCP_TRICKLE_K,
        .keepalive_interval = HNCP_KEEPALIVE_INTERVAL,
        .maximum_multicast_size = HNCP_MAXIMUM_MULTICAST_SIZE,

        /* TBD - should this be true or not? hmm. if so, we would have
         * to turn it off _for every link_ when dtls is enabled. */
        .accept_node_data_updates_via_multicast = false
      },
      .node_identifier_length = HNCP_NI_LEN,
      .hash_length = HNCP_HASH_LEN,
      .keepalive_multiplier_percent = HNCP_KEEPALIVE_MULTIPLIER * 100,
      .grace_interval = HNCP_PRUNE_GRACE_PERIOD,
      .minimum_prune_interval = HNCP_MINIMUM_PRUNE_INTERVAL,
      .ext_node_data_size = sizeof(hncp_node_s),
      .ext_ep_data_size = sizeof(hncp_ep_s)
    },
    .cb = {
      /* Rest of callbacks are populated in the hncp_io_init */
      .hash = hncp_hash_md5,
      .validate_node_data = hncp_validate_node_data,
      .handle_collision = hncp_handle_collision_randomly
    }
  };
  memset(o, 0, sizeof(*o));
  o->ext = ext_s;
  o->udp_port = HNCP_PORT;
  if (!hncp_io_init(o))
    return false;
  o->dncp = dncp_create(&o->ext);
  if (!o->dncp)
    return false;
  if (inet_pton(AF_INET6, HNCP_MCAST_GROUP, &o->multicast_address) < 1)
    {
      L_ERR("unable to inet_pton multicast group address");
      return false;
    }
  return true;
}

void hncp_uninit(hncp h)
{
  dncp o = h->dncp;
  dncp_ep ep;
  hncp_ep hep;

  dncp_for_each_ep(o, ep)
    {
      hep = dncp_ep_get_ext_data(ep);
      uloop_timeout_cancel(&hep->join_timeout);
    }
  hncp_io_uninit(h);
  if (!h->dncp)
    return;
  dncp_destroy(h->dncp);
}

dncp hncp_get_dncp(hncp o)
{
  return o->dncp;
}

static void _join_timeout(struct uloop_timeout *t)
{
  hncp_ep hep = container_of(t, hncp_ep_s, join_timeout);
  dncp_ep ep = dncp_ep_from_ext_data(hep);
  dncp o = dncp_ep_get_dncp(ep);
  hncp h = container_of(dncp_get_ext(o), hncp_s, ext);

  /* If it fails immediately, schedule another timeout to try it
   * again */
  if (!hncp_io_set_ifname_enabled(h, ep->ifname, !dncp_ep_is_enabled(ep)))
    uloop_timeout_set(&hep->join_timeout, HNCP_REJOIN_INTERVAL);
}

void hncp_set_enabled(hncp h, const char *ifname, bool enabled)
{
  dncp_ep ep = dncp_find_ep_by_name(h->dncp, ifname);

  if (!dncp_ep_is_enabled(ep) == !enabled)
    return;
  hncp_ep hep = dncp_ep_get_ext_data(ep);
  uloop_timeout_cancel(&hep->join_timeout);
  hep->join_timeout.cb = _join_timeout;
  _join_timeout(&hep->join_timeout);
}
