/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 14:50:58 2014 mstenber
 * Last modified: Tue May 26 07:10:51 2015 mstenber
 * Edit time:     40 min
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
  dncp_node_identifier_s ni;
  int i;

  L_ERR("second+ collision -> changing node identifier");
  for (i = 0; i < DNCP_NI_LEN(o); i++)
    ni.buf[i] = random() % 256;
  dncp_set_own_node_identifier(o, &ni);
  return true;
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
  dncp o = n->dncp;
  dncp_node on = o->own_node;
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
  dncp_ep_i l = NULL;
  hncp_ep hl;

  if (prefer_ifname)
    l = dncp_find_link_by_name(o, prefer_ifname, false);
  hl = dncp_ep_get_ext_data(&l->conf);
  if (!( l && hl && hl->has_ipv6_address))
    {
      /* Iterate through the links in order, stopping at one with IPv6
       * address. */
      vlist_for_each_element(&o->links, l, in_links)
        {
          hl = dncp_ep_get_ext_data(&l->conf);
          if (hl->has_ipv6_address)
            break;
        }
    }
  if (l && hl && hl->has_ipv6_address)
    return &hl->ipv6_address;
  return NULL;
}

void
hncp_set_ipv6_address(hncp h, const char *ifname, const struct in6_addr *addr)
{
  dncp o = h->dncp;
  bool has_addr = addr != NULL;
  dncp_ep_i l = dncp_find_link_by_name(o, ifname, false);
  if (!l)
    return;
  hncp_ep hl = dncp_ep_get_ext_data(&l->conf);
  if (hl->has_ipv6_address == has_addr &&
      (!has_addr || memcmp(&hl->ipv6_address, addr, sizeof(*addr)) == 0))
    return;
  hl->has_ipv6_address = has_addr;
  if (has_addr)
    {
      hl->ipv6_address = *addr;
      L_DEBUG("hncp_set_ipv6_address: address on %s: %s",
              l->ifname, ADDR_REPR(addr));
    }
  else
    {
      L_DEBUG("hncp_set_ipv6_address: no %s any more", l->ifname);
    }
  dncp_notify_subscribers_link_changed(l, DNCP_EVENT_UPDATE);
}

bool hncp_init(hncp o)
{
  dncp_ext_s ext_s = {
    .conf = {

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

void hncp_uninit(hncp o)
{
  hncp_io_uninit(o);
  if (!o->dncp)
    return;
  dncp_destroy(o->dncp);
}
