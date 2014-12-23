/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 14:50:58 2014 mstenber
 * Last modified: Tue Dec 23 15:40:47 2014 mstenber
 * Edit time:     7 min
 *
 */

#include "hncp_i.h"

bool dncp_profile_handle_collision(hncp o)
{
  hncp_node_identifier_s ni;
  int i;

  L_ERR("second+ collision -> changing node identifier");
  for (i = 0; i < DNCP_NI_LEN; i++)
    ni.buf[i] = random() % 256;
  hncp_set_own_node_identifier(o, &ni);
  return true;
}




void dncp_profile_link_send_network_state(hncp_link l)
{
  struct sockaddr_in6 dst =
    { .sin6_family = AF_INET6,
      .sin6_addr = l->hncp->profile_data.multicast_address,
      .sin6_port = htons(l->hncp->udp_port)
    };
  if (!(dst.sin6_scope_id = l->ifindex))
    if (!(dst.sin6_scope_id = if_nametoindex(l->ifname)))
      {
        L_ERR("Unable to find index for " DNCP_LINK_F, DNCP_LINK_D(l));
        return;
      }
  hncp_link_send_network_state(l, &dst, HNCP_MAXIMUM_MULTICAST_SIZE);
}

struct tlv_attr *dncp_profile_node_validate_data(hncp_node n,
                                                 struct tlv_attr *a)
{
  uint8_t version = 0;
#if L_LEVEL >= LOG_ERR
  const char *agent = NULL;
  int agent_len = 0;
#endif /* L_LEVEL >= LOG_ERR */
  struct tlv_attr *va, *a_valid = a;
  hncp_node on = n->hncp->own_node;

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
      && on->profile_data.version
      && version != on->profile_data.version)
    a_valid = NULL;
  if (a && n->profile_data.version != version)
    {
      if (!a_valid)
        L_ERR("Incompatible node: %s version %u (%.*s) != %u",
              HNCP_NODE_REPR(n), version, agent_len, agent,
              on->profile_data.version);
      else if (!n->profile_data.version)
        L_INFO("%s runs %.*s",
               HNCP_NODE_REPR(n), agent_len, agent);
      n->profile_data.version = version;
    }
  return a_valid;
}

/* Utilities for formatting TLVs. */
void hncp_tlv_ra_update(hncp o,
                        uint32_t lid,
                        const struct in6_addr *address,
                        bool add)
{
  hncp_t_router_address_s ra;

  ra.link_id = lid;
  ra.address = *address;
  hncp_update_tlv(o, HNCP_T_ROUTER_ADDRESS, &ra, sizeof(ra), 0, add);
}


void hncp_tlv_ap_update(hncp o,
                        const struct prefix *prefix,
                        const char *ifname,
                        bool authoritative,
                        unsigned int preference,
                        bool add)
{
  struct prefix p;
  int mlen = sizeof(hncp_t_assigned_prefix_header_s) + 16 + 3;
  unsigned char buf[mlen];
  int plen = ROUND_BITS_TO_BYTES(prefix->plen);
  int flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;
  hncp_t_assigned_prefix_header ah;
  hncp_link l;

  memset(buf, 0, sizeof(buf));
  p = *prefix;
  prefix_canonical(&p, &p);
  /* XXX - what if links renumber? let's hope they don't */
  ah = (void *)buf;
  l = hncp_find_link_by_name(o, ifname, false);
  if (l)
    ah->link_id = l->iid;
  ah->flags =
    HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(preference)
    | (authoritative ? HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE : 0);
  ah->prefix_length_bits = p.plen;
  ah++;
  memcpy(ah, &p, plen);
  hncp_update_tlv(o, HNCP_T_ASSIGNED_PREFIX, buf, flen, 0, add);
}

hncp hncp_create(void)
{
  hncp o = dncp_create();
  if (!o)
    return NULL;
  if (inet_pton(AF_INET6, HNCP_MCAST_GROUP,
                &o->profile_data.multicast_address) < 1) {
    L_ERR("unable to inet_pton multicast group address");
    return false;
  }
  struct __packed {
    hncp_t_version_s h;
    char agent[32];
  } data;
  memset(&data, 0, sizeof(data));
  data.h.version = HNCP_VERSION;
  int alen = snprintf(data.agent, sizeof(data.agent),
                      "hnetd-%s", STR(HNETD_VERSION));
  if (alen == sizeof(data.agent))
    alen = sizeof(data.agent) - 1;
  data.agent[alen] = 0;
  hncp_add_tlv(o, HNCP_T_VERSION, &data, sizeof(data.h) + alen + 1, 0);
  return o;
}
