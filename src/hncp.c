/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 14:50:58 2014 mstenber
 * Last modified: Wed May 13 09:37:58 2015 mstenber
 * Edit time:     13 min
 *
 */

#include "hncp_i.h"

bool dncp_profile_handle_collision(dncp o)
{
  dncp_node_identifier_s ni;
  int i;

  L_ERR("second+ collision -> changing node identifier");
  for (i = 0; i < DNCP_NI_LEN; i++)
    ni.buf[i] = random() % 256;
  dncp_set_own_node_identifier(o, &ni);
  return true;
}




void dncp_profile_link_send_network_state(dncp_ep_i l)
{
  struct sockaddr_in6 dst =
    { .sin6_family = AF_INET6,
      .sin6_addr = l->dncp->profile_data.multicast_address,
      .sin6_port = htons(l->dncp->udp_port)
    };
  if (!(dst.sin6_scope_id = l->ifindex))
    if (!(dst.sin6_scope_id = if_nametoindex(l->ifname)))
      {
        L_ERR("Unable to find index for " DNCP_LINK_F, DNCP_LINK_D(l));
        return;
      }
  dncp_ep_i_send_network_state(l, &dst, HNCP_MAXIMUM_MULTICAST_SIZE);
}

struct tlv_attr *dncp_profile_node_validate_data(dncp_node n,
                                                 struct tlv_attr *a)
{
  uint8_t version = 0;
#if L_LEVEL >= LOG_ERR
  const char *agent = NULL;
  int agent_len = 0;
#endif /* L_LEVEL >= LOG_ERR */
  struct tlv_attr *va, *a_valid = a;
  dncp_node on = n->dncp->own_node;

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
              DNCP_NODE_REPR(n), version, agent_len, agent,
              on->profile_data.version);
      else if (!n->profile_data.version)
        L_INFO("%s runs %.*s",
               DNCP_NODE_REPR(n), agent_len, agent);
      n->profile_data.version = version;
    }
  return a_valid;
}

static bool _hncp_init(dncp o)
{
  if (inet_pton(AF_INET6, HNCP_MCAST_GROUP,
                &o->profile_data.multicast_address) < 1)
    {
      L_ERR("unable to inet_pton multicast group address");
      return false;
    }
  return true;
}

bool hncp_init(dncp o, const void *node_identifier, int len)
{
  if (!dncp_init(o, node_identifier, len))
    return false;
  return _hncp_init(o);
}

void hncp_uninit(dncp o)
{
  dncp_uninit(o);
}


dncp hncp_create(void)
{
  dncp o = dncp_create(NULL);
  if (!o)
    return NULL;
  if (!_hncp_init(o))
    {
      dncp_destroy(o);
      return NULL;
    }
  return o;
}

