/*
 * $Id: hncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:33:03 2014 mstenber
 * Last modified: Mon May 25 15:27:18 2015 mstenber
 * Edit time:     16 min
 *
 */

#pragma once

#include "dncp_i.h"
#include "hncp.h"
#include "hncp_proto.h"

/* Pretty arbitrary. I wonder if all links can really guarantee MTU
 * size packets going through. However, IPv6 minimum MTU - size of
 * IPv6 header - size of UDP header (we consider only the payload
 * here) should work.  */
#define HNCP_MAXIMUM_MULTICAST_SIZE (1280-40-8)

/* TLV handling */
#include "prefix_utils.h"

static inline hncp_t_assigned_prefix_header
dncp_tlv_ap(const struct tlv_attr *a)
{
  hncp_t_assigned_prefix_header ah;

  if (tlv_id(a) != HNCP_T_ASSIGNED_PREFIX || tlv_len(a) < sizeof(*ah))
    return NULL;
  ah = tlv_data(a);
  if (tlv_len(a) < (sizeof(*ah) + ROUND_BITS_TO_BYTES(ah->prefix_length_bits))
      || ah->prefix_length_bits > 128)
    return NULL;
  return ah;
}

static inline hncp_t_delegated_prefix_header
dncp_tlv_dp(const struct tlv_attr *a)
{
  hncp_t_delegated_prefix_header dh;

  if (tlv_id(a) != HNCP_T_DELEGATED_PREFIX || tlv_len(a) < sizeof(*dh))
    return NULL;
  dh = tlv_data(a);
  if (tlv_len(a) < (sizeof(*dh) + ROUND_BITS_TO_BYTES(dh->prefix_length_bits))
      || dh->prefix_length_bits > 128)
    return NULL;
  return dh;
}

static inline hncp_t_router_address
dncp_tlv_router_address(const struct tlv_attr *a)
{
  if (tlv_id(a) != HNCP_T_ROUTER_ADDRESS
      || tlv_len(a) != sizeof(hncp_t_router_address_s))
    return NULL;
  return tlv_data(a);
}

bool hncp_init(hncp o);
void hncp_uninit(hncp o);

struct hncp_struct {
  /* Our DNCP 'handle' */
  dncp_ext_s ext;

  /* Actual DNCP instance pointer. */
  dncp dncp;

  /* Multicast address */
  struct in6_addr multicast_address;

  /* search domain provided to clients. */
  /* (Shared between pa + sd, that's why it's here) */
  char domain[DNS_MAX_ESCAPED_LEN];

#ifdef DTLS
  /* DTLS 'socket' abstraction, which actually hides two UDP sockets
   * (client and server) and N OpenSSL contexts tied to each of
   * them. */
  dtls d;

  /* Trust consensus model of authz for DTLS is _not_ here; see
   * hncp_trust.[ch]. */
#endif /* DTLS */
};


struct hncp_bfs_head {
  /* List head for implementing BFS */
  struct list_head head;

  /* Next-hop in path (also used to mark visited nodes) */
  const struct in6_addr *next_hop;
  const struct in6_addr *next_hop4;
  const char *ifname;
  unsigned hopcount;
};

typedef struct hncp_ep_struct hncp_ep_s, *hncp_ep;

struct hncp_ep_struct {
  /* 'Best' address (if any) */
  bool has_ipv6_address;
  struct in6_addr ipv6_address;

  /* When did multicast join fail last time? */
  /* -> probably tried during DAD. Should try later again. */
  hnetd_time_t join_failed_time;

  bool join_pending;
};

typedef struct hncp_node_struct hncp_node_s, *hncp_node;

struct hncp_node_struct {
  /* Version of HNCP */
  uint32_t version;

  /* Iterator to do bfs-traversal */
  struct hncp_bfs_head bfs;
};


#define dncp_get_hncp(o) container_of(o->ext, hncp_s, ext)
