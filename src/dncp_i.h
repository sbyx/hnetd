/*
 * $Id: dncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Wed Feb 11 20:03:51 2015 mstenber
 * Edit time:     325 min
 *
 */

#pragma once

#include "dncp.h"
#include "dncp_proto.h"
#include "dncp_profile.h"

#include "dns_util.h"

/* ADDR_REPR etc. */
#include "prefix_utils.h"

#include <assert.h>

#include <libubox/uloop.h>

/* Rough approximation - should think of real figure. */
#define DNCP_MAXIMUM_PAYLOAD_SIZE 65536


#include <libubox/vlist.h>
#include <libubox/list.h>

typedef uint32_t iid_t;

struct dncp_struct {
  /* Disable pruning (should be used probably only in unit tests) */
  bool disable_prune;

  /* cached current time; if zero, should ask dncp_io for it again */
  hnetd_time_t now;

  /* nodes (as contained within the protocol, that is, raw TLV data blobs). */
  struct vlist_tree nodes;

  /* local data (TLVs API's clients want published). */
  struct vlist_tree tlvs;

  /* local links (those API's clients want active). */
  struct vlist_tree links;

  /* Link configuration options */
  struct list_head link_confs;

  /* flag which indicates that we should perhaps re-publish our node
   * in nodes. */
  bool tlvs_dirty;

  /* flag which indicates that we MUST re-publish our node, regardless
   * of what's in local tlvs currently. */
  bool republish_tlvs;

  /* Have we already collided once this boot? If so, let profile deal
   * with it. */
  bool collided;

  /* flag which indicates that we (or someone connected) may have
   * changed connectivity. */
  bool graph_dirty;

  /* Few different times.. */
  hnetd_time_t last_prune;
  hnetd_time_t next_prune;
  hnetd_time_t last_network_hash_change;

  /* flag which indicates that we should re-calculate network hash
   * based on nodes' state. */
  bool network_hash_dirty;

  /* before io-init is done, we keep just prod should_schedule. */
  bool io_init_done;
  bool should_schedule;
  bool immediate_scheduled;

  /* Our own node (it should be constant, never purged) */
  dncp_node own_node;

  /* Whole network hash we consider current (based on content of 'nodes'). */
  dncp_hash_s network_hash;

  /* First free local interface identifier (we allocate them in
   * monotonically increasing fashion just to keep things simple). */
  int first_free_iid;

  /* The UDP port number our socket is bound to. 0 = use default. */
  /* (Currently only of internal utility as no way to provide it when
   * initializing dncp instance, and by the time it is created, it is
   * too late to change.) */
  uint16_t udp_port;

  /* UDP socket. */
  int udp_socket;

  /* And it's corresponding uloop_fd */
  struct uloop_fd ufd;

  /* Timeout for doing 'something' in dncp_io. */
  struct uloop_timeout timeout;

  /* List of subscribers to change notifications. */
  struct list_head subscribers;

  /* search domain provided to clients. */
  char domain[DNS_MAX_ESCAPED_LEN];

  /* An array that contains type -> index+1 (if available) or type ->
   * 0 (if no index yet allocated). */
  int *tlv_type_to_index;

  /* Highest allocated TLV index. */
  int tlv_type_to_index_length;

  /* Number of TLV indexes we have. That is, the # of non-empty slots
   * in the tlv_type_to_index. */
  int num_tlv_indexes;

  /* Number of times neighbor has been dropped. */
  int num_neighbor_dropped;

  /* Profile-specific data */
  dncp_profile_data_s profile_data;
};

struct dncp_link_struct {
  struct vlist_node in_links;

  /* Backpointer to dncp */
  dncp dncp;

  /* Pointer to some dncp_link configuration structure */
  dncp_link_conf conf;

  /* Name of the (local) link. */
  char ifname[IFNAMSIZ];

  /* In-system ifindex; if not set, determine dynamically. */
  uint32_t ifindex;

  /* Interface identifier - these should be unique over lifetime of
   * dncp process. */
  iid_t iid;

  /* When did multicast join fail last time? */
  /* -> probably tried during DAD. Should try later again. */
  hnetd_time_t join_failed_time;

  bool join_pending;

  /* Trickle state */
  int trickle_i; /* trickle interval size */
  hnetd_time_t trickle_send_time; /* when do we send if c < k*/
  hnetd_time_t trickle_interval_end_time; /* when does current interval end */
  int trickle_c; /* counter */
  hnetd_time_t last_trickle_sent;

  /* What value we have TLV for, if any */
  uint32_t published_keepalive_interval;

  /* Statistics about Trickle (mostly for debugging) */
  int num_trickle_sent;
  int num_trickle_skipped;

  /* 'Best' address (if any) */
  bool has_ipv6_address;
  struct in6_addr ipv6_address;
};

typedef struct dncp_neighbor_struct dncp_neighbor_s, *dncp_neighbor;


struct dncp_neighbor_struct {
  /* Link-level address */
  struct sockaddr_in6 last_sa6;

  /* When did we last time receive _consistent_ state from the peer. */
  hnetd_time_t last_sync;
};


struct dncp_node_struct {
  /* dncp->nodes entry */
  struct vlist_node in_nodes;

  /* backpointer to dncp */
  dncp dncp;

  /* These map 1:1 to node data TLV's start */
  dncp_node_identifier_s node_identifier;
  uint32_t update_number;

  /* When was the last prune during which this node was reachable */
  hnetd_time_t last_reachable_prune;

  /* Node state stuff */
  dncp_hash_s node_data_hash;
  bool node_data_hash_dirty; /* Something related to hash changed */
  hnetd_time_t origination_time; /* in monotonic time */

  /* TLV data for the node. All TLV data in one binary blob, as
   * received/created. We could probably also maintain this at end of
   * the structure, but that'd mandate re-inserts whenever content
   * changes, so probably just faster to keep a pointer to it. */
  struct tlv_attr *tlv_container;

  /* TLV data, that is of correct version # and otherwise looks like
   * it should be used by us. Either tlv_container, or NULL. */
  struct tlv_attr *tlv_container_valid;

  /* An index of DNCP TLV indexes (that have been registered and
   * precomputed for this node). Typically NULL, until first access
   * during which we have to traverse all TLVs in any case and this
   * gets populated. It contains 'first', 'next' pairs for each
   * registered index. */
  struct tlv_attr **tlv_index;

  /* Flag which indicates whether contents of tlv_idnex are up to date
   * with tlv_container. As a result of this, there's no need for
   * re-alloc when tlv_container changes and we don't immediately want
   * to recalculate tlv_index. */
  bool tlv_index_dirty;

  /* Profile-specific data */
  dncp_profile_node_data_s profile_data;
};

struct dncp_tlv_struct {
  /* dncp->tlvs entry */
  struct vlist_node in_tlvs;

  /* Actual TLV attribute itself. */
  struct tlv_attr tlv;

  /* var-length tlv */

  /* .. and after it's padding length: extra data space reserved by
   * the client, if any */
};

/* Internal or testing-only way to initialize hp struct _without_
 * dynamic allocations (and some of the steps omitted too). */
bool dncp_init(dncp o, const void *node_identifier, int len);
void dncp_uninit(dncp o);

/* Utility to change local node identifier - use with care */
bool dncp_set_own_node_identifier(dncp o, dncp_node_identifier ni);

dncp_link dncp_find_link_by_name(dncp o, const char *ifname, bool create);
dncp_link dncp_find_link_by_id(dncp o, uint32_t link_id);
dncp_node
dncp_find_node_by_node_identifier(dncp o, dncp_node_identifier ni, bool create);

/* Private utility - shouldn't be used by clients. */
int dncp_node_cmp(dncp_node n1, dncp_node n2);
void dncp_node_set(dncp_node n,
                   uint32_t update_number, hnetd_time_t t,
                   struct tlv_attr *a);
void dncp_node_recalculate_index(dncp_node n);

bool dncp_add_tlv_index(dncp o, uint16_t type);

bool dncp_get_ipv6_address(dncp o, char *prefer_ifname, struct in6_addr *addr);

void dncp_schedule(dncp o);

/* Flush own TLV changes to own node. */
void dncp_self_flush(dncp_node n);

/* Various hash calculation utilities. */
void dncp_calculate_hash(const void *buf, int len, dncp_hash dest);
void dncp_calculate_network_hash(dncp o);
static inline unsigned long long dncp_hash64(dncp_hash h)
{
  return *((unsigned long long *)h);
}

/* Utility functions to send frames. */
void dncp_link_send_network_state(dncp_link l,
                                  struct sockaddr_in6 *dst,
                                  size_t maximum_size);
void dncp_link_send_req_network_state(dncp_link l, struct sockaddr_in6 *dst);
void dncp_link_set_ipv6_address(dncp_link l, const struct in6_addr *addr);
void dncp_link_set_keepalive_interval(dncp_link l, uint32_t value);


/* Miscellaneous utilities that live in dncp_timeout */
hnetd_time_t dncp_neighbor_interval(dncp o, struct tlv_attr *neighbor_tlv);
void dncp_trickle_reset(dncp o);

/* Subscription stuff (dncp_notify.c) */
void dncp_notify_subscribers_tlvs_changed(dncp_node n,
                                          struct tlv_attr *a_old,
                                          struct tlv_attr *a_new);
void dncp_notify_subscribers_node_changed(dncp_node n, bool add);
void dncp_notify_subscribers_about_to_republish_tlvs(dncp_node n);
void dncp_notify_subscribers_local_tlv_changed(dncp o,
                                               struct tlv_attr *a,
                                               bool add);
void dncp_notify_subscribers_link_changed(dncp_link l, enum dncp_subscriber_event event);

/* Inlined utilities. */
static inline hnetd_time_t dncp_time(dncp o)
{
  if (!o->now)
    return dncp_io_time(o);
  return o->now;
}

#define TMIN(x,y) ((x) == 0 ? (y) : (y) == 0 ? (x) : (x) < (y) ? (x) : (y))

#define DNCP_STRUCT_REPR(i) HEX_REPR(&i, sizeof(i))

#define DNCP_NODE_REPR(n) DNCP_STRUCT_REPR(n->node_identifier)

#define DNCP_LINK_F "link %s[#%d]"
#define DNCP_LINK_D(l) l->ifname,l->iid

#define SA6_F "%s:%d"
#define SA6_D(sa) ADDR_REPR(&sa->sin6_addr),ntohs(sa->sin6_port)

static inline struct tlv_attr *
dncp_node_get_tlv_with_type(dncp_node n, uint16_t type, bool first)
{
  if (type >= n->dncp->tlv_type_to_index_length
      || !n->dncp->tlv_type_to_index[type])
    if (!dncp_add_tlv_index(n->dncp, type))
      return NULL;
  if (n->tlv_index_dirty)
    {
      dncp_node_recalculate_index(n);
      if (!n->tlv_index)
        return NULL;
    }
  int index = n->dncp->tlv_type_to_index[type] - 1;
  assert(index >= 0 && index < n->dncp->num_tlv_indexes);
  int i = index * 2 + (first ? 0 : 1);
  return n->tlv_index[i];
}

#define dncp_for_each_node_including_unreachable(o, n)                  \
  for (n = (avl_is_empty(&o->nodes.avl) ?                               \
            NULL : avl_first_element(&o->nodes.avl, n, in_nodes.avl)) ; \
       n ;                                                              \
       n = (n == avl_last_element(&o->nodes.avl, n, in_nodes.avl) ?     \
            NULL : avl_next_element(n, in_nodes.avl)))

#define dncp_node_for_each_tlv_with_type(n, a, type)            \
  for (a = dncp_node_get_tlv_with_type(n, type, true) ;         \
       a && a != dncp_node_get_tlv_with_type(n, type, false) ;  \
       a = tlv_next(a))

#define ROUND_BITS_TO_BYTES(b) (((b) + 7) / 8)
#define ROUND_BYTES_TO_4BYTES(b) ((((b) + 3) / 4) * 4)

static inline dncp_t_node_data_neighbor
dncp_tlv_neighbor(const struct tlv_attr *a)
{
  if (tlv_id(a) != DNCP_T_NODE_DATA_NEIGHBOR
      || tlv_len(a) != sizeof(dncp_t_node_data_neighbor_s))
    return NULL;
  return tlv_data(a);
}

static inline dncp_t_trust_verdict
dncp_tlv_trust_verdict(const struct tlv_attr *a)
{
  if (tlv_id(a) != DNCP_T_TRUST_VERDICT)
    return NULL;
  if (tlv_len(a) < sizeof(dncp_t_trust_verdict_s) + 1)
    return NULL;
  if (tlv_len(a) > sizeof(dncp_t_trust_verdict_s) + DNCP_T_TRUST_VERDICT_CNAME_LEN)
    return NULL;
  const char *data = tlv_data(a);
  /* Make sure it is also null terminated */
  if (data[tlv_len(a)-1])
    return NULL;
  return tlv_data(a);
}

static inline dncp_node
dncp_node_find_neigh_bidir(dncp_node n, dncp_t_node_data_neighbor ne)
{
  if (!n)
    return NULL;
  dncp_node_identifier ni = &ne->neighbor_node_identifier;
  dncp_node n2 = dncp_find_node_by_node_identifier(n->dncp, ni, false);
  if (!n2)
    return NULL;
  struct tlv_attr *a;
  dncp_t_node_data_neighbor ne2;

  dncp_node_for_each_tlv_with_type(n2, a, DNCP_T_NODE_DATA_NEIGHBOR)
    if ((ne2 = dncp_tlv_neighbor(a)))
      {
        if (ne->link_id == ne2->neighbor_link_id
            && ne->neighbor_link_id == ne2->link_id &&
            !memcmp(&ne2->neighbor_node_identifier,
                    &n->node_identifier, DNCP_NI_LEN))
          return n2;
      }

  return NULL;
}

#define dncp_md5_end(h, ctx)    \
do {                            \
  char tbuf[16];                \
  md5_end(tbuf, ctx);           \
  *h = *((dncp_hash)tbuf);      \
} while (0)

#define dncp_for_each_local_tlv(o, t)  \
  avl_for_each_element(&o->tlvs.avl, t, in_tlvs.avl)

#define dncp_for_each_local_tlv_safe(o, t, t2)  \
  avl_for_each_element_safe(&o->tlvs.avl, t, in_tlvs.avl, t2)

#define dncp_update_tlv(o, t, d, dlen, elen, is_add)    \
do {                                                    \
  if (is_add)                                           \
    dncp_add_tlv(o, t, d, dlen, elen);                  \
  else                                                  \
    dncp_remove_tlv_matching(o, t, d, dlen);            \
 } while(0)

#define dncp_update_number_gt(a,b) \
  ((((uint32_t)(a) - (uint32_t)(b)) & ((uint32_t)1<<31)) != 0)
