/*
 * $Id: dncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Thu Jul  2 11:44:00 2015 mstenber
 * Edit time:     388 min
 *
 */

#pragma once

/* NOTE: This is NOT public API. Stay away, unless you're dncp*, or
 * legacy code that ought to be taken behind the barn and taken care
 * of. dncp{,_util,_trust}.h are the public API of the dncp module. */

#include "dncp.h"
#include "dncp_proto.h"
#include "dncp_util.h"

#include "dns_util.h"

/* ADDR_REPR etc. */
#include "prefix.h"

#include <assert.h>

#include <libubox/uloop.h>

/* Rough approximation - should think of real figure. */
#define DNCP_MAXIMUM_PAYLOAD_SIZE 65536

#include <libubox/vlist.h>
#include <libubox/list.h>

typedef struct dncp_ep_i_struct dncp_ep_i_s, *dncp_ep_i;


typedef struct __packed {
  unsigned char buf[DNCP_HASH_MAX_LEN];
} dncp_hash_s, *dncp_hash;

typedef struct __packed {
  unsigned char buf[DNCP_NI_MAX_LEN];
} dncp_node_id_s, *dncp_node_id;

struct dncp_struct {
  /* 'external' handling structure */
  dncp_ext ext;

  /* Disable pruning (should be used probably only in unit tests) */
  bool disable_prune;

  /* cached current time; if zero, should ask dncp_ext for it again */
  hnetd_time_t now;

  /* nodes (as contained within the protocol, that is, raw TLV data blobs). */
  struct vlist_tree nodes;

  /* local data (TLVs API's clients want published). */
  struct vlist_tree tlvs;

  /* local endpoints (endpoints clients have at least referred to once). */
  struct vlist_tree eps;

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

  /* flag which indicates that we should re-calculate network hash
   * based on nodes' state. */
  bool network_hash_dirty;

  bool immediate_scheduled;

  /* Our own node (it should be constant, never purged) */
  dncp_node own_node;

  /* Whole network hash we consider current (based on content of 'nodes'). */
  dncp_hash_s network_hash;

  /* First free local interface identifier (we allocate them in
   * monotonically increasing fashion just to keep things simple). */
  int first_free_ep_id;

  /* List of subscribers to change notifications. */
  struct list_head subscribers[NUM_DNCP_CALLBACKS];

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
};

typedef struct dncp_trickle_struct dncp_trickle_s, *dncp_trickle;

struct dncp_trickle_struct {
  /* Trickle state */
  int i; /* trickle interval size */
  hnetd_time_t send_time; /* when do we send if c < k*/
  hnetd_time_t interval_end_time; /* when does current interval end */
  int c; /* counter */
  hnetd_time_t last_sent;
  int num_sent;
  int num_skipped;
};


struct dncp_ep_i_struct {
  struct vlist_node in_eps;

  /* Backpointer to dncp */
  dncp dncp;

  /* Is the endpoint actually 'ready' according to ext? By default, not. */
  bool enabled;

  /* The public portion of the endpoint */
  dncp_ep_s conf;

  /* Interface identifier - these should be unique over lifetime of
   * dncp process. */
  ep_id_t ep_id;

  /* What value we have TLV for, if any */
  uint32_t published_keepalive_interval;

  /* Most recent request for network state. (This could be global too,
   * but one outgoing request per endpoint sounds fine too). */
  hnetd_time_t last_req_network_state;

  /* The per-ep Trickle state. */
  dncp_trickle_s trickle;
};

typedef struct dncp_neighbor_struct dncp_neighbor_s, *dncp_neighbor;

struct dncp_neighbor_struct {
  /* Most recent address we heard from this particular neighbor */
  struct sockaddr_in6 last_sa6;

  /* When did we last time receive _consistent_ state from the peer
   * (multicast) or any contact (unicast). */
  hnetd_time_t last_contact;

  /* The per-(local)peer Trickle state. */
  dncp_trickle_s trickle;
};


struct dncp_node_struct {
  /* dncp->nodes entry */
  struct vlist_node in_nodes;

  /* backpointer to dncp */
  dncp dncp;

  /* These map 1:1 to node data TLV's start */
  dncp_node_id_s node_id;
  uint32_t update_number;

  /* When was the last prune during which this node was reachable */
  hnetd_time_t last_reachable_prune;

  /* Node state stuff */
  dncp_hash_s node_data_hash;
  bool node_data_hash_dirty; /* Something related to hash changed */
  hnetd_time_t origination_time; /* in monotonic time */
  hnetd_time_t expiration_time; /* in monotonic time */

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
bool dncp_init(dncp o, dncp_ext ext, const void *node_id, int len);
void dncp_uninit(dncp o);

/* Private utility - shouldn't be used by clients. */
void dncp_node_set(dncp_node n,
                   uint32_t update_number, hnetd_time_t t,
                   struct tlv_attr *a);
void dncp_node_recalculate_index(dncp_node n);

bool dncp_add_tlv_index(dncp o, uint16_t type);

void dncp_schedule(dncp o);

/* Flush own TLV changes to own node. */
void dncp_self_flush(dncp_node n);

/* Various hash calculation utilities. */
void dncp_calculate_network_hash(dncp o);

/* Utility functions to send frames. */
void dncp_ep_i_send_network_state(dncp_ep_i l,
                                  struct sockaddr_in6 *src,
                                  struct sockaddr_in6 *dst,
                                  size_t maximum_size,
                                  bool always_ep_id);


/* Miscellaneous utilities that live in dncp_timeout */
void dncp_trickle_reset(dncp o);

/* Compatibility / convenience macros to access stuff that used to be fixed. */
#define DNCP_NI_LEN(o) (o)->ext->conf.node_id_length
#define DNCP_HASH_LEN(o) (o)->ext->conf.hash_length
#define DNCP_KEEPALIVE_INTERVAL(o) (o)->ext->conf.per_ep.keepalive_interval
#define DNCP_HASH_REPR(o, h) HEX_REPR(h, DNCP_HASH_LEN(o))

/* Inlined utilities. */
static inline hnetd_time_t dncp_time(dncp o)
{
  if (!o->now)
    return o->ext->cb.get_time(o->ext);
  return o->now;
}

#define TMIN(x,y) ((x) == 0 ? (y) : (y) == 0 ? (x) : (x) < (y) ? (x) : (y))

#define DNCP_LINK_F "link %s[#%d]"
#define DNCP_LINK_D(l) l ? l->conf.ifname : "(NULL IF)", l ? l->ep_id : 0

#define DNCP_NI_REPR(o, ni) HEX_REPR(ni, DNCP_NI_LEN(o))

#define dncp_for_each_node_including_unreachable(o, n)                  \
  for (n = (avl_is_empty(&o->nodes.avl) ?                               \
            NULL : avl_first_element(&o->nodes.avl, n, in_nodes.avl)) ; \
       n ;                                                              \
       n = (n == avl_last_element(&o->nodes.avl, n, in_nodes.avl) ?     \
            NULL : avl_next_element(n, in_nodes.avl)))

static inline dncp_t_neighbor
dncp_tlv_neighbor2(const struct tlv_attr *a, int nidlen)
{
  if (tlv_id(a) != DNCP_T_NEIGHBOR
      || tlv_len(a) != (nidlen + sizeof(dncp_t_neighbor_s)))
    return NULL;
  return (dncp_t_neighbor)(tlv_data(a) + nidlen);
}

static inline dncp_t_neighbor
dncp_tlv_neighbor(dncp o, const struct tlv_attr *a)
{
  return dncp_tlv_neighbor2(a, DNCP_NI_LEN(o));
}

static inline dncp_node_id
dncp_tlv_get_node_id2(void *tlv, int nidlen)
{
  return (dncp_node_id)(tlv - nidlen);
}

static inline dncp_node_id
dncp_tlv_get_node_id(dncp o, void *tlv)
{
  return dncp_tlv_get_node_id2(tlv,
                               o->ext->conf.node_id_length);
}

static inline dncp_node
dncp_node_find_neigh_bidir(dncp_node n, dncp_t_neighbor ne)
{
  if (!n)
    return NULL;
  dncp_node_id ni = dncp_tlv_get_node_id(n->dncp, ne);
  dncp_node n2 = dncp_find_node_by_node_id(n->dncp, ni, false);
  if (!n2)
    return NULL;
  struct tlv_attr *a;
  dncp_t_neighbor ne2;

  dncp_node_for_each_tlv_with_t_v(n2, a, DNCP_T_NEIGHBOR, false)
    if ((ne2 = dncp_tlv_neighbor(n->dncp, a)))
      {
        if (ne->ep_id == ne2->neighbor_ep_id
            && ne->neighbor_ep_id == ne2->ep_id &&
            !memcmp(dncp_tlv_get_node_id(n->dncp, ne2),
                    &n->node_id, DNCP_NI_LEN(n->dncp)))
          return n2;
      }

  return NULL;
}
