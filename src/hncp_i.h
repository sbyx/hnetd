/*
 * $Id: hncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Thu Jun 12 16:43:28 2014 mstenber
 * Edit time:     226 min
 *
 */

#ifndef HNCP_I_H
#define HNCP_I_H

#include "hncp.h"

#include "dns_util.h"

#include <assert.h>

#include <libubox/uloop.h>

/* Rough approximation - should think of real figure. */
#define HNCP_MAXIMUM_PAYLOAD_SIZE 65536

/* Pretty arbitrary. I wonder if all links can really guarantee MTU
 * size packets going through. However, IPv6 minimum MTU - size of
 * IPv6 header - size of UDP header (we consider only the payload
 * here) should work.  */
#define HNCP_MAXIMUM_MULTICAST_SIZE (1280-40-8)

/* Collision time window. */
#define HNCP_UPDATE_COLLISION_N (60 * HNETD_TIME_PER_SECOND)

/* How many collisions are needed in time window for renumbering. */
#define HNCP_UPDATE_COLLISIONS_IN_N 3


#include <libubox/vlist.h>
#include <libubox/list.h>

typedef uint32_t iid_t;


struct hncp_struct {
  /* Disable pruning (should be used probably only in unit tests) */
  bool disable_prune;

  /* cached current time; if zero, should ask hncp_io for it again */
  hnetd_time_t now;

  /* nodes (as contained within the protocol, that is, raw TLV data blobs). */
  struct vlist_tree nodes;

  /* local data (TLVs API's clients want published). */
  struct vlist_tree tlvs;

  /* local links (those API's clients want active). */
  struct vlist_tree links;

  /* Link configuration options */
  struct list_head link_confs;

  /* flag which indicates that we should re-publish links. */
  bool links_dirty;

  /* flag which indicates that we should perhaps re-publish our node
   * in nodes. */
  bool tlvs_dirty;

  /* flag which indicates that we MUST re-publish our node, regardless
   * of what's in local tlvs currently. */
  bool republish_tlvs;

  /* flag which indicates that we (or someone connected) may have
   * changed connectivity. */
  bool graph_dirty;
  hnetd_time_t last_prune;
  hnetd_time_t next_prune;

  /* flag which indicates that we should re-calculate network hash
   * based on nodes' state. */
  bool network_hash_dirty;

  /* before io-init is done, we keep just prod should_schedule. */
  bool io_init_done;
  bool should_schedule;
  bool immediate_scheduled;

  /* Our own node (it should be constant, never purged) */
  hncp_node own_node;

  /* Whole network hash we consider current (based on content of 'nodes'). */
  hncp_hash_s network_hash;

  /* First free local interface identifier (we allocate them in
   * monotonically increasing fashion just to keep things simple). */
  int first_free_iid;

  /* UDP socket. */
  int udp_socket;

  /* And it's corresponding uloop_fd */
  struct uloop_fd ufd;

  /* Timeout for doing 'something' in hncp_io. */
  struct uloop_timeout timeout;

  /* Multicast address */
  struct in6_addr multicast_address;

  /* When did multicast join fail last time? */
  hnetd_time_t join_failed_time;

  /* List of subscribers to change notifications. */
  struct list_head subscribers;

  /* Collision tracking - when to rename. */
  int last_collision;
  hnetd_time_t collisions[HNCP_UPDATE_COLLISIONS_IN_N];

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
};

typedef struct hncp_link_struct hncp_link_s, *hncp_link;

struct hncp_link_struct {
  struct vlist_node in_links;

  /* Backpointer to hncp */
  hncp hncp;

  /* Pointer to some hncp_link configuration structure */
  hncp_link_conf conf;

  /* Who are the neighbors on the link. */
  struct vlist_tree neighbors;

  /* Name of the (local) link. */
  char ifname[IFNAMSIZ];

  /* Interface identifier - these should be unique over lifetime of
   * hncp process. */
  iid_t iid;

  /* Join failed -> probably tried during DAD. Should try later again. */
  bool join_pending;

  /* Trickle state */
  int trickle_i; /* trickle interval size */
  hnetd_time_t trickle_send_time; /* when do we send if c < k*/
  hnetd_time_t trickle_interval_end_time; /* when does current interval end */
  int trickle_c; /* counter */

  /* 'Best' address (if any) */
  bool has_ipv6_address;
  struct in6_addr ipv6_address;
};

typedef struct hncp_neighbor_struct hncp_neighbor_s, *hncp_neighbor;


struct hncp_neighbor_struct {
  struct vlist_node in_neighbors;

  hncp_hash_s node_identifier_hash;
  iid_t iid;

  /* Link-level address */
  struct in6_addr last_address;

  /* When did we last hear from this one? */
  hnetd_time_t last_heard;

  /* When did they last respond to our message? */
  hnetd_time_t last_response;

  /* How many pings we have sent that haven't been responded to. */
  int ping_count;

  /* When did we send the ping most recently. */
  hnetd_time_t last_ping;
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

struct hncp_node_struct {
  /* hncp->nodes entry */
  struct vlist_node in_nodes;

  /* backpointer to hncp */
  hncp hncp;

  /* iterator to do bfs-traversal */
  struct hncp_bfs_head bfs;

  /* These map 1:1 to node data TLV's start */
  hncp_hash_s node_identifier_hash;
  uint32_t update_number;

  uint32_t version;

  /* When was the last prune during which this node was reachable */
  hnetd_time_t last_reachable_prune;

  /* Node state stuff */
  hncp_hash_s node_data_hash;
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

  /* An index of HNCP TLV indexes (that have been registered and
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

typedef struct hncp_tlv_struct hncp_tlv_s, *hncp_tlv;

struct hncp_tlv_struct {
  /* hncp->tlvs entry */
  struct vlist_node in_tlvs;

  /* Actual TLV attribute itself. */
  struct tlv_attr tlv;
};

/* Internal or testing-only way to initialize hp struct _without_
 * dynamic allocations (and some of the steps omitted too). */
bool hncp_init(hncp o, const void *node_identifier, int len);
void hncp_uninit(hncp o);

/* Utility to change local node identifier - use with care */
bool hncp_set_own_hash(hncp o, hncp_hash h);

hncp_link hncp_find_link_by_name(hncp o, const char *ifname, bool create);
hncp_link hncp_find_link_by_id(hncp o, uint32_t link_id);
hncp_node hncp_find_node_by_hash(hncp o, const hncp_hash h, bool create);

/* Private utility - shouldn't be used by clients. */
void hncp_link_reset_trickle(hncp_link l);

bool hncp_node_set_tlvs(hncp_node n, struct tlv_attr *a);
int hncp_node_cmp(hncp_node n1, hncp_node n2);
void hncp_node_recalculate_index(hncp_node n);

bool hncp_add_tlv_index(hncp o, uint16_t type);

bool hncp_get_ipv6_address(hncp o, char *prefer_ifname, struct in6_addr *addr);

void hncp_schedule(hncp o);

/* Flush own TLV changes to own node. */
void hncp_self_flush(hncp_node n);

/* Various hash calculation utilities. */
void hncp_calculate_hash(const void *buf, int len, hncp_hash dest);
void hncp_calculate_network_hash(hncp o);
static inline unsigned long long hncp_hash64(hncp_hash h)
{
  return *((unsigned long long *)h);
}

/* Utility functions to send frames. */
bool hncp_link_send_network_state(hncp_link l,
                                  struct in6_addr *dst,
                                  size_t maximum_size);
bool hncp_link_send_req_network_state(hncp_link l, struct in6_addr *dst);
void hncp_link_set_ipv6_address(hncp_link l, const struct in6_addr *addr);

/* Subscription stuff (hncp_notify.c) */
void hncp_notify_subscribers_tlvs_changed(hncp_node n,
                                          struct tlv_attr *a_old,
                                          struct tlv_attr *a_new);
void hncp_notify_subscribers_node_changed(hncp_node n, bool add);
void hncp_notify_subscribers_about_to_republish_tlvs(hncp_node n);
void hncp_notify_subscribers_local_tlv_changed(hncp o,
                                               struct tlv_attr *a,
                                               bool add);
void hncp_notify_subscribers_link_changed(hncp_link l);

/* Low-level interface module stuff. */

bool hncp_io_init(hncp o);
void hncp_io_uninit(hncp o);
bool hncp_io_set_ifname_enabled(hncp o, const char *ifname, bool enabled);
int hncp_io_get_hwaddrs(unsigned char *buf, int buf_left);
void hncp_io_schedule(hncp o, int msecs);
hnetd_time_t hncp_io_time(hncp o);

ssize_t hncp_io_recvfrom(hncp o, void *buf, size_t len,
                         char *ifname,
                         struct in6_addr *src,
                         struct in6_addr *dst);
ssize_t hncp_io_sendto(hncp o, void *buf, size_t len,
                       const char *ifname,
                       const struct in6_addr *dst);

/* Multicast rejoin utility. (in hncp.c) */
bool hncp_link_join(hncp_link l);

/* TLV handling */
#include "prefix_utils.h"
void hncp_tlv_ap_update(hncp o,
                        const struct prefix *prefix,
                        const char *ifname,
                        bool authoritative,
                        unsigned int preference,
                        bool add);

void hncp_tlv_ra_update(hncp o,
                        uint32_t lid,
                        const struct in6_addr *address,
                        bool add);

/* Inlined utilities. */
static inline hnetd_time_t hncp_time(hncp o)
{
  if (!o->now)
    return hncp_io_time(o);
  return o->now;
}

#define TMIN(x,y) ((x) == 0 ? (y) : (y) == 0 ? (x) : (x) < (y) ? (x) : (y))

#define HNCP_NODE_REPR(n) HEX_REPR(&n->node_identifier_hash, HNCP_HASH_LEN)

static inline struct tlv_attr *
hncp_node_get_tlv_with_type(hncp_node n, uint16_t type, bool first)
{
  if (type >= n->hncp->tlv_type_to_index_length
      || !n->hncp->tlv_type_to_index[type])
    if (!hncp_add_tlv_index(n->hncp, type))
      return NULL;
  if (n->tlv_index_dirty)
    {
      hncp_node_recalculate_index(n);
      if (!n->tlv_index)
        return NULL;
    }
  int index = n->hncp->tlv_type_to_index[type] - 1;
  assert(index >= 0 && index < n->hncp->num_tlv_indexes);
  int i = index * 2 + (first ? 0 : 1);
  return n->tlv_index[i];
}

#define hncp_for_each_node_including_unreachable(o, n)                  \
  for (n = (avl_is_empty(&o->nodes.avl) ?                               \
            NULL : avl_first_element(&o->nodes.avl, n, in_nodes.avl)) ; \
       n ;                                                              \
       n = (n == avl_last_element(&o->nodes.avl, n, in_nodes.avl) ?     \
            NULL : avl_next_element(n, in_nodes.avl)))

#define hncp_node_for_each_tlv_with_type(n, a, type)            \
  for (a = hncp_node_get_tlv_with_type(n, type, true) ;         \
       a && a != hncp_node_get_tlv_with_type(n, type, false) ;  \
       a = tlv_next(a))

#define ROUND_BITS_TO_BYTES(b) (((b) + 7) / 8)
#define ROUND_BYTES_TO_4BYTES(b) ((((b) + 3) / 4) * 4)

static inline hncp_t_assigned_prefix_header
hncp_tlv_ap(const struct tlv_attr *a)
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
hncp_tlv_dp(const struct tlv_attr *a)
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

static inline hncp_t_node_data_neighbor
hncp_tlv_neighbor(const struct tlv_attr *a)
{
  if (tlv_id(a) != HNCP_T_NODE_DATA_NEIGHBOR
      || tlv_len(a) != sizeof(hncp_t_node_data_neighbor_s))
    return NULL;
  return tlv_data(a);
}

static inline hncp_t_router_address
hncp_tlv_router_address(const struct tlv_attr *a)
{
  if (tlv_id(a) != HNCP_T_ROUTER_ADDRESS
      || tlv_len(a) != sizeof(hncp_t_router_address_s))
    return NULL;
  return tlv_data(a);
}

static inline hncp_node
hncp_node_find_neigh_bidir2(hncp_node n,
                            iid_t n_iid,
                            iid_t o_iid,
                            hncp_hash oh)
{
  if (!n)
    return NULL;
  hncp_node n2 = hncp_find_node_by_hash(n->hncp, oh, false);
  if (!n2)
    return NULL;
  struct tlv_attr *a, *tlvs = hncp_node_get_tlvs(n2);
  hncp_t_node_data_neighbor ne;

  tlv_for_each_attr(a, tlvs)
    if ((ne = hncp_tlv_neighbor(a)))
      {
        if (n_iid == ne->neighbor_link_id
            && o_iid == ne->link_id &&
            !memcmp(&ne->neighbor_node_identifier_hash,
                    &n->node_identifier_hash, sizeof(n->node_identifier_hash)))
          return n2;
      }

  return NULL;
}


static inline hncp_node
hncp_node_find_neigh_bidir(hncp_node n, hncp_t_node_data_neighbor ne)
{
  return hncp_node_find_neigh_bidir2(n,
                                     ne->link_id,
                                     ne->neighbor_link_id,
                                     &ne->neighbor_node_identifier_hash);
}



#endif /* HNCP_I_H */
