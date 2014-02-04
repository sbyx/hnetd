/*
 * $Id: hncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Tue Feb  4 18:21:10 2014 mstenber
 * Edit time:     116 min
 *
 */

#ifndef HNCP_I_H
#define HNCP_I_H

#include "hncp.h"

#include <libubox/uloop.h>

/* Rough approximation - should think of real figure. */
#define HNCP_MAXIMUM_PAYLOAD_SIZE 65536

/* Pretty arbitrary. I wonder if all links can really guarantee MTU size
 * packets going through.. */
#define HNCP_MAXIMUM_MULTICAST_SIZE 1280

#include <libubox/vlist.h>

/* in6_addr */
#include <netinet/in.h>

/* IFNAMSIZ */
#include <net/if.h>

typedef uint32_t iid_t;

struct hncp_struct {
  /* Can we assume bidirectional reachability? */
  bool assume_bidirectional_reachability;

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

  /* flag which indicates that we should re-publish links. */
  bool links_dirty;

  /* flag which indicates that we should re-publish our node in nodes. */
  bool tlvs_dirty;

  /* flag which indicates that we (or someone connected) may have
   * changed connectivity. */
  bool neighbors_dirty;
  hnetd_time_t last_prune;

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
};

typedef struct hncp_link_struct hncp_link_s, *hncp_link;

struct hncp_link_struct {
  struct vlist_node in_links;

  /* Backpointer to hncp */
  hncp hncp;

  /* Who are the neighbors on the link. */
  struct vlist_tree neighbors;

  /* Name of the (local) link. */
  char ifname[IFNAMSIZ];

  /* Address of the interface (_only_ used in testing) */
  struct in6_addr address;

  /* Interface identifier - these should be unique over lifetime of
   * hncp process. */
  iid_t iid;

  /* Join failed -> probably tried during DAD. Should try later again. */
  bool join_pending;

  /* Trickle state */
  int i; /* trickle interval size */
  hnetd_time_t send_time; /* when do we send if c < k*/
  hnetd_time_t interval_end_time; /* when does current interval end */
  int c; /* counter */
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

  /* If proactive mode is enabled, when did we last try to ping this
   * one. */
  hnetd_time_t last_ping;
  int ping_count;
};


struct hncp_bfs_head {
  /* List head for implementing BFS */
  struct list_head head;

  /* Next-hop in path (also used to mark visited nodes) */
  const struct in6_addr *next_hop;
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

  /* Node state stuff */
  hncp_hash_s node_data_hash;
  bool node_data_hash_dirty; /* Something related to hash changed */
  hnetd_time_t origination_time; /* in monotonic time */

  /* TLV data for the node. All TLV data in one binary blob, as
   * received/created. We could probably also maintain this at end of
   * the structure, but that'd mandate re-inserts whenever content
   * changes, so probably just faster to keep a pointer to it. */

  /* (We actually _do_ parse incoming TLV and create a new TLV, just
   * to make sure there's no 'bad actors' somewhere with invalid sizes
   * or whatever). */
  struct tlv_attr *tlv_container;
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

hncp_link hncp_find_link_by_name(hncp o, const char *ifname, bool create);
hncp_link hncp_find_link_by_id(hncp o, uint32_t link_id);
hncp_node hncp_find_node_by_hash(hncp o, const hncp_hash h, bool create);

/* Private utility - shouldn't be used by clients. */
bool hncp_node_set_tlvs(hncp_node n, struct tlv_attr *a);
int hncp_node_cmp(hncp_node n1, hncp_node n2);

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
bool hncp_link_send_req_network_state(hncp_link l,
                                      struct in6_addr *dst);


/* Subscription stuff (hncp_notify.c) */
void hncp_notify_subscribers_tlvs_changed(hncp_node n,
                                          struct tlv_attr *a_old,
                                          struct tlv_attr *a_new);
void hncp_notify_subscribers_node_changed(hncp_node n, bool add);
void hncp_notify_subscribers_about_to_republish_tlvs(hncp_node n);
void hncp_notify_subscribers_local_tlv_changed(hncp o,
                                               struct tlv_attr *a,
                                               bool add);

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
bool hncp_io_get_ipv6(struct in6_addr *addr, char *prefer_ifname);

/* Multicast rejoin utility. (in hncp.c) */
bool hncp_link_join(hncp_link l);

/* TLV handling */
#include "prefix_utils.h"
void hncp_tlv_ap_update(hncp o,
                        const struct prefix *prefix,
                        const char *ifname,
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

#define hncp_node_for_each_tlv_i(n, a, i)       \
  tlv_for_each_attr(a, (n)->tlv_container, i)

#define ROUND_BITS_TO_BYTES(b) (((b) + 7) / 8)
#define ROUND_BYTES_TO_4BYTES(b) ((((b) + 3) / 4) * 4)

static inline bool hncp_tlv_ap_valid(const struct tlv_attr *a)
{
  hncp_t_assigned_prefix_header ah;

  if (tlv_len(a) < sizeof(*ah))
    return false;
  ah = tlv_data(a);
  if (tlv_len(a) < (sizeof(*ah) + ROUND_BITS_TO_BYTES(ah->prefix_length_bits))
      || ah->prefix_length_bits > 128)
    return false;
  return true;
}

static inline bool hncp_tlv_dp_valid(const struct tlv_attr *a)
{
  hncp_t_delegated_prefix_header dh;

  if (tlv_len(a) < sizeof(*dh))
    return false;
  dh = tlv_data(a);
  if (tlv_len(a) < (sizeof(*dh) + ROUND_BITS_TO_BYTES(dh->prefix_length_bits))
      || dh->prefix_length_bits > 128)
    return false;
  return true;
}

#endif /* HNCP_I_H */
