/*
 * $Id: hcp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Mon Nov 25 13:33:44 2013 mstenber
 * Edit time:     55 min
 *
 */

#ifndef HCP_I_H
#define HCP_I_H

/* Rough approximation - should think of real figure (-UDP size - HCP
   header size). */
#define HCP_MAXIMUM_TLV_SIZE 65536
#define HCP_MAXIMUM_LINK_TLV_SIZE 1024

/* How big is one neighbor TLV? (incl. TLV header). */
#define HCP_NEIGHBOR_TLV_SIZE (4 + 4 + HCP_HASH_LEN)

#include <libubox/vlist.h>

/* in6_addr */
#include <netinet/in.h>

/* IFNAMSIZ */
#include <net/if.h>

/* Let's assume we use MD5 for the time being.. */
#define HCP_HASH_LEN 16

/* 64 bit version of the hash */
#define HCP_HASH64_LEN 8

/* Internal definitions for hcp.[ch] - do not touch or include! (This
 * is here mostly for test use.) */

#include "hcp.h"

typedef uint32_t iid_t;

struct hcp_struct {
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

  /* flag which indicates that we should re-calculate network hash
   * based on nodes' state. */
  bool network_hash_dirty;

  /* Our own node (it should be constant, never purged) */
  hcp_node own_node;

  /* Whole network hash we consider current (based on content of 'nodes'). */
  unsigned char network_hash[HCP_HASH_LEN];


  /* First free local interface identifier (we allocate them in
   * monotonically increasing fashion just to keep things simple). */
  int first_free_iid;
};

typedef struct hcp_link_struct hcp_link_s, *hcp_link;

struct hcp_link_struct {
  struct vlist_node in_links;

  /* Backpointer to hcp */
  hcp hcp;

  /* Who are the neighbors on the link. */
  struct vlist_tree neighbors;

  /* Name of the (local) link. */
  char ifname[IFNAMSIZ];

  /* Interface identifier - these should be unique over lifetime of
   * hcp process. */
  iid_t iid;

  /* XXX Trickle state */
};

typedef struct hcp_neighbor_struct hcp_neighbor_s, *hcp_neighbor;


struct hcp_neighbor_struct {
  struct vlist_node in_neighbors;

  unsigned char node_identifier_hash[HCP_HASH_LEN];
  iid_t iid;

  /* Link-level address */
  struct in6_addr last_address;

  /* When did we last hear from this one? */
  time_t last_heard;

  /* When did they last respond to our message? */
  time_t last_response;
};

struct hcp_node_struct {
  /* hcp->nodes entry */
  struct vlist_node in_nodes;

  /* backpointer to hcp */
  hcp hcp;

  /* These map 1:1 to node data TLV's start */
  unsigned char node_identifier_hash[HCP_HASH_LEN];
  uint32_t update_number;

  /* Node state stuff */
  unsigned char node_state_hash[HCP_HASH_LEN];
  time_t origination_time; /* in monotonic time */

  /* TLV data for the node. All TLV data in one binary blob, as
   * received/created. We could probably also maintain this at end of
   * the structure, but that'd mandate re-inserts whenever content
   * changes, so probably just faster to keep a pointer to it. */

  /* (We actually _do_ parse incoming TLV and create a new TLV, just
   * to make sure there's no 'bad actors' somewhere with invalid sizes
   * or whatever). */
  struct tlv_attr *tlv_container;
};

typedef struct hcp_tlv_struct hcp_tlv_s, *hcp_tlv;

struct hcp_tlv_struct {
  /* hcp->tlvs entry */
  struct vlist_node in_tlvs;

  /* Actual TLV attribute itself. */
  struct tlv_attr tlv;
};

/* Internal or testing-only way to initialize hp struct _without_
 * dynamic allocations (and some of the steps omitted too). */
bool hcp_init(hcp o, unsigned char *node_identifier, int len);

void hcp_hash(const void *buf, int len, unsigned char *dest);

#endif /* HCP_I_H */
