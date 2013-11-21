/*
 * $Id: hcp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Thu Nov 21 14:20:24 2013 mstenber
 * Edit time:     34 min
 *
 */

#ifndef HCP_I_H
#define HCP_I_H

#include <libubox/vlist.h>

/* Let's assume we use MD5 for the time being.. */
#define HCP_HASH_LEN 16

/* 64 bit version of the hash */
#define HCP_HASH64_LEN 8

/* Internal definitions for hcp.[ch] - do not touch or include! (This
 * is here mostly for test use.) */

#include "hcp.h"

struct hcp_struct {
  /* vlist tree of nodes. */
  struct vlist_tree nodes;

  /* vlist tree of local data. */
  struct vlist_tree tlvs;

  /* flag which indicates that we should re-publish our node in nodes. */
  bool should_publish;

  /* Our own node (it should be constant, never purged) */
  hcp_node own_node;

  /* Whole network hash we consider current (based on content of 'nodes'). */
  unsigned char network_hash[HCP_HASH_LEN];
};

struct hcp_link_struct {
  struct vlist_node in_links;
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
