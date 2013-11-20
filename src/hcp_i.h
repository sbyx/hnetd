/*
 * $Id: hcp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:56:12 2013 mstenber
 * Last modified: Wed Nov 20 15:43:30 2013 mstenber
 * Edit time:     13 min
 *
 */

#ifndef HCP_I_H
#define HCP_I_H

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

  /* avl tree of local data (that may not be committed to nodes yet). */
  struct avl_tree tlvs;

  /* flag which indicates that we should re-publish our node in nodes. */
  bool tlvs_dirty;

  /* Our own node (it should be constant, never purged) */
  hcp_node own_node;
};

struct hcp_node_struct {
  /* hcp->nodes entry */
  struct vlist_node avl;

  /* These map 1:1 to node data TLV's start */
  unsigned char node_identifier_hash[HCP_HASH_LEN];
  uint32_t update_number;

  /* TLV data for the node. All TLV data in one binary blob, as
   * received/created. */
  struct tlv_attr *first_tlv;
  int tlv_len;

  /* Node state stuff */
  unsigned char node_state_hash[HCP_HASH_LEN];
  time_t origination_time; /* in monotonic time */
};

struct hcp_tlv_struct {
  /* hcp->tlvs entry */
  struct avl_node avl;

  /* Actual TLV attribute itself. */
  struct tlv_attr *tlv;
};

#endif /* HCP_I_H */
