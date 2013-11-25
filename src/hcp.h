/*
 * $Id: hcp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:15:53 2013 mstenber
 * Last modified: Mon Nov 25 19:01:43 2013 mstenber
 * Edit time:     39 min
 *
 */

#ifndef HCP_H
#define HCP_H

#include "hnetd.h"
#include "tlv.h"

enum {
  /* Request TLVs (not to be really stored anywhere) */
  HCP_T_REQ_NET_HASH = 1,
  HCP_T_REQ_NODE_DATA = 5,

  HCP_T_NET_HASH = 2,
  HCP_T_NODE_ID = 3,
  HCP_T_NODE_STATE = 4,

  HCP_T_NODE_DATA = 6,
  HCP_T_NODE_DATA_KEY = 7,
  HCP_T_NODE_DATA_LINK = 8,
  HCP_T_NODE_DATA_LINK_NEIGHBOR = 9,

  HCP_T_CUSTOM = 10,

  HCP_T_SIGNATURE = 0xFFFF
};

#define HCP_PORT 880
#define HCP_MCAST_GROUP "ff02::880"

/* Opaque pointer that represents hcp instance. */
typedef struct hcp_struct hcp_s, *hcp;

/* Opaque pointer that represents single node (own or another) in
   hcp. It is effectlively TLV list. */
typedef struct hcp_node_struct hcp_node_s, *hcp_node;

/************************************************ API for whole hcp instance */

/**
 * Create HCP instance.
 *
 * This call will create the hcp object, and register it to uloop. In
 * case of error, NULL is returned.
 */
hcp hcp_create(void);

/**
 * Destroy HCP instance
 *
 * This call will destroy the previous created HCP object.
 */
void hcp_destroy(hcp o);

/**
 * Get first HCP node.
 */
hcp_node hcp_get_first_node(hcp o);

/**
 * Publish a single TLV.
 */
bool hcp_add_tlv(hcp o, struct tlv_attr *tlv);

/**
 * Remove a single TLV.
 */
bool hcp_remove_tlv(hcp o, struct tlv_attr *tlv);

/**
 * Enable/disable on an interface.
 */
bool hcp_set_link_enabled(hcp o, const char *ifname, bool enabled);

/**
 * Run HCP state machine once. It should re-queue itself when needed.
 * (This should be mainly called from timeout callback, or from unit
 * tests).
 */
void hcp_run(hcp o);

/************************************************************** Per-node API */

/**
 * Get next HCP node (in order, from HCP).
 */
hcp_node hcp_node_get_next(hcp_node n);

/**
 * Check if the HCP node is ourselves (may require different handling).
 */
bool hcp_node_is_self(hcp_node n);

/**
 * Get the TLVs for particular HCP node.
 */
void hcp_node_get_tlvs(hcp_node n, struct tlv_attr **container_tlv);


#endif /* HCP_H */
