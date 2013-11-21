/*
 * $Id: hcp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:15:53 2013 mstenber
 * Last modified: Thu Nov 21 15:07:09 2013 mstenber
 * Edit time:     32 min
 *
 */

#ifndef HCP_H
#define HCP_H

#include "hnetd.h"
#include "tlv.h"

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
