/*
 * $Id: hcp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:15:53 2013 mstenber
 * Last modified: Wed Dec  4 10:28:37 2013 mstenber
 * Edit time:     82 min
 *
 */

#ifndef HCP_H
#define HCP_H

#include "hnetd.h"
#include "tlv.h"
#include "hcp_proto.h"

#include <libubox/list.h>

/* Opaque pointer that represents hcp instance. */
typedef struct hcp_struct hcp_s, *hcp;

/* Opaque pointer that represents single node (own or another) in
   hcp. It is effectlively TLV list. */
typedef struct hcp_node_struct hcp_node_s, *hcp_node;

typedef struct hcp_subscriber_struct hcp_subscriber_s, *hcp_subscriber;

struct hcp_subscriber_struct {
  /**
   * Place within list of subscribers (owned by hcp while subscription
   * is valid). Using the same subscriber object twice will result in
   * undefined (and most likely bad) behavior.
   */
  struct list_head lh;

  /**
   * TLV change notification.
   *
   * This is called whenever one TLV within one node in HCP
   * changes. This INCLUDE also the local node itself.
   *
   * @param cbs The subscriber structure.
   * @param n The node for which change notification occurs.
   * @param tlv The TLV that is being added or removed (there is no 'update').
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*tlv_change_callback)(hcp_subscriber s,
                              hcp_node n, struct tlv_attr *tlv, bool add);

  /**
   * Node change notification.
   *
   * This is called whenever a node is being added or removed within
   * HCP.
   *
   * @param cbs The subscriber structure.
   * @param n The node which is being added or removed.
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*node_change_callback)(hcp_subscriber s, hcp_node n, bool add);
};

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
 * Subscribe to HCP state change events.
 *
 * This call will register the caller as subscriber to HCP state
 * changes. It will also trigger a series of add notifications for
 * existing state.
 */
void hcp_subscribe(hcp o, hcp_subscriber s);

/**
 * Unsubscribe from HCP state change events.
 *
 * Inverse of hcp_subscribe (including calls to pretend to remove all
 * state).
 */
void hcp_unsubscribe(hcp o, hcp_subscriber s);

/**
 * Run HCP state machine once. It should re-queue itself when needed.
 * (This should be mainly called from timeout callback, or from unit
 * tests).
 */
void hcp_run(hcp o);

/**
 * Poll the i/o system once. This should be called from event loop
 * whenever the udp socket has inputs.
 */
void hcp_poll(hcp o);

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
struct tlv_attr *hcp_node_get_tlvs(hcp_node n);

#define hcp_for_each_node(o, n) \
  for (n = hcp_get_first_node(o) ; n ; n = hcp_node_get_next(n))

#define hcp_node_for_each_tlv(n, a, i) \
  tlv_for_each_attr(a, hcp_node_get_tlvs(n), i)


#endif /* HCP_H */
