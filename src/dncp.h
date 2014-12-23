/*
 * $Id: dncp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:15:53 2013 mstenber
 * Last modified: Tue Dec 23 15:38:14 2014 mstenber
 * Edit time:     145 min
 *
 */

#pragma once

#include "hnetd.h"
#include "tlv.h"

/* in6_addr */
#include <netinet/in.h>

/* IFNAMSIZ */
#include <net/if.h>

/* DNS_MAX_ESCAPED_LEN */
#include "dns_util.h"

#include <libubox/list.h>

/********************************************* Opaque object-like structures */

/* A single hncp instance. */
typedef struct hncp_struct hncp_s, *hncp;

/* A single node in the hncp network. It is effectively TLV list and
 * other associated metadata that should not be visible to users of
 * this public API. If referring to local node, the TLVs visible here
 * are the ones that have been actually published to other nodes
 * (after a delay). */
typedef struct hncp_node_struct hncp_node_s, *hncp_node;

/* A single, local published TLV.*/
typedef struct hncp_tlv_struct hncp_tlv_s, *hncp_tlv;

/*
 * Flow of HNCP state change notifications (outbound case):
 *
 * - (if local TLV change), local_tlv_change_callback is called
 * .. at some point, when TLV changes are to be published to the network ..
 * - republish_callback is called
 * - tlv_change_callback is called
 */

typedef struct hncp_subscriber_struct hncp_subscriber_s, *hncp_subscriber;

struct hncp_subscriber_struct {
  /**
   * Place within list of subscribers (owned by hncp while subscription
   * is valid). Using the same subscriber object twice will result in
   * undefined (and most likely bad) behavior.
   */
  struct list_head lh;

  /**
   * Local TLV change notification.
   *
   * This is called whenever one local set of TLVs (to be published at
   * some point) changes.
   *
   * @param tlv The TLV that is being added or removed (there is no 'update').
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*local_tlv_change_callback)(hncp_subscriber s,
                                    struct tlv_attr *tlv, bool add);

  /**
   * About to republish local TLVs notification.
   *
   * This is when TLVs with relative timestamps should be refreshed.
   * It is called _before_ TLV change notifications for _local_ TLVs
   * are provided.
   */
  void (*republish_callback)(hncp_subscriber r);

  /**
   * TLV change notification.
   *
   * This is called whenever one TLV within one node in HNCP
   * changes. This INCLUDE also the local node itself.
   *
   * @param n The node for which change notification occurs.
   * @param tlv The TLV that is being added or removed (there is no 'update').
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*tlv_change_callback)(hncp_subscriber s,
                              hncp_node n, struct tlv_attr *tlv, bool add);

  /**
   * Node change notification.
   *
   * This is called whenever a node is being added or removed within
   * HNCP.
   *
   * @param n The node which is being added or removed.
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*node_change_callback)(hncp_subscriber s, hncp_node n, bool add);

  /**
   * Some link-specific information changed.
   *
   * This is called whenever a link's preferred address changes, or
   * set of links itself changes.  (Link omitted because it's assumed
   * this is just general reconfiguration signal. name or index is
   * trivial to add later on if needed, though).
   */
  void (*link_change_callback)(hncp_subscriber s);
};

/********************************************* API for handling single links */

/* (hncp_link itself is implementation detail) */

typedef struct hncp_link_conf_struct hncp_link_conf_s, *hncp_link_conf;
struct hncp_link_conf_struct {
  struct list_head in_link_confs;
  char ifname[IFNAMSIZ]; /* Name of the link. */
  char dnsname[DNS_MAX_ESCAPED_LEN]; /* DNS FQDN or label */

  /* Trickle conf */
  hnetd_time_t trickle_imin, trickle_imax;
  int trickle_k;

  /* How frequently (overriding Trickle) we MUST send something on the
   * link. */
  hnetd_time_t keepalive_interval;
};

/**
 * Find or create new hncp_link_conf_s that matches the interface.
 */
hncp_link_conf hncp_if_find_conf_by_name(hncp o, const char *ifname);

/**
 * Does the current HNCP instance have highest ID on the given interface?
 */
bool hncp_if_has_highest_id(hncp o, const char *ifname);

/**
 * Enable/disable HNCP protocol on an interface.
 */
bool hncp_if_set_enabled(hncp o, const char *ifname, bool enabled);

/************************************************ API for whole hncp instance */

/**
 * Create DNCP instance.
 *
 * This call will create the hncp object, and register it to uloop. In
 * case of error, NULL is returned.
 */
hncp dncp_create(void);

/**
 * Destroy HNCP instance
 *
 * This call will destroy the previous created HNCP object.
 */
void hncp_destroy(hncp o);

/**
 * Get first HNCP node.
 */
hncp_node hncp_get_first_node(hncp o);

/**
 * Publish a single TLV.
 *
 * @return The newly allocated TLV, which is valid until
 * hncp_remove_tlv is called for it. Otherwise NULL.
 */
hncp_tlv hncp_add_tlv(hncp o,
                      uint16_t type, void *data, uint16_t len,
                      int extra_bytes);

#define hncp_add_tlv_attr(o, a, bytes) \
  hncp_add_tlv(o, tlv_id(a), tlv_data(a), tlv_len(a), bytes)

/**
 * Find TLV with exact match (if any).
 */
hncp_tlv hncp_find_tlv(hncp o, uint16_t type, void *data, uint16_t len);

/**
 * Stop publishing a TLV.
 */
void hncp_remove_tlv(hncp o, hncp_tlv tlv);

#define hncp_remove_tlv_matching(o, t, d, dlen) \
  hncp_remove_tlv(o, hncp_find_tlv(o, t, d, dlen))

/**
 * Remove all TLVs of particular type.
 *
 * @return The number of TLVs removed.
 */
int hncp_remove_tlvs_by_type(hncp o, int type);

/**
 * Subscribe to HNCP state change events.
 *
 * This call will register the caller as subscriber to HNCP state
 * changes. It will also trigger a series of add notifications for
 * existing state.
 */
void hncp_subscribe(hncp o, hncp_subscriber s);

/**
 * Unsubscribe from HNCP state change events.
 *
 * Inverse of hncp_subscribe (including calls to pretend to remove all
 * state).
 */
void hncp_unsubscribe(hncp o, hncp_subscriber s);

/**
 * Run HNCP state machine once. It should re-queue itself when needed.
 * (This should be mainly called from timeout callback, or from unit
 * tests).
 */
void hncp_run(hncp o);

/**
 * Poll the i/o system once. This should be called from event loop
 * whenever the udp socket has inputs.
 */
void hncp_poll(hncp o);

/************************************************************** Per-node API */

/**
 * Get next HNCP node (in order, from HNCP).
 */
hncp_node hncp_node_get_next(hncp_node n);

/**
 * Check if the HNCP node is ourselves (may require different handling).
 */
bool hncp_node_is_self(hncp_node n);

/**
 * Get the TLVs for particular HNCP node.
 */
struct tlv_attr *hncp_node_get_tlvs(hncp_node n);

#define hncp_for_each_node(o, n)                                        \
  for (n = hncp_get_first_node(o) ; n ; n = hncp_node_get_next(n))

#define hncp_node_for_each_tlv(n, a)    \
  tlv_for_each_attr(a, hncp_node_get_tlvs(n))

/******************************************************* Per-(local) tlv API */

/**
 * Get the extra byte pointer associated with the tlv (extra_bytes).
 *
 * As length is not stored anywhere, it is up to the caller to be
 * consistent. If extra_bytes is zero, the first byte pointed by the
 * return value may already be invalid.
 */
void *hncp_tlv_get_extra(hncp_tlv tlv);
