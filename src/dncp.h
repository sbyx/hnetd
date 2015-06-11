/*
 * $Id: dncp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 13:15:53 2013 mstenber
 * Last modified: Thu Jun 11 09:48:33 2015 mstenber
 * Edit time:     261 min
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

/* ep_id_t */
#include "dncp_proto.h"

/********************************************* Opaque object-like structures */

/* Defined later; this is the 'public' part of I/O + system API, which
 * essentially just contains a set of callbacks. */
typedef struct dncp_ext_struct dncp_ext_s, *dncp_ext;

/* (Not so opaque) per-endpoint _configuration_ blob, that is actually
 * part of implementation-side-only dncp_ep_i. */
typedef struct dncp_ep_struct dncp_ep_s, *dncp_ep;


/* A single dncp instance. */
typedef struct dncp_struct dncp_s, *dncp;

/* A single node in the dncp network. It is effectively TLV list and
 * other associated metadata that should not be visible to users of
 * this public API. If referring to local node, the TLVs visible here
 * are the ones that have been actually published to other nodes
 * (after a delay). */
typedef struct dncp_node_struct dncp_node_s, *dncp_node;

/* generic subscriber event enum */
enum dncp_subscriber_event {
  DNCP_EVENT_REMOVE,
  DNCP_EVENT_ADD,
  DNCP_EVENT_UPDATE
};

/* A single, local published TLV.*/
typedef struct dncp_tlv_struct dncp_tlv_s, *dncp_tlv;

/*
 * Flow of DNCP state change notifications (outbound case):
 *
 * - (if local TLV change), local_tlv_change_callback is called
 * .. at some point, when TLV changes are to be published to the network ..
 * - republish_callback is called
 * - tlv_change_callback is called
 */

enum {
  DNCP_CALLBACK_LOCAL_TLV,
  DNCP_CALLBACK_REPUBLISH,
  DNCP_CALLBACK_TLV,
  DNCP_CALLBACK_NODE,
  DNCP_CALLBACK_LINK,
  DNCP_CALLBACK_SOCKET_MSG,
  NUM_DNCP_CALLBACKS
};

typedef struct dncp_subscriber_struct dncp_subscriber_s, *dncp_subscriber;

struct dncp_subscriber_struct {
  /**
   * Place within list of subscribers (owned by dncp while subscription
   * is valid). Using the same subscriber object twice will result in
   * undefined (and most likely bad) behavior.
   */
  struct list_head lhs[NUM_DNCP_CALLBACKS];

  /**
   * Local TLV change notification.
   *
   * This is called whenever one local set of TLVs (to be published at
   * some point) changes.
   *
   * @param tlv The TLV that is being added or removed (there is no 'update').
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*local_tlv_change_callback)(dncp_subscriber s,
                                    struct tlv_attr *tlv, bool add);

  /**
   * About to republish local TLVs notification.
   *
   * This is when TLVs with relative timestamps should be refreshed.
   * It is called _before_ TLV change notifications for _local_ TLVs
   * are provided.
   */
  void (*republish_callback)(dncp_subscriber r);

  /**
   * TLV change notification.
   *
   * This is called whenever one TLV within one node in DNCP
   * changes. This INCLUDE also the local node itself.
   *
   * @param n The node for which change notification occurs.
   * @param tlv The TLV that is being added or removed (there is no 'update').
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*tlv_change_callback)(dncp_subscriber s,
                              dncp_node n, struct tlv_attr *tlv, bool add);

  /**
   * Node change notification.
   *
   * This is called whenever a node is being added or removed within
   * DNCP.
   *
   * @param n The node which is being added or removed.
   * @param add Flag which indicates whether the operation was add or remove.
   */
  void (*node_change_callback)(dncp_subscriber s, dncp_node n, bool add);

  /**
   * Some link-specific information changed.
   *
   * This is called whenever a link's preferred address changes, or
   * set of links itself changes.
   *
   * @param ifname The link which is being added, removed or modified.
   * @param event indicates whether the link was added, removed or updated.
   */
  void (*link_change_callback)(dncp_subscriber s, dncp_ep ep,
                               enum dncp_subscriber_event event);

  /**
   * TLV(s) received on a socket-notification.
   *
   * This is called whenever a message is received, either unicast or
   * multicast, on one of the socket(s) controlled by DNCP.
   *
   * NOTE: This is very low-level message handling callback; NO CHECKS
   * HAVE BEEN PERFORMED ON THE PAYLOAD (or that src/dst are really
   * allowed to send us something). Only in the (global) DTLS mode
   * handling this without address checks is probably ok, as the
   * authentication and authorization has happened before this
   * callback is called.
   */
  void (*msg_received_callback)(dncp_subscriber s,
                                dncp_ep ep,
                                struct sockaddr_in6 *src,
                                struct sockaddr_in6 *dst,
                                int recv_flags,
                                struct tlv_attr *msg);
};

/***************************************** API for handling single endpoints */

/* (dncp_ep_i itself is implementation detail) */

struct dncp_ep_struct {
  char ifname[IFNAMSIZ]; /* Name of the endpoint. */
  /* NOTE: This MUST NOT be changed. It is kept around just for
   * usability reasons. */

  char dnsname[DNS_MAX_ESCAPED_LEN]; /* DNS FQDN or label */

  /* Trickle conf */
  hnetd_time_t trickle_imin, trickle_imax;
  int trickle_k;

  /* How frequently (overriding Trickle) we MUST send something on the
   * link. */
  hnetd_time_t keepalive_interval;

  /* How large can the multicasts be? */
  ssize_t maximum_multicast_size;

  /* Do we accept node data updates via multicast? */
  bool accept_node_data_updates_via_multicast;

  /* Accept non-linklocal traffic (insecure). */
  bool accept_insecure_nonlocal_traffic;

  /* Accept non-linklocal traffic (secure). */
  bool accept_secure_nonlocal_traffic;

  /* Indicate that the interface is in unicast mode.
   *
   * In unicast mode, the keep-alives are handled per-peer, and so is
   * sending of Trickle state.
   */
  bool unicast_only;

  /* Is unicast stream + reliable? */
  bool unicast_is_reliable_stream;
};

/**
 * Find or create an endpoint that matches the name.
 */
dncp_ep dncp_find_ep_by_name(dncp o, const char *name);

/**
 * Find an endpoint that matches the id, or NULL if it does not exist.
 */
dncp_ep dncp_find_ep_by_id(dncp o, ep_id_t ep_id);

/**
 * Does the current DNCP instance have highest ID on the given endpoint?
 */
bool dncp_ep_has_highest_id(dncp_ep ep);

/**
 * Get next DNCP endpoint.
 */
dncp_ep dncp_ep_get_next(dncp_ep ep);

#define dncp_for_each_ep(o, ep)                                         \
  for (ep = dncp_get_first_ep(o) ; ep ; ep = dncp_ep_get_next(ep))

#define dncp_for_each_enabled_ep(o, ep)                 \
  dncp_for_each_ep(o, ep) if (dncp_ep_is_enabled(ep))

/* Various accessors */
dncp dncp_ep_get_dncp(dncp_ep ep);
ep_id_t dncp_ep_get_id(dncp_ep ep);
bool dncp_ep_is_enabled(dncp_ep ep);

/************************************************ API for whole dncp instance */

/**
 * Create DNCP instance.
 *
 * This call will create the dncp object, and register it to uloop. In
 * case of error, NULL is returned.
 */
dncp dncp_create(dncp_ext ext);

/**
 * Destroy DNCP instance
 *
 * This call will destroy the previous created DNCP object.
 */
void dncp_destroy(dncp o);

/**
 * Get first DNCP node.
 */
dncp_node dncp_get_first_node(dncp o);

/**
 * Get first DNCP endpoint.
 */
dncp_ep dncp_get_first_ep(dncp o);

/**
 * Publish a single TLV.
 *
 * @return The newly allocated TLV, which is valid until
 * dncp_remove_tlv is called for it. Otherwise NULL.
 */
dncp_tlv dncp_add_tlv(dncp o,
                      uint16_t type, void *data, uint16_t len,
                      int extra_bytes);

#define dncp_add_tlv_attr(o, a, bytes)                          \
  dncp_add_tlv(o, tlv_id(a), tlv_data(a), tlv_len(a), bytes)

/**
 * Find TLV with exact match (if any).
 */
dncp_tlv dncp_find_tlv(dncp o, uint16_t type, void *data, uint16_t len);

/**
 * Find node with matching node identifier (if any).
 */
dncp_node dncp_find_node_by_node_id(dncp o, void *nibuf, bool create);

/**
 * Stop publishing a TLV.
 */
void dncp_remove_tlv(dncp o, dncp_tlv tlv);

#define dncp_remove_tlv_matching(o, t, d, dlen)         \
  dncp_remove_tlv(o, dncp_find_tlv(o, t, d, dlen))

/**
 * Remove all TLVs of particular type.
 *
 * @return The number of TLVs removed.
 */
int dncp_remove_tlvs_by_type(dncp o, int type);

/**
 * Set the local node identifier.
 *
 * 'nibuf' must be of same size as the given node_id_length.
 */
bool dncp_set_own_node_id(dncp o, void *nibuf);

/**
 * Subscribe to DNCP state change events.
 *
 * This call will register the caller as subscriber to DNCP state
 * changes. It will also trigger a series of add notifications for
 * existing state.
 */
void dncp_subscribe(dncp o, dncp_subscriber s);

/**
 * Unsubscribe from DNCP state change events.
 *
 * Inverse of dncp_subscribe (including calls to pretend to remove all
 * state).
 */
void dncp_unsubscribe(dncp o, dncp_subscriber s);

/* Accessors */
dncp_ext dncp_get_ext(dncp o);
dncp_node dncp_get_own_node(dncp o);

/************************************************************** Per-node API */

/**
 * Get next DNCP node (in order, from DNCP).
 */
dncp_node dncp_node_get_next(dncp_node n);

/**
 * Check if the DNCP node is ourselves (may require different handling).
 */
bool dncp_node_is_self(dncp_node n);

/**
 * Get the TLVs for particular DNCP node.
 */
struct tlv_attr *dncp_node_get_tlvs(dncp_node n);

#define dncp_for_each_node(o, n)                                        \
  for (n = dncp_get_first_node(o) ; n ; n = dncp_node_get_next(n))

#define dncp_node_for_each_tlv(n, a)            \
  tlv_for_each_attr(a, dncp_node_get_tlvs(n))

/* Accessors */
void *dncp_node_get_id(dncp_node n);
dncp dncp_node_get_dncp(dncp_node n);
hnetd_time_t dncp_node_get_origination_time(dncp_node n);

/* Assorted node handling utilities */
const char *dncp_node_repr(dncp_node n, char *to_buf);
int dncp_node_cmp(dncp_node n1, dncp_node n2);

struct tlv_attr *dncp_node_get_tlv_with_type(dncp_node n, uint16_t type, bool first);

#define dncp_node_for_each_tlv_with_type(n, a, type)            \
  for (a = dncp_node_get_tlv_with_type(n, type, true) ;         \
       a && a != dncp_node_get_tlv_with_type(n, type, false) ;  \
       a = tlv_next(a))


/******************************************************* Per-(local) tlv API */

/**
 * Get the extra byte pointer associated with the tlv (extra_bytes).
 *
 * As length is not stored anywhere, it is up to the caller to be
 * consistent. If extra_bytes is zero, the first byte pointed by the
 * return value may already be invalid.
 */
void *dncp_tlv_get_extra(dncp_tlv tlv);

dncp_tlv dncp_get_next_tlv(dncp o, dncp_tlv tlv);

struct tlv_attr *dncp_tlv_get_attr(dncp_tlv tlv);

#define dncp_for_each_tlv(o, t)                                         \
  for (t = dncp_get_first_tlv(o) ; t ; t = dncp_get_next_tlv(o, t))

#define dncp_for_each_tlv_safe(o, t, t2)                                \
  for (t = dncp_get_first_tlv(o), t2 = dncp_get_next_tlv(o, t) ; t;     \
       t = t2, t2 = dncp_get_next_tlv(o, t))

dncp_tlv dncp_get_first_tlv(dncp o);

/**************************************************** dncp external bits API */

/*
 * Change these if you need bigger; however, by default, we wind up
 * wasting some memory (but as dynamic allocations are not really free
 * either, I do not care). (And we have ~2 of these per node, so
 * memory overhead in typical small networks is not large.)
 */
#define DNCP_HASH_MAX_LEN 32
#define DNCP_NI_MAX_LEN 32

/* These cover i/o, profile, and system interface. Notably, we assume
 * sockaddr_in6 is sufficient encoding for addresses, and if it is
 * not, someone needs to do some refactoring. As DNCP code itself does
 * not use it for anything else than just storing it, it should be
 * _relatively_ straightforward to abstract further if the need
 * comes. */

struct dncp_ext_configuration_struct {
  /* Per-link configuration defaults to what is provided here. */
  dncp_ep_s per_link;

  /* Size of the node identifier; MUST be <= DNCP_NI_MAX_LEN */
  uint8_t node_id_length;

  /* Hash length; MUST be <= DNCP_HASH_MAX_LEN */
  uint8_t hash_length;

  /* Keepalive multiplier (as percent of keepalive interval) */
  uint16_t keepalive_multiplier_percent;

  /* How recently node has to have been reachable before prune kills
   * it for real. */
  hnetd_time_t grace_interval;

  /* How often frequently the pruning is done at most; it should be
   * less than minimum Trickle interval, as non-valid state will not
   * be used to respond to node data requests. */
  hnetd_time_t minimum_prune_interval;

  /* How much memory do we allocate for external code parts per node? */
  size_t ext_node_data_size;

  /* How much memory do we allocate for external code parts per ep? */
  size_t ext_ep_data_size;
};

/* While the code uses sockaddr_in6 for now, it intentionally does not
 * use any of the internal semantics within dncp*. Therefore, the I/O
 * is responsible for setting following flags:
 *
 * Note also that 'NULL' dst is mapped to the multicast address, but
 * as dncp does not need to know about it, it does not.
 */

/* IN6_IS_ADDR_LINKLOCAL result on src/dst */
#define DNCP_RECV_FLAG_SRC_LINKLOCAL 0x1
#define DNCP_RECV_FLAG_DST_LINKLOCAL 0x2

/* Whether or not the packet was actually received using secure means. */
#define DNCP_RECV_FLAG_SECURE        0x4

/* Whether or not security was available. If this is set, but
 * FLAG_SECURE is not, packet should be probably ignored. */
#define DNCP_RECV_FLAG_SECURE_TRIED  0x8

struct dncp_ext_callbacks_struct {
  /* I/O-related callbacks */

  /** Receive bytes from the network. ep, src, dst are set as appropriate. */
  ssize_t (*recv)(dncp_ext e, dncp_ep *ep,
                  struct sockaddr_in6 **src,
                  struct sockaddr_in6 **dst,
                  int *flags,
                  void *buf, size_t buf_len);

  /** Send bytes to the network. */
  void (*send)(dncp_ext e, dncp_ep ep,
               struct sockaddr_in6 *src,
               struct sockaddr_in6 *dst,
               void *buf, size_t buf_len);

  /* Profile-related callbacks */

  /**
   * Callback to perform hashing.
   *
   * It MUST write only hash_length (see above) bytes to dst after
   * running hash over buf[:len].
   */
  void (*hash)(const void *buf, size_t len, void *dst);

  /**
   * Validate node data.
   */
  struct tlv_attr *(*validate_node_data)(dncp_node n, struct tlv_attr *a);

  /**
   * Handle node identifier collision.
   *
   * If it returns true, the collision should be ignored (=the code
   * did something); if it returns false, the current node's TLV data
   * should be republished (with higher update number - 'we are right,
   * we are not moving').
   */
  bool (*handle_collision)(dncp_ext e);

  /* Platform abstraction layer (facilitates unit testing etc.) */
  int (*get_hwaddrs)(dncp_ext e, unsigned char *buf, int buf_left);
  hnetd_time_t (*get_time)(dncp_ext e);
  void (*schedule_timeout)(dncp_ext e, int msecs);
};

struct dncp_ext_struct {
  struct dncp_ext_configuration_struct conf;
  struct dncp_ext_callbacks_struct cb;
};

/**
 * Get the external node data pointer of an endpoint. If endpoint is
 * NULL, extdata is also NULL.
 */
void *dncp_ep_get_ext_data(dncp_ep n);

/**
 * Get the external node data pointer of a node. If node is NULL,
 * extdata is also NULL.
 */
void *dncp_node_get_ext_data(dncp_node n);

/**
 * Reverse operation - convert ext data pointer to node.
 */
dncp_node dncp_node_from_ext_data(void *ext_data);


/**
 * Notification from i/o that the endpoint is ready.
 */
void dncp_ext_ep_ready(dncp_ep ep, bool ready);

/**
 * Reverse operation - convert ext data pointer to ep.
 */
dncp_ep dncp_ep_from_ext_data(void *ext_data);

/**
 * Notification from i/o that a peer state has changed.
 *
 * These will occur only on connection-oriented transport. The 'local'
 * (and possibly even remote) MAY be NULL if the transport warrants
 * it. Any peer (defined by (local, remote) in 'connected' state) is
 * assumed to be reachable and DNCP MAY attempt to send packets to it.
 */
void dncp_ext_ep_peer_state(dncp_ep ep,
                            struct sockaddr_in6 *local,
                            struct sockaddr_in6 *remote,
                            bool connected);

/**
 * Notification from the i/o that there is something new available to be read.
 */
void dncp_ext_readable(dncp dncp);

/**
 * Notification from the platform that the timeout has expired.
 */
void dncp_ext_timeout(dncp dncp);

/****************************************** For profile implementation use.. */

/* Subscription stuff (dncp_notify.c) */
void dncp_notify_subscribers_tlvs_changed(dncp_node n,
                                          struct tlv_attr *a_old,
                                          struct tlv_attr *a_new);
void dncp_notify_subscribers_node_changed(dncp_node n, bool add);
void dncp_notify_subscribers_about_to_republish_tlvs(dncp_node n);
void dncp_notify_subscribers_local_tlv_changed(dncp o,
                                               struct tlv_attr *a,
                                               bool add);
void dncp_notify_subscribers_link_changed(dncp_ep ep,
                                          enum dncp_subscriber_event event);
