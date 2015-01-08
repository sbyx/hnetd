/*
 * $Id: dncp_proto.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 18:17:46 2013 mstenber
 * Last modified: Thu Jan  8 14:32:54 2015 mstenber
 * Edit time:     106 min
 *
 */

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>

#include "dncp_profile.h"

/******************************************************************* TLV T's */

enum {
  /* This should be included in every message to facilitate neighbor
   * discovery of peers. */
  DNCP_T_LINK_ID = 1,

  /* Request TLVs (not to be really stored anywhere) */
  DNCP_T_REQ_NET_HASH = 2, /* empty */
  DNCP_T_REQ_NODE_DATA = 3, /* = just normal hash */

  /* 4-9 reserved for profile use */

  DNCP_T_NETWORK_HASH = 10, /* = just normal hash, accumulated from node states so sensible to send later */
  DNCP_T_NODE_STATE = 11,

  DNCP_T_NODE_DATA = 12,
  DNCP_T_NODE_DATA_NEIGHBOR = 13,
  DNCP_T_KEEPALIVE_INTERVAL = 14,
  DNCP_T_CUSTOM = 15, /* not implemented */
  DNCP_T_TRUST_VERDICT = 16
};

#define TLV_SIZE sizeof(struct tlv_attr)

typedef struct __packed {
  unsigned char buf[DNCP_HASH_LEN];
} dncp_hash_s, *dncp_hash;

typedef struct __packed {
  unsigned char buf[DNCP_SHA256_LEN];
} dncp_sha256_s, *dncp_sha256;

typedef struct __packed {
  unsigned char buf[DNCP_NI_LEN];
} dncp_node_identifier_s, *dncp_node_identifier;

/* DNCP_T_LINK_ID */
typedef struct __packed {
  dncp_node_identifier_s node_identifier;
  uint32_t link_id;
} dncp_t_link_id_s, *dncp_t_link_id;

/* DNCP_T_REQ_NET_HASH has no content */

/* DNCP_T_REQ_NODE_DATA has only (node identifier) hash */

/* DNCP_T_NETWORK_HASH has only (network state) hash */

/* DNCP_T_NODE_STATE */
typedef struct __packed {
  dncp_node_identifier_s node_identifier;
  uint32_t update_number;
  uint32_t ms_since_origination;
  dncp_hash_s node_data_hash;
} dncp_t_node_state_s, *dncp_t_node_state;

/* DNCP_T_NODE_DATA */
typedef struct __packed {
  dncp_node_identifier_s node_identifier;
  uint32_t update_number;
} dncp_t_node_data_header_s, *dncp_t_node_data_header;

/* DNCP_T_NODE_DATA_NEIGHBOR */
typedef struct __packed {
  dncp_node_identifier_s neighbor_node_identifier;
  uint32_t neighbor_link_id;
  uint32_t link_id;
} dncp_t_node_data_neighbor_s, *dncp_t_node_data_neighbor;

/* DNCP_T_CUSTOM custom data, with H-64 of URI at start to identify type TBD */

typedef enum {
  DNCP_VERDICT_NONE = -1, /* internal, should not be stored */
  DNCP_VERDICT_NEUTRAL = 0,
  DNCP_VERDICT_CACHED_POSITIVE = 1,
  DNCP_VERDICT_CACHED_NEGATIVE = 2,
  DNCP_VERDICT_CONFIGURED_POSITIVE = 3,
  DNCP_VERDICT_CONFIGURED_NEGATIVE = 4
} dncp_trust_verdict;

#define DNCP_T_TRUST_VERDICT_CNAME_LEN 64

typedef struct __packed {
  uint8_t verdict;
  uint8_t reserved[3];
  dncp_sha256_s sha256_hash;
  char cname[];
} dncp_t_trust_verdict_s, *dncp_t_trust_verdict;


/************** Various tunables, that we in practise hardcode (not options) */

/* How often we retry multicast joins? Once per second seems sane
 * enough. */
#define DNCP_REJOIN_INTERVAL (1 * HNETD_TIME_PER_SECOND)

