/*
 * $Id: dncp_proto.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 18:17:46 2013 mstenber
 * Last modified: Mon May 25 12:41:38 2015 mstenber
 * Edit time:     121 min
 *
 */

#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>

/******************************************************************* TLV T's */

enum {
  /* Request TLVs (not to be really stored anywhere) */
  DNCP_T_REQ_NET_STATE = 1, /* empty */
  DNCP_T_REQ_NODE_STATE = 2, /* = just normal hash */

  /* This should be included in every message to facilitate neighbor
   * discovery of peers. */
  DNCP_T_ENDPOINT_ID = 3,

  DNCP_T_NET_STATE = 4, /* = just normal hash, accumulated from node states so sensible to send later */
  DNCP_T_NODE_STATE = 5,
  DNCP_T_CUSTOM = 6, /* not implemented */
  DNCP_T_FRAGMENT_COUNT = 7, /* not implemented */
  DNCP_T_NEIGHBOR = 8,
  DNCP_T_KEEPALIVE_INTERVAL = 9,
  DNCP_T_TRUST_VERDICT = 10
};

#define TLV_SIZE sizeof(struct tlv_attr)

#define DNCP_SHA256_LEN 32

typedef struct __packed {
  unsigned char buf[DNCP_SHA256_LEN];
} dncp_sha256_s, *dncp_sha256;

/* DNCP_T_REQ_NET_STATE has no content */

/* DNCP_T_REQ_NODE_STATE has only (node identifier) hash */

/* DNCP_T_ENDPOINT_ID */
typedef struct __packed {
  /* dncp_node_identifier_s node_identifier; variable length, encoded here */
  uint32_t link_id;
} dncp_t_link_id_s, *dncp_t_link_id;

/* DNCP_T_NET_STATE has only (network state) hash */

/* DNCP_T_NODE_STATE */
typedef struct __packed {
  /* dncp_node_identifier_s node_identifier; variable length, encoded here */
  uint32_t update_number;
  uint32_t ms_since_origination;
  /* + hash + + optional node data after this */
} dncp_t_node_state_s, *dncp_t_node_state;

/* DNCP_T_CUSTOM custom data, with H-64 of URI at start to identify type TBD */

/* DNCP_T_NEIGHBOR */
typedef struct __packed {
  /* dncp_node_identifier_s node_identifier; variable length, encoded here */
  uint32_t neighbor_link_id;
  uint32_t link_id;
} dncp_t_neighbor_s, *dncp_t_neighbor;

/* DNCP_T_KEEPALIVE_INTERVAL */
typedef struct __packed {
  uint32_t link_id;
  uint32_t interval_in_ms;
} dncp_t_keepalive_interval_s, *dncp_t_keepalive_interval;

typedef enum {
  DNCP_VERDICT_NONE = -1, /* internal, should not be stored */
  DNCP_VERDICT_NEUTRAL = 0,
  DNCP_VERDICT_CACHED_POSITIVE = 1,
  DNCP_VERDICT_CACHED_NEGATIVE = 2,
  DNCP_VERDICT_CONFIGURED_POSITIVE = 3,
  DNCP_VERDICT_CONFIGURED_NEGATIVE = 4,
  NUM_DNCP_VERDICT = 5
} dncp_trust_verdict;

#define DNCP_T_TRUST_VERDICT_CNAME_LEN 64

/* DNCP_T_TRUST_VERDICT */
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
