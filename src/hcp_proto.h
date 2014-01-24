/*
 * $Id: hcp_proto.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 18:17:46 2013 mstenber
 * Last modified: Fri Jan 24 13:02:21 2014 mstenber
 * Edit time:     37 min
 *
 */

#ifndef HCP_PROTO_H
#define HCP_PROTO_H

/******************************** Not standardized, but hopefully one day..  */

/* Let's assume we use MD5 for the time being.. */
#define HCP_HASH_LEN 16

/* 64 bit version of the hash */
#define HCP_HASH64_LEN 8

/* When do we start to worry about the other side.. */
#define HCP_INTERVAL_WORRIED (60 * HNETD_TIME_PER_SECOND)

/* Exponentially backed off retries to 'ping' other side somehow
 * ( either within protocol or without protocol ) to hear from them.
 */
#define HCP_INTERVAL_RETRIES 3

/* Don't do node pruning more often than this. */
#define HCP_MINIMUM_PRUNE_INTERVAL (1*HNETD_TIME_PER_SECOND)

/* 0 = reserved link id. note it somewhere. */

/******************************************************************* TLV T's */

enum {
  /* This should be included in every message to facilitate neighbor
   * discovery of peers. */
  HCP_T_LINK_ID = 1,

  /* Request TLVs (not to be really stored anywhere) */
  HCP_T_REQ_NET_HASH = 2, /* empty */
  HCP_T_REQ_NODE_DATA = 3, /* = just normal hash */

  HCP_T_NODE_STATE = 4,
  HCP_T_NETWORK_HASH = 5, /* = just normal hash, accumulated from node states so sensible to send later */

  HCP_T_NODE_DATA = 6,
  HCP_T_NODE_DATA_KEY = 7, /* public key payload, not implemented*/
  HCP_T_NODE_DATA_NEIGHBOR = 8,

  HCP_T_CUSTOM = 9, /* not implemented */

  HCP_T_DELEGATED_PREFIX = 42, /* may contain TLVs */
  HCP_T_ASSIGNED_PREFIX = 43, /* may contain TLVs */

  HCP_T_DHCPV6_OPTIONS = 45, /* contains just raw DHCPv6 options */

  HCP_T_DNS_DELEGATED_ZONE = 50, /* the 'beef' */
  HCP_T_DNS_ROUTER_NAME = 51, /* router name (moderately optional) */
  HCP_T_DNS_DOMAIN_NAME = 52, /* non-default domain (very optional) */

  HCP_T_SIGNATURE = 0xFFFF /* not implemented */
};

#define TLV_SIZE sizeof(struct tlv_attr)

typedef struct __packed {
  unsigned char buf[HCP_HASH_LEN];
} hcp_hash_s, *hcp_hash;

/* HCP_T_LINK_ID */
typedef struct __packed {
  hcp_hash_s node_identifier_hash;
  uint32_t link_id;
} hcp_t_link_id_s, *hcp_t_link_id;

/* HCP_T_NODE_STATE */
typedef struct __packed {
  hcp_hash_s node_identifier_hash;
  uint32_t update_number;
  uint32_t ms_since_origination;
  hcp_hash_s node_data_hash;
} hcp_t_node_state_s, *hcp_t_node_state;

/* HCP_T_NODE_DATA */
typedef struct __packed {
  hcp_hash_s node_identifier_hash;
  uint32_t update_number;
} hcp_t_node_data_header_s, *hcp_t_node_data_header;

/* HCP_T_NODE_DATA_NEIGHBOR */
typedef struct __packed {
  hcp_hash_s neighbor_node_identifier_hash;
  uint32_t neighbor_link_id;
  uint32_t link_id;
} hcp_t_node_data_neighbor_s, *hcp_t_node_data_neighbor;

/* HCP_T_DELEGATED_PREFIX */
typedef struct __packed {
  /* uint32_t link_id; I don't think this is reasonable; by
   * definition, the links we get delegated things should be OUTSIDE
   * this protocol or something weird is going on. */
  uint32_t ms_valid_at_origination;
  uint32_t ms_preferred_at_origination;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hcp_t_delegated_prefix_header_s, *hcp_t_delegated_prefix_header;

/* HCP_T_ASSIGNED_PREFIX */
typedef struct __packed {
  uint32_t link_id;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hcp_t_assigned_prefix_header_s, *hcp_t_assigned_prefix_header;

/* HCP_T_DNS_DELEGATED_ZONE */
typedef struct __packed {
  uint8_t address[16];
  uint8_t flags;
  /* Label list in DNS encoding (no compression). */
  uint8_t ll[];
} hcp_t_dns_delegated_zone_s, *hcp_t_dns_delegated_zone;

#define HCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE 1
#define HCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH 2

/**************************************************************** Addressing */

#define HCP_PORT 8808
#define HCP_MCAST_GROUP "ff02::8808"

/************** Various tunables, that we in practise hardcode (not options) */

/* How often we retry multicast joins? Once per second seems sane
 * enough. */
#define HCP_REJOIN_INTERVAL (1 * HNETD_TIME_PER_SECOND)

/* Minimum interval trickle starts at. The first potential time it may
 * send something is actually this divided by two. */
#define HCP_TRICKLE_IMIN (HNETD_TIME_PER_SECOND / 4)

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define HCP_TRICKLE_IMAX (64 * HNETD_TIME_PER_SECOND)

/* Redundancy constant. */
#define HCP_TRICKLE_K 1



#endif /* HCP_PROTO_H */
