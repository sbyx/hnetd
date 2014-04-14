/*
 * $Id: hncp_proto.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 18:17:46 2013 mstenber
 * Last modified: Mon Apr 14 18:57:41 2014 mstenber
 * Edit time:     59 min
 *
 */

#ifndef HNCP_PROTO_H
#define HNCP_PROTO_H

#include <arpa/inet.h>
#include <netinet/in.h>

/******************************** Not standardized, but hopefully one day..  */

/* Current (binary) data schema version
 *
 * Note that adding new TLVs does not require change of version; only
 * change of contents of existing TLVs (used by others) does.
 */
#define HNCP_VERSION 1

/* Let's assume we use MD5 for the time being.. */
#define HNCP_HASH_LEN 16

/* 64 bit version of the hash */
#define HNCP_HASH64_LEN 8

/* When do we start to worry about the other side.. */
#define HNCP_INTERVAL_WORRIED (60 * HNETD_TIME_PER_SECOND)

/* Exponentially backed off retries to 'ping' other side somehow
 * ( either within protocol or without protocol ) to hear from them.
 */
#define HNCP_INTERVAL_RETRIES 3

/* Don't do node pruning more often than this. This should be less
 * than minimum Trickle interval, as currently non-valid state will
 * not be used to respond to node data requests about anyone except
 * self. */
#define HNCP_MINIMUM_PRUNE_INTERVAL (HNETD_TIME_PER_SECOND / 50)

/* 0 = reserved link id. note it somewhere. */

/******************************************************************* TLV T's */

enum {
  /* This should be included in every message to facilitate neighbor
   * discovery of peers. */
  HNCP_T_LINK_ID = 1,

  /* Request TLVs (not to be really stored anywhere) */
  HNCP_T_REQ_NET_HASH = 2, /* empty */
  HNCP_T_REQ_NODE_DATA = 3, /* = just normal hash */

  HNCP_T_NETWORK_HASH = 4, /* = just normal hash, accumulated from node states so sensible to send later */
  HNCP_T_NODE_STATE = 5,

  HNCP_T_NODE_DATA = 6,
  HNCP_T_NODE_DATA_KEY = 7, /* public key payload, not implemented*/
  HNCP_T_NODE_DATA_NEIGHBOR = 8,

  HNCP_T_CUSTOM = 9, /* not implemented */

  HNCP_T_VERSION = 10,

  HNCP_T_EXTERNAL_CONNECTION = 41,
  HNCP_T_DELEGATED_PREFIX = 42, /* may contain TLVs */
  HNCP_T_ASSIGNED_PREFIX = 43, /* may contain TLVs */
  HNCP_T_DHCP_OPTIONS = 44,
  HNCP_T_DHCPV6_OPTIONS = 45, /* contains just raw DHCPv6 options */
  HNCP_T_ROUTER_ADDRESS = 46, /* router address */

  HNCP_T_DNS_DELEGATED_ZONE = 50, /* the 'beef' */
  HNCP_T_DNS_ROUTER_NAME = 51, /* router name (moderately optional) */
  HNCP_T_DNS_DOMAIN_NAME = 52, /* non-default domain (very optional) */

  HNCP_T_ROUTING_PROTOCOL = 60,

  HNCP_T_SIGNATURE = 0xFFFF /* not implemented */
};

#define TLV_SIZE sizeof(struct tlv_attr)

typedef struct __packed {
  unsigned char buf[HNCP_HASH_LEN];
} hncp_hash_s, *hncp_hash;

/* HNCP_T_LINK_ID */
typedef struct __packed {
  hncp_hash_s node_identifier_hash;
  uint32_t link_id;
} hncp_t_link_id_s, *hncp_t_link_id;

/* HNCP_T_REQ_NET_HASH has no content */

/* HNCP_T_REQ_NODE_DATA has only (node identifier) hash */

/* HNCP_T_NETWORK_HASH has only (network state) hash */

/* HNCP_T_NODE_STATE */
typedef struct __packed {
  hncp_hash_s node_identifier_hash;
  uint32_t update_number;
  uint32_t ms_since_origination;
  hncp_hash_s node_data_hash;
} hncp_t_node_state_s, *hncp_t_node_state;

/* HNCP_T_NODE_DATA */
typedef struct __packed {
  hncp_hash_s node_identifier_hash;
  uint32_t update_number;
} hncp_t_node_data_header_s, *hncp_t_node_data_header;

/* HNCP_T_NODE_DATA_KEY has only raw public key (perhaps it should
 * have more information though? TBD */

/* HNCP_T_NODE_DATA_NEIGHBOR */
typedef struct __packed {
  hncp_hash_s neighbor_node_identifier_hash;
  uint32_t neighbor_link_id;
  uint32_t link_id;
} hncp_t_node_data_neighbor_s, *hncp_t_node_data_neighbor;

/* HNCP_T_CUSTOM custom data, with H-64 of URI at start to identify type TBD */

/* HNCP_T_VERSION */
typedef struct __packed {
  uint32_t version;
  char user_agent[];
} hncp_t_version_s, *hncp_t_version;

/* HNCP_T_EXTERNAL_CONNECTION - just container, no own content */

/* HNCP_T_DELEGATED_PREFIX */
typedef struct __packed {
  /* uint32_t link_id; I don't think this is reasonable; by
   * definition, the links we get delegated things should be OUTSIDE
   * this protocol or something weird is going on. */
  uint32_t ms_valid_at_origination;
  uint32_t ms_preferred_at_origination;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_delegated_prefix_header_s, *hncp_t_delegated_prefix_header;

/* HNCP_T_ASSIGNED_PREFIX */
typedef struct __packed {
  uint32_t link_id;
  unsigned int reserved: 3;
  unsigned int authoritative: 1;
  unsigned int preference: 4;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_assigned_prefix_header_s, *hncp_t_assigned_prefix_header;

/* HNCP_T_DHCP_OPTIONS - just container, no own content */
/* HNCP_T_DHCPV6_OPTIONS - just container, no own content */

/* HNCP_T_ROUTER_ADDRESS */
typedef struct __packed {
  uint32_t link_id;
  struct in6_addr address;
} hncp_t_router_address_s, *hncp_t_router_address;

/* HNCP_T_DNS_DELEGATED_ZONE */
typedef struct __packed {
  uint8_t address[16];
  uint8_t flags;
  /* Label list in DNS encoding (no compression). */
  uint8_t ll[];
} hncp_t_dns_delegated_zone_s, *hncp_t_dns_delegated_zone;

/* HNCP_T_DNS_DOMAIN_NAME has just DNS label sequence */

/* HNCP_T_DNS_ROUTER_NAME has just variable length string. */

/* HNCP_T_ROUTING_PROTOCOL */
typedef struct __packed {
  uint8_t protocol;
  uint8_t preference;
} hncp_t_routing_protocol_s, *hncp_t_routing_protocol;


#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE 1
#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH 2

/**************************************************************** Addressing */

#define HNCP_PORT 8808
#define HNCP_MCAST_GROUP "ff02::8808"

/************** Various tunables, that we in practise hardcode (not options) */

/* How often we retry multicast joins? Once per second seems sane
 * enough. */
#define HNCP_REJOIN_INTERVAL (1 * HNETD_TIME_PER_SECOND)

/* Minimum interval trickle starts at. The first potential time it may
 * send something is actually this divided by two. */
#define HNCP_TRICKLE_IMIN (HNETD_TIME_PER_SECOND / 4)

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define HNCP_TRICKLE_IMAX (64 * HNETD_TIME_PER_SECOND)

/* Redundancy constant. */
#define HNCP_TRICKLE_K 1



#endif /* HNCP_PROTO_H */
