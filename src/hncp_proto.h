/*
 * $Id: hncp_proto.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:52:55 2014 mstenber
 * Last modified: Thu Jan  8 14:31:24 2015 mstenber
 * Edit time:     4 min
 *
 */

#pragma once

/***************************************** Structures encoded on top of DNCP */

enum {
  HNCP_T_VERSION = 32,

  HNCP_T_EXTERNAL_CONNECTION = 33,
  HNCP_T_DELEGATED_PREFIX = 34, /* may contain TLVs */
  HNCP_T_ASSIGNED_PREFIX = 35, /* may contain TLVs */
  HNCP_T_ROUTER_ADDRESS = 36, /* router address */
  HNCP_T_DHCP_OPTIONS = 37,
  HNCP_T_DHCPV6_OPTIONS = 38, /* contains just raw DHCPv6 options */

  HNCP_T_DNS_DELEGATED_ZONE = 39, /* the 'beef' */
  HNCP_T_DNS_DOMAIN_NAME = 40, /* non-default domain (very optional) */
  HNCP_T_DNS_ROUTER_NAME = 41, /* router name (moderately optional) */
  HNCP_T_MANAGED_PSK = 42,

  HNCP_T_ROUTING_PROTOCOL = 199 /* RP election (for now) from
                                   'implementation specific reserved
                                   space waiting for RP choice */
};

/* HNCP_T_VERSION */
typedef struct __packed {
  uint8_t version;
  uint8_t reserved;
  unsigned int cap_mdnsproxy:4;
  unsigned int cap_prefixdel:4;
  unsigned int cap_hostnames:4;
  unsigned int cap_legacy:4;
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
  uint8_t flags;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_assigned_prefix_header_s, *hncp_t_assigned_prefix_header;

#define HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE 0x10
#define HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(flags) ((flags) & 0xf)

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

#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH 1
#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE 2
#define HNCP_T_DNS_DELEGATED_ZONE_FLAG_LEGACY_BROWSE 4

/* HNCP_T_DNS_DOMAIN_NAME has just DNS label sequence */

/* HNCP_T_DNS_ROUTER_NAME */
typedef struct __packed {
  struct in6_addr address;
  char name[];
} hncp_t_dns_router_name_s, *hncp_t_dns_router_name;

/* HNCP_T_ROUTING_PROTOCOL */
typedef struct __packed {
  uint8_t protocol;
  uint8_t preference;
} hncp_t_routing_protocol_s, *hncp_t_routing_protocol;

/**************************************************************** Addressing */

#define HNCP_PORT 8808
#define HNCP_DTLS_SERVER_PORT 8809
#define HNCP_MCAST_GROUP "ff02::8808"
