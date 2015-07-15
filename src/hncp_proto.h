/*
 * $Id: hncp_proto.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:52:55 2014 mstenber
 * Last modified: Mon Jun  8 12:56:00 2015 mstenber
 * Edit time:     9 min
 *
 */

#pragma once

/***************************************** Structures encoded on top of DNCP */

enum {
  /* hncp draft itself */
  HNCP_T_VERSION = 32,

  HNCP_T_EXTERNAL_CONNECTION = 33,
  HNCP_T_DELEGATED_PREFIX = 34, /* may contain TLVs */
  HNCP_T_ASSIGNED_PREFIX = 35, /* may contain TLVs */
  HNCP_T_ROUTER_ADDRESS = 36, /* router address */
  HNCP_T_DHCPV6_OPTIONS = 37, /* contains just raw DHCPv6 options */
  HNCP_T_DHCP_OPTIONS = 38,

  HNCP_T_DNS_DELEGATED_ZONE = 39, /* the 'beef' */
  HNCP_T_DNS_DOMAIN_NAME = 40, /* non-default domain (very optional) */
  HNCP_T_DNS_ROUTER_NAME = 41, /* router name (moderately optional) */
  HNCP_T_MANAGED_PSK = 42,
  HNCP_T_PREFIX_DOMAIN = 43,

  /* draft-pfister-homenet-multicast */
  HNCP_T_PIM_RPA_CANDIDATE = 191,
  HNCP_T_PIM_BORDER_PROXY = 192,
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
  uint32_t ms_valid_at_origination;
  uint32_t ms_preferred_at_origination;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_delegated_prefix_header_s, *hncp_t_delegated_prefix_header;

/* HNCP_T_ASSIGNED_PREFIX */
typedef struct __packed {
  ep_id_t ep_id;
  uint8_t flags;
  uint8_t prefix_length_bits;
  /* Prefix data, padded so that ends at 4 byte boundary (0s). */
  uint8_t prefix_data[];
} hncp_t_assigned_prefix_header_s, *hncp_t_assigned_prefix_header;

#define HNCP_T_ASSIGNED_PREFIX_FLAG_PRIORITY(flags) ((flags) & 0x0f)
#define HNCP_T_ASSIGNED_PREFIX_FLAG(prio) (prio & 0x0f)

/* HNCP_T_DHCP_OPTIONS - just container, no own content */
/* HNCP_T_DHCPV6_OPTIONS - just container, no own content */

/* HNCP_T_ROUTER_ADDRESS */
typedef struct __packed {
  ep_id_t ep_id;
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

/* HNCP_T_PREFIX_DOMAIN */
typedef struct __packed {
  uint8_t type;
  uint8_t id[];
} hncp_t_prefix_domain_s, *hncp_t_prefix_domain;

/* HNCP_T_PIM_RPA_CANDIDATE */
typedef struct __packed {
	struct in6_addr addr;
} hncp_t_pim_rpa_candidate_s, *hncp_t_pim_rpa_candidate;

/* HNCP_T_PIM_BORDER_PROXY */
typedef struct __packed {
	struct in6_addr addr;
	uint16_t port;
} hncp_t_pim_border_proxy_s, *hncp_t_pim_border_proxy;

/**************************************************************** Addressing */

#define HNCP_PORT 8808
#define HNCP_DTLS_SERVER_PORT 8809
#define HNCP_MCAST_GROUP "ff02::8808"

#define HNCP_UCAST_DISCOVER6 "2001:1::8808"
#define HNCP_UCAST_DISCOVER4 "192.0.0.9"
