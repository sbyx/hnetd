/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#ifndef _IFACE_H
#define _IFACE_H

#include "hnetd.h"
#include "dncp.h"
#include "dncp_i.h"
#include "hncp_sd.h"
#include "hncp_link.h"
#include "hncp_pa.h"
#include "prefix_utils.h"

#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubox/vlist.h>
#include <netinet/in.h>
#include <time.h>


// API for PA / HNCP & friends

struct iface_user {
	// We will just add this struct to our linked-list so please keep it around by yourself ;)
	struct list_head head;

	/* Callback for internal interfaces */
	void (*cb_intiface)(struct iface_user *u, const char *ifname, bool enabled);

	/* Callback for external interfaces */
	void (*cb_extiface)(struct iface_user *u, const char *ifname, bool enabled);

	/* Callback for external interfaces */
	void (*cb_extdata)(struct iface_user *u, const char *ifname,
			const void *dhcpv6_data, size_t dhcpv6_len);

	/* Callback for delegated prefixes (a negative validity time indicates removal) */
	void (*cb_prefix)(struct iface_user *u, const char *ifname,
			const struct prefix *prefix, const struct prefix *excluded,
			hnetd_time_t valid_until, hnetd_time_t preferred_until,
			const void *dhcpv6_data, size_t dhcpv6_len);

	/* Callback for IPv4 connectivity state */
	void (*cb_ext4data)(struct iface_user *u, const char *ifname,
			const void *dhcp_data, size_t dhcp_len);

	/* Callback for internal addresses */
	void (*cb_intaddr)(struct iface_user *u, const char *ifname,
			const struct prefix *addr6, const struct prefix *addr4);
};

// Register user for interface events (callbacks with NULL-values are ignored)
void iface_register_user(struct iface_user *user);

// Unregister user for interface events, do NOT call this from the callback itself!
void iface_unregister_user(struct iface_user *user);

// Update DHCPv6 out data
void iface_set_dhcp_send(const char *ifname, const void *dhcpv6_data, size_t dhcpv6_len, const void *dhcp_data, size_t dhcp_len);
void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len, const void *dhcp_data, size_t dhcp_len);

// Test if iface has IPv4 address
bool iface_has_ipv4_address(const char *ifname);

// Get preferred interface address
int iface_get_preferred_address(struct in6_addr *addr, bool v4, const char *ifname);


// Internal API to platform

struct iface_addr {
	struct vlist_node node;
	hnetd_time_t valid_until;
	hnetd_time_t preferred_until;
	struct prefix excluded;
	struct prefix prefix;
	struct iface *iface;
	struct uloop_timeout timer;
	size_t dhcpv6_len;
	uint8_t dhcpv6_data[];
};

typedef int iface_flags;

#define IFACE_FLAG_INTERNAL		 0x01
#define IFACE_FLAG_LEAF          (0x02 | IFACE_FLAG_INTERNAL)
#define IFACE_FLAG_ADHOC         (0x04 | IFACE_FLAG_INTERNAL)
#define IFACE_FLAG_DISABLE_PA    0x08
#define IFACE_FLAG_ULA_DEFAULT	 0x10
#define IFACE_FLAG_GUEST         (0x20 | IFACE_FLAG_LEAF)
#define IFACE_FLAG_HYBRID		 (0x40 | IFACE_FLAG_INTERNAL)
#define IFACE_FLAG_EXTERNAL		 0x80
#define IFACE_FLAG_NODHCP		 0x100

struct iface {
	struct list_head head;

	// Platform specific handle
	void *platform;

	// Interface status
	bool unused;
	bool internal;
	bool carrier;
	bool designatedv4;
	bool had_ipv4_uplink;
	bool had_ipv6_uplink;

	// Flags
	enum hncp_link_elected elected;
	iface_flags flags;

	// LL-address
	struct in6_addr eui64_addr;
	struct in_addr v4_saddr;
	int v4_prefix;

	// Config
	uint8_t ip6_plen; //Fixed IPv6 assignment prefix length or 0
	uint8_t ip4_plen; //Fixed IPv4 assignment prefix length or 0

	// Prefix storage
	struct vlist_tree assigned;
	struct vlist_tree delegated;
	struct list_head chosen;
	struct list_head addrconf;
	struct pa_link_id_rule *id;

	// Other data
	void *dhcpv6_data_stage;
	void *dhcpv6_data_in;
	void *dhcpv6_data_out;
	size_t dhcpv6_len_stage;
	size_t dhcpv6_len_in;
	size_t dhcpv6_len_out;

	// DHCP data
	void *dhcp_data_stage;
	void *dhcp_data_in;
	void *dhcp_data_out;
	size_t dhcp_len_stage;
	size_t dhcp_len_in;
	size_t dhcp_len_out;

	// Internal transition timeout
	struct uloop_timeout transition;
	struct uloop_timeout preferred;

	// Interface name
	char ifname[];
};

// Generic initializer to be called by main()
int iface_init(hncp hncp, hncp_sd sd, hncp_pa pa,
		struct hncp_link *link, const char *pd_socket);

// Get an interface by name
struct iface* iface_get(const char *ifname);

// Create / get an interface (external or internal), handle set = managed
struct iface* iface_create(const char *ifname, const char *handle, iface_flags flags);

// Remove a known interface
void iface_remove(struct iface *iface);

// Interface iterator
struct iface* iface_next(struct iface *prev);


// Begin uplink update cycle
void iface_update_ipv6_uplink(struct iface *c);
void iface_update_ipv4_uplink(struct iface *c);

// Add currently available prefixes from PD
void iface_add_delegated(struct iface *c,
		const struct prefix *p, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len);

// Flush and commit uplink to synthesize events to users and rerun border discovery
void iface_commit_ipv6_uplink(struct iface *c);
void iface_commit_ipv4_uplink(struct iface *c);


// Set DHCPv4 uplink
void iface_set_ipv4_uplink(struct iface *c, const struct in_addr *saddr, int prefix);


// Set DHCPv4 leased flag and rerun border discovery
void iface_add_dhcp_received(struct iface *c, const void *data, size_t len);


// Set DHCPv6 data received
void iface_add_dhcpv6_received(struct iface *c, const void *data, size_t len);


// Add prefix
void iface_add_chosen_prefix(struct iface *c, const struct prefix *p);


// Set link ID
void iface_set_link_id(struct iface *c, uint32_t linkid, uint8_t mask);


// Add hnet address
void iface_add_addrconf(struct iface *c, struct in6_addr *addr,
		uint8_t mask, struct prefix *filter);

// Get fqdn address
char* iface_get_fqdn(const char *ifname, char *buf, size_t len);


// Flush uplinks
void iface_update(void);
void iface_commit(void);


// Flush all interfaces
void iface_flush(void);


#ifdef __linux__
void iface_set_unreachable_route(const struct prefix *p, bool enable);
#endif

#endif
