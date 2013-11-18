#pragma once
#include "hnetd.h"

#include <stdbool.h>
#include <netinet/in.h>

#include <libubox/vlist.h>
#include <libubox/list.h>

struct iface_ia {
	union {
		struct in_addr inet;
		struct in6_addr inet6;
	} addr;
	uint8_t prefix;
};

struct iface_route {
	struct vlist_node node;
	struct iface *iface;
	time_t valid_until;

	bool v6;
	uint32_t metric;
	struct iface_ia target;
	struct iface_ia nexthop;
	struct iface_ia source;
};

struct iface_addr {
	struct vlist_node node;
	struct iface *iface;

	time_t valid_until;
	time_t preferred_until;

	bool v6;
	struct iface_ia addr;
};

struct iface {
	struct list_head head;

	char *name;
	int ifindex;
	char *ifname;
	char *domain;

	bool internal;

	struct vlist_tree routes;
	struct vlist_tree addrs;

	void *platform_data;
};

struct list_head interfaces;

// API to be called from ELSA logic to manipulate interface config

// Get / set / delete managed interface
struct iface* iface_get(const char *name);
struct iface* iface_create(const char *name, const char *ifname);
void iface_delete(struct iface *iface);

// Add route to interface
void iface_set_route(struct iface *iface, bool v6, const struct iface_ia *target,
		const struct iface_ia *nexthop, const struct iface_ia *source,
		uint32_t metric, time_t valid_until);

// Add address to interface
void iface_set_addr(struct iface *iface, bool v6, const struct iface_ia *addr,
		time_t valid_until, time_t preferred_until);

// Change domain of interface
void iface_set_domain(struct iface *iface, const char *domain);

// Change internal state of interface
void iface_set_internal(struct iface *iface, bool external);

// Commit all changes to this interface to apply it on platform
void iface_commit(struct iface *iface);
