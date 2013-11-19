#pragma once
#include "hnetd.h"

#include <stdbool.h>
#include <netinet/in.h>

#include <libubox/vlist.h>
#include <libubox/list.h>

struct iface_addr {
	struct vlist_node node;
	struct iface *iface;

	time_t valid_until;
	time_t preferred_until;

	bool v6;
	uint8_t prefix;
	union iface_ia {
		struct in_addr inet;
		struct in6_addr inet6;
	} addr;
};

struct iface {
	struct list_head head;

	char *name;
	int ifindex;
	char *ifname;
	char *domain;

	bool internal;
	bool managed;

	struct vlist_tree addrs;
	struct vlist_tree prefixes;
};

struct list_head interfaces;

// API to be called from ELSA logic to manipulate interface config

// Get / set / delete managed interface
struct iface* iface_get(const char *name);
struct iface* iface_create(const char *name, const char *ifname, bool managed);
void iface_delete(const char *name);

// Add address to interface
void iface_set_addr(struct iface *iface, bool v6, const union iface_ia *addr,
		uint8_t prefix, time_t valid_until, time_t preferred_until);

// Add prefix to interface
void iface_set_prefix(struct iface *iface, bool v6, const union iface_ia *addr,
		uint8_t prefix, time_t valid_until, time_t preferred_until);

// Change domain of interface
void iface_set_domain(struct iface *iface, const char *domain);

// Change internal state of interface
void iface_set_internal(struct iface *iface, bool external);

// Commit all changes to this interface to apply it on platform
void iface_commit(struct iface *iface);
