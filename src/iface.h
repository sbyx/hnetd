#ifndef _IFACE_H
#define _IFACE_H

#include "hnetd.h"
#include "prefix_utils.h"

#include <libubox/list.h>
#include <libubox/vlist.h>
#include <netinet/in.h>
#include <time.h>


// API for PA / HCP & friends

struct iface_user {
	// We will just add this struct to our linked-list so please keep it around by yourself ;)
	struct list_head head;

	/* Callback for internal interfaces */
	void (*cb_intiface)(struct iface_user *u, const char *ifname, bool internal);

	/* Callback for delegated prefixes (a negative validity time indicates removal) */
	void (*cb_prefix)(struct iface_user *u, const struct prefix *prefix,
			time_t valid_until, time_t preferred_until);
};

// Register user for interface events (callbacks with NULL-values are ignored)
void iface_register_user(struct iface_user *user);

// Unregister user for interface events, do NOT call this from the callback itself!
void iface_unregister_user(struct iface_user *user);



// Internal API to platform

struct iface_addr {
	struct vlist_node node;
	time_t valid_until;
	time_t preferred_until;
	struct prefix prefix;
};

struct iface {
	struct list_head head;

	// Platform specific handle
	void *platform;

	// Interface status
	bool linkowner;
	bool unmanaged;
	bool internal;
	bool v4leased;

	// Prefix storage
	struct vlist_tree assigned;
	struct vlist_tree delegated;

	// Other data
	char *domain;

	// Interface name
	char ifname[];
};


int iface_init(void);
struct iface* iface_get(const char *ifname, const char *handle);
void iface_remove(const char *ifname);

#endif
