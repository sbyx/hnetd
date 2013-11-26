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
	void (*cb_intiface)(struct iface_user *u, const char *ifname, bool enabled);

	/* Callback for delegated prefixes (a negative validity time indicates removal) */
	void (*cb_prefix)(struct iface_user *u, const struct prefix *prefix,
			hnetd_time_t valid_until, hnetd_time_t preferred_until);
};

// Register user for interface events (callbacks with NULL-values are ignored)
void iface_register_user(struct iface_user *user);

// Unregister user for interface events, do NOT call this from the callback itself!
void iface_unregister_user(struct iface_user *user);



// Internal API to platform

struct iface_addr {
	struct vlist_node node;
	hnetd_time_t valid_until;
	hnetd_time_t preferred_until;
	struct prefix prefix;
};

struct iface {
	struct list_head head;

	// Platform specific handle
	void *platform;

	// Interface status
	bool linkowner;
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


// Generic initializer to be called by main()
int iface_init(void);

// Get an interface by name
struct iface* iface_get(const char *ifname);

// Create / get an interface (external or internal), handle set = managed
struct iface* iface_create(const char *ifname, const char *handle);

// Remove a known interface
void iface_remove(const char *ifname);


// Begin PD update cycle
void iface_update_delegated(struct iface *c);

// Add currently available prefixes from PD
void iface_add_delegated(struct iface *c, const struct prefix *p,
		hnetd_time_t valid_until, hnetd_time_t preferred_until);

// Flush and commit PD to synthesize events to users and rerun border discovery
void iface_commit_delegated(struct iface *c);


// Set DHCPv4 leased flag and rerun border discovery
void iface_set_v4leased(struct iface *c, bool v4leased);


#endif
