/*
 * Author: Pierre Pfister
 *
 * Prefix assignment algorithm.
 *
 * This file provides a protocol independent interface
 * for prefix allocation and assignment in home networks.
 *
 */

#ifndef PA_H
#define PA_H

#include <libubox/avl.h>
#include <libubox/uloop.h>
#include <net/if.h>
#include <stdint.h>
#include <time.h>

#include "prefix_utils.h"

typedef void *pa_t;

/* Callbacks for flooding protocol. */
struct pa_flood_callbacks {
	void *priv;
	/* Called whenever a locally assigned prefix is modified
	 * @p - the assigned prefix
	 * @ifname - interface on which assignment is made
	 * @to_delete - non-zero when the lap must not be advertised anymore
	 * @priv - The private pointer */
	void (*updated_lap)(const struct prefix *p, const char *ifname,
							int to_delete, void *priv);
	/* Called whenever a locally delegated prefix is modified
	 * @p - the delegated prefix
	 * @valid_until - End of validity date and 0 to ask for deletion
	 * @prefered_until - Preferred date
	 * @priv - The private pointer */
	void (*updated_ldp)(const struct prefix *p, time_t valid_until,
							time_t prefered_until, void *priv);
};

struct pa_iface_callbacks {
	void *priv;
	/* Called whenever an prefix assigned to some interface should be
	 * modified.
	 * @p - the assigned prefix
	 * @ifname - the interface on which that prefix is or should be
	 * @owner - whether the iface should do dhcp+ras on the link
	 * @valid_until - validity date
	 * @prefered_until - prefered date
	 * @priv - The private pointer
	 */
	void (*update_prefix)(const struct prefix *p, const char *ifname,
						time_t valid_until,	time_t prefered_until, void *priv);

	/* When interface ownership changes.
	 * @ifname - The interface name
	 * @owner - Whether we are link owner
	 * @priv - The private pointer */
	void (*update_link_owner)(const char *ifname, bool owner, void *priv);
};

struct pa_conf {
	/* Delay between flooding announce and interface level
	 * address assignment. */
	uint32_t commit_lap_delay;
	uint32_t delete_lap_delay;

	/* Enables ULA use
	 * default = 1 */
	char use_ula;

	/* Disable ULA when an ipv6 prefix is available
	 * default = 1 */
	char no_ula_if_glb_ipv6;

	/* Selects a ula randomly according to rfc4193
	 * default = 1 */
	char use_random_ula;

	/* If not random, use that ULA prefix (must be ULA)
	 * default = undef */
	struct prefix ula_prefix;

	/* Enable IPv4 use
	 * default = 1 */
	char use_ipv4;

	/* Disable IPv4 when there is global ipv6 available
	 * default = 0 */
	char no_ipv4_if_glb_ipv6;

	/* When needed, use that v4 prefix
	 * default = ::ffff:10.0.0.0/104 */
	struct prefix v4_prefix;

};



/*
 * Configuration manipulation
 */

/* Sets conf values to defaults. */
void pa_conf_default(struct pa_conf *);


/*
 * pa control functions
 */

/* Initializes the prefix assignment algorithm with a default
 * configuration.
 * Returns a pa struct on success and NULL on error. */
pa_t pa_create(const struct pa_conf *);

/* Starts the pa algorithm
 * All registrations with other modules (uloop, iface, ...) are
 * done here. */
int pa_start(pa_t);

/* Modifies the conf. */
int pa_set_conf(pa_t, const struct pa_conf *);

/* Stops and destroys the prefix assignment.
 * Init must be called to use it again. */
void pa_destroy(pa_t);



/*
 * For iface interface
 */

/* Subscribes to lap change events.
 * Will be used by iface.c to obtain new laps information.
 * Subscribing will override previous subscription (if any). */
void pa_iface_subscribe(pa_t, const struct pa_iface_callbacks *);



/*
 * Flooding algorithm interface
 */


/* Sets flooder algorithm callbacks.
 * Subscribing will override previous subscription (if any). */
void pa_flood_subscribe(pa_t, const struct pa_flood_callbacks *);


/* For each prefix assigned by *other* node, call that function.
 * @prefix - The assigned prefix
 * @ifname - Interface name, if assigned on a connected link.
 *           Zero-length string otherwise.
 * @do_delete - Whether this eap must be deleted
 */
int pa_update_eap(pa_t, const struct prefix *prefix, const char *ifname,
					int do_delete);

/* When link ownership changes (or doesn't change, it is checked)
 * @ifname - The interface name
 * @owner - Whether we are owner
 */
int pa_update_link_owner(pa_t, const char *ifname, bool owner);

/* For each delegated prefix announced by *other* node,
 * call this function. This can only be called during db update.
 * @prefix - The delegated prefix
 * @valid_until - Time when the prefix becomes invalid (0 for deletion)
 * @prefered_until - Time when the prefix is not prefered.
 */
int pa_update_edp(pa_t, const struct prefix *prefix,
				time_t valid_until, time_t prefered_until);

/* For some things (like deciding whether to choose ula prefix),
 * the router needs to be home network leader.
 * This can be called anytime. */
void pa_set_global_leadership(pa_t, bool leadership);

#endif





