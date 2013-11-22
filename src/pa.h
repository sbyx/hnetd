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
	 * @valid_until - validity date
	 * @prefered_until - prefered date
	 * @priv - The private pointer
	 */
	void (*update_prefix)(const struct prefix *p, const char *ifname,
						time_t valid_until,	time_t prefered_until, void *priv);
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

/* Initializes a conf structure.
 * Values are set to default. */
void pa_conf_init(struct pa_conf *);

/* Uninitializes a conf structure.
 * Values are undefined, and init can be used again. */
void pa_conf_term(struct pa_conf *);


/*
 * pa control functions
 */

/* Initializes the prefix assignment algorithm with a default
 * configuration.
 * returns 0 on success, a negative value on error. */
int pa_init(const struct pa_conf *);

/* Starts the pa algorithm
 * All registrations with other modules (uloop, iface, ...) are
 * done here. */
int pa_start();

/* Modifies the conf. */
int pa_set_conf(const struct pa_conf *);

/* Stops and uninit the prefix assignement.
 * Init must be called to use it again. */
void pa_term();



/*
 * For iface interface
 */

/* Subscribes to lap change events.
 * Will be used by iface.c to obtain new laps information.
 * Subscribing will override previous subscription (if any). */
void pa_iface_subscribe(const struct pa_iface_callbacks *);



/*
 * Flooding algorithm interface
 */


/* Sets flooder algorithm callbacks.
 * Subscribing will override previous subscription (if any). */
void pa_flood_subscribe(const struct pa_flood_callbacks *);


/* For each prefix assigned by *other* node, call that function.
 * @prefix - The assigned prefix
 * @takes_precedence - Whether we have higher priority on prefix
 *                     assignment.
 * @ifname - Interface name, if assigned on a connected link.
 *           Zero-length string otherwise.
 */
int pa_update_eap(const struct prefix *prefix, const char *ifname,
				bool takes_precedence, int do_delete);

/* For each delegated prefix announced by *other* node,
 * call this function. This can only be called during db update.
 * @prefix - The delegated prefix
 * @valid_until - Time when the prefix becomes invalid (0 for deletion)
 * @prefered_until - Time when the prefix is not prefered.
 */
int pa_update_edp(const struct prefix *prefix,
				time_t valid_until, time_t prefered_until);

/* For some things (like deciding whether to choose ula prefix),
 * the router needs to be home network leader.
 * This can be called anytime. */
void pa_set_global_leadership(bool leadership);

#endif





