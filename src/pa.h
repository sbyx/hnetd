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

/* Locally assigned prefix */
struct pa_lap {
	struct avl_node avl_node;   /* Must be first */
	struct prefix prefix;	    /* The assigned prefix */
	char ifname[IFNAMSIZ];		/* lap's interface name */

	/** PRIVATE **/
	time_t assigned; // When assigned for the first time
	bool configured; // Whether that lap is pushed to iface */
};

/* Locally delegated prefix.
 * i.e. a delegated prefix that we own. */
struct pa_ldp {
	struct avl_node avl_node; /* Must be first */

	/* The delegated prefix. */
	struct prefix prefix;

	/* The prefix is valid until that time.
	 * Afterward, it will be discarded (no delay for graceful timeout). */
	time_t valid_until;
	/* The prefix also as a prefered lifetime */
	time_t prefered_until;

	/** PRIVATE **/
	// Nothing for now
};

/* Callbacks for flooding callbacks. */
struct pa_flood_callbacks {
	void *priv;
	void (*updated_laps)(void *priv); /* When laps are updated */
	void (*updated_ldps)(void *priv); /* When ldps are udated */
};

struct pa_iface_callbacks {
	void *priv;
	void (*assign_prefix)(const char *ifname, struct prefix *, void *priv);
	void (*remove_prefix)(const char *ifname, struct prefix *, void *priv);
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
 * Callbacks for iface
 */

/* Subscribes to lap change events.
 * Will be used by iface.c to obtain new laps information. */
void pa_laps_subscribe(struct pa_iface_callbacks *);


/*
 * Owner's interface.
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
 * Flooding algorithm interface
 */

/*
 * Each time it changes, the flooding algorithm must
 * update the eap and edp database. All the entries must
 * be pushed and everything must be done in a single uloop event.
 */

/* Sets flooder algorithm callbacks.
 * A new subscription will override the previous one. */
void pa_flood_subscribe(const struct pa_flood_callbacks *);

/* Before starting update, the flooder has to call this function. */
void pa_update_init();

/* For each prefix assigned by *other* node, call that function.
 * @prefix - The assigned prefix
 * @takes_precedence - Whether we have higher priority on prefix
 *                     assignment.
 * @ifname - Interface name, if assigned on a connected link.
 *           Zero-length string otherwise.
 */
int pa_update_eap(const struct prefix *prefix,
				bool takes_precedence,
				const char *ifname);

/* For each delegated prefix announced by *other* node,
 * call this function. This can only be called during db update.
 * @prefix - The delegated prefix
 * @valid_until - Time when the prefix becomes invalid
 */
int pa_update_edp(const struct prefix *prefix,
				time_t valid_until, time_t prefered_until);

/* At the end of an update, the flooder must call this function. */
void pa_update_commit();

/* For some things (like deciding whether to choose ula prefix),
 * the router needs to be home network leader.
 * This can be called anytime. */
void pa_set_global_leadership(bool leadership);

/* This will return the tree containing assigned prefixes
 * (struct pa_lap) */
struct avl_tree *pa_get_laps();

/* This will return the tree containing delegated prefixes
 * (struct pa_ldp) */
struct avl_tree *pa_get_ldps();

#endif





