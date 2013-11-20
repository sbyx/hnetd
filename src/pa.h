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

#include <libubox/list.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdint.h>
#include <time.h>

/* A prefix for IPv4 and IPv6 addresses.
 * IPv4 addresses are of the form ffff::AABB:CCDD. */
struct pa_prefix {
	struct in6_addr prefix;		/* Address itself */
	uint8_t plen;				/* Prefix length */
};

/* Locally assigned prefix */
struct pa_lap {
	struct list_head le;		/* laps are stored in a list */
	struct pa_prefix prefix;	/* The assigned prefix */
	char ifname[IFNAMSIZ];		/* lap's interface name */
};

/* Locally delegated prefix.
 * i.e. a delegated prefix that we own. */
struct pa_ldp {
	struct list_head le;

	/* The delegated prefix. */
	struct pa_prefix prefix;

	/* Interface toward gateway for that prefix or
	 * zero-length string if no gateway (like ulas) */
	char ifname[IFNAMSIZ];

	/* Gateway address (can be link local) */
	struct in6_addr next_hop;

	/* The prefix is valid until that time.
	 * Afterward, it will be discarded (no delay for graceful timeout). */
	time_t valid_until;

	/* Time when the prefix becomes deprecated.
	 * It should not be announced anymore. But will remain some time. */
	time_t deprecated;
};

/* Callbacks for flooding callbacks. */
struct pa_flood_callbacks {
	void *priv;
	void (*updated_laps)(void *priv); /* When laps are updated */
	void (*updated_ldps)(void *priv); /* When ldps are udated */
};

/* Callbacks for interface and routing configuration. */
struct pa_net_callbacks {
	void *priv;

	/* Must configure network interfaces with some prefix.
	 * Address can then be chosen and RAs sent. */
	void (*assign_prefix)(char *ifname, struct pa_prefix *prefix);
	void (*remove_prefix)(char *ifname, struct pa_prefix *prefix);

	/* Must configure routing protocol to advertise the prefix route.
	 * Must configure routing table for next hop. */
	void (*add_ldp)(struct pa_ldp *ldp);
	void (*remove_ldp)(struct pa_ldp *ldp);
};

struct pa_conf {
	/* Iface list */
	struct list_head ifaces;

	/* When a global/ula delegated prefix is deleted, we wait
	 * some time before removing it from our list. */
	uint32_t remove_glb_delegated_prefix_delay;
	uint32_t remove_ula_delegated_prefix_delay;

	/* Delay between flooding announce and interface level
	 * address assignment. */
	uint32_t commit_glb_prefix_delay;
	uint32_t commit_ula_prefix_delay;

	char use_ula; /* Enables ULA use */
	char no_ula_if_glb_ipv6; /* Disable ULA when there is a global IPv6 */
	char use_ipv4; /* Enables IPv4 10/8 use */
	char no_ipv4_if_glb_ipv6; /* Disable IPv4 when we have IPv6 global address */

	/* Callbacks for flooding protocol */
	struct pa_flood_callbacks flood_cb;

	/* Callbacks for configuration */
	struct pa_net_callbacks conf_cb;
};



/*
 * Configuration manipulation
 */

/* Initializes a conf structure.
 * Values are set to default. */
void pa_conf_init(struct pa_conf *);

/* Add an interface to configuration. */
int pa_conf_add_iface(struct pa_conf *, const char *ifname);

/* Uninitializes a conf structure.
 * Values are undefined, and init can be used again. */
void pa_conf_term(struct pa_conf *);



/*
 * Owner's interface.
 */

/* Initializes the prefix assignment algorithm. */
int pa_init(const struct pa_conf *);


/* Modifies the conf. */
void pa_update_conf(const struct pa_conf *);

/* Stops the prefix assignement. */
void pa_term();



/*
 * Upper layer interface (dhcp & co)
 */

/* Updates or add a locally delegated prefix.
 * prefix      - The delegated prefix.
 * valid_until - When the delegated prefix will timeout.
 * deprecated  - Zero if not deprecated. The time it became
 *               deprecated otherwise. */
int pa_update_ldp(const struct pa_prefix *prefix,
			time_t valid_until,
			time_t deprecated);



/*
 * Flooding algorithm interface
 */

/*
 * Each time it changes, the flooding algorithm must
 * update the eap and edp database. All the entries must
 * be pushed and everything must be done in a single uloop event.
 */

/* Before starting update, the flooder has to call this function. */
void pa_update_init();

/* For each prefix assigned by *other* node, call that function.
 * @prefix - The assigned prefix
 * @takes_precedence - Whether we have higher priority on prefix
 *                     assignment.
 * @ifname - Interface name, if assigned on a connected link.
 *           Zero-length string otherwise.
 */
int pa_update_eap(const struct pa_prefix *prefix,
				bool takes_precedence,
				const char ifname);

/* For each delegated prefix announced by *other* node,
 * call this function. This can only be called during db update.
 * @prefix - The delegated prefix
 * @valid_until - Time when the prefix becomes invalid
 */
int pa_update_edp(const struct pa_prefix *prefix,
				time_t valid_until);

/* At the end of an update, the flooder must call this function. */
void pa_update_commit();

/* For some things (like deciding whether to choose ula prefix),
 * the router needs to be home network leader.
 * This can be called anytime. */
void pa_set_global_leadership(bool leadership);

/* This will return a list of locally assigned prefixes (struct pa_lap) */
struct list_head *pa_get_laps();

/* This will return a list of all locally delegated prefixes
 * (struct pa_ldp) */
struct list_head *pa_get_ldps();

#endif





