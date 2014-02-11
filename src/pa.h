/*
 * pa_data.h
 *
 * Author: Pierre Pfister
 *
 * Interfacing functions between Prefix Assignment Algorithm
 * and other elements (hcp or iface).
 *
 */


#ifndef PA_H_
#define PA_H_

#include <libubox/uloop.h>
#include <stdint.h>

#include "pa_core.h"
#include "pa_data.h"
#include "pa_local.h"
#include "pa_store.h"

#include "hnetd.h"

typedef struct pa *pa_t;
#include "iface.h"

/* Callbacks for flooding protocol. */
struct pa_flood_callbacks {
	/* Private pointer provided by the subscriber */
	void *priv;
	/* Called whenever a locally assigned prefix is modified.
	 * @param prefix The assigned prefix
	 * @param ifname Interface on which assignment is made
	 * @param to_delete Whether that lap needs to be deleted
	 * @param priv Private pointer as provided by subscriber */
	void (*updated_lap)(const struct prefix *prefix, const char *ifname,
							bool authoritative, uint8_t priority,
							int to_delete, void *priv);

	/* Called whenever a locally delegated prefix is modified.
	 * @param prefix The assigned prefix
	 * @param prefix Some subprefix that must not be assigned
	 * @param dp_ifname Delegating side interface (NULL if not delegated)
	 * @param valid_until End of validity date or zero when the ldp should
	 *        be deleted
	 * @param preferred_until When the prefix will not be preferred anymore
	 * @param dhcpv6_data Data provided by the delegating dhcpv6 server (NULL if no data)
	 * @param dhcpv6_len The length of the dhcpv6 data (0 if not data)
	 * @param priv Private pointer as provided by subscriber */
	void (*updated_ldp)(const struct prefix *prefix,
				hnetd_time_t valid_until, hnetd_time_t preferred_until,
				const void *dhcpv6_data, size_t dhcpv6_len,
				void *priv);

	/* Called whenever a locally assigned address is modified.
	 * @param prefix The assigned prefix
	 * @param ifname Interface on which assignment is made
	 * @param to_delete Whether that aap needs to be deleted
	 * @param priv Private pointer as provided by subscriber */
	void (*updated_laa)(const struct in6_addr *addr, const char *ifname,
			int to_delete, void *priv);
};

struct pa_iface_callbacks {
	/* Private pointer provided by the subscriber */
	void *priv;
	/* Called whenever a prefix assigned to some interface should be
	 * modified.
	 * @param prefix The assigned prefix
	 * @param ifname The interface on which that prefix must be assigned
	 * @param valid_until End of validity date or zero when the prefix should
	 *        be deleted
	 * @param preferred_until When the prefix will not be preferred anymore
	 * @param dhcpv6_data Data provided by the delegating dhcpv6 server (NULL if no data)
	 * @param dhcpv6_len The length of the dhcpv6 data (0 if not data)
	 * @param priv Private pointer as provided by subscriber */
	void (*update_prefix)(const struct prefix *p, const char *ifname,
						hnetd_time_t valid_until, hnetd_time_t preferred_until,
						const void *dhcpv6_data, size_t dhcpv6_len,
						void *priv);

	/* When interface ownership changes.
	 * @param ifname The interface name
	 * @param owner Whether we should do dhcp+ra
	 * @param priv Private pointer as provided by subscriber */
	void (*update_link_owner)(const char *ifname, bool owner, void *priv);

	/* Called whenever an assigned address must be applied or unapplied. */
	void (*update_address)(const char *ifname, const struct in6_addr *addr,
			int to_delete, void *priv);
};

struct pa_conf {
	/* Enables ULA use
	 * default = 1 */
	char use_ula;

	/* Disable ULA when an ipv6 prefix is available
	 * default = 1 */
	char no_ula_if_glb_ipv6;

	/* Generates a random ula, and store it in stable storage.
	 * default = 1 */
	char use_random_ula;

	/* Sets the prefix length of randomly generated ula prefixes.
	 * default = 48 */
	char random_ula_plen;

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

	/* Valid lifetime for local prefixes (ula + ipv4)
	 * default = 600 * HNETD_TIME_PER_SECOND */
	uint32_t local_valid_lifetime;

	/* Preferred lifetime for local prefixes
	 * default = 300 * HNETD_TIME_PER_SECOND */
	uint32_t local_preferred_lifetime;

	/* A local prefix lifetime is update when
	 * prefix.valid - local_update_delay <= now
	 * This should be more than valid_lifetime - preferred_lifetime.
	 * default = 330 * HNETD_TIME_PER_SECOND */
	uint32_t local_update_delay;

	/* Pointer to an initialized pa permanent storage structure.
	 * May be left to NULL so that no permanent storage is used.
	 * Default is NULL */
	struct pa_store *storage;
};

struct pa_flood {
	struct pa_rid rid;
	hnetd_time_t flooding_delay;
	hnetd_time_t flooding_delay_ll;
};

struct pa {
	struct pa_core core;                  /* Algorithm core elements */
	struct pa_flood flood;                /* Main information from flooding */
	struct pa_data data;                  /* PAA database */
	struct pa_conf conf;                  /* Configuration */
	struct pa_local local;                /* Ipv4 and ULA elements */
	struct pa_flood_callbacks flood_cbs;  /* HCP callbacks */
	struct pa_iface_callbacks iface_cbs;  /* Iface callbacks */
	struct iface_user ifu;
};


/************************************/
/********** Main interface **********/
/************************************/

void pa_conf_set_defaults(struct pa_conf *conf);
/* Initializes the pa structure. */
void pa_init(struct pa *pa, const struct pa_conf *conf);
/* Start the pa algorithm. */
void pa_start(struct pa *pa);
/* Pause the pa alforithm (Possibly wrong state). */
void pa_stop(struct pa *pa);
/* Reset pa to post-init state, without modifying configuration. */
void pa_term(struct pa *pa);


/************************************/
/********* Iface interface **********/
/************************************/

/* Subscribes to lap change events. */
void pa_iface_subscribe(struct pa *pa, const struct pa_iface_callbacks *);


/************************************/
/********* Flood interface **********/
/************************************/

/* Sets flooder algorithm callbacks.
 * Subscribing will override previous subscription (if any).
 * The provided structure can be destroyed after function returns. */
void pa_flood_subscribe(pa_t, const struct pa_flood_callbacks *);

/* Sets the router id. */
void pa_set_rid(struct pa *pa, const struct pa_rid *rid);

/* Flooding protocol must call that function whenever an assigned
 * prefix advertised by some *other* node is modified or deleted.
 * @param prefix The assigned prefix
 * @param ifname Interface name when assigned on a connected link.
 *           NULL otherwise.
 * @param do_delete Whether this eap must be deleted
 * @param rid The source router id
 * @return 0 on success. A different value on error. */
int pa_update_ap(struct pa *pa, const struct prefix *prefix,
				const struct pa_rid *rid,
				const char *ifname, bool authoritative, uint8_t priority,
				bool to_delete);

/* Flooding protocol must call that function whenever a delegated
 * prefix advertised by some *other* node is modified or deleted.
 * @param prefix The delegated prefix
 * @param rid Prefix owner's router id
 * @param valid_until Time when the prefix becomes invalid (0 for deletion)
 * @param preferred_until - Time when the prefix is not preferred anymore.
 * @param dhcpv6_data Data provided by the delegating dhcpv6 server (NULL if no data)
 * @param dhcpv6_len The length of the dhcpv6 data (0 if not data)
 * @return 0 on success. A different value on error. */
int pa_update_edp(struct pa *pa, const struct prefix *prefix,
				const struct pa_rid *rid,
				hnetd_time_t valid_until, hnetd_time_t preferred_until,
				const void *dhcpv6_data, size_t dhcpv6_len);

/* Flooding protocol must call that function whenever an address assigned by
 * another router is modified. */
int pa_update_eaa(struct pa *pa, const struct in6_addr *addr,
				const struct pa_rid *rid, bool to_delete);


/************************************/
/******** pa_core interface *********/
/************************************/

/* When a local element is modifed */
void pa_updated_cp(struct pa_core *core, struct pa_cp *cp, bool to_delete, bool tell_flood, bool tell_iface);
void pa_updated_laa(struct pa_core *core, struct pa_laa *laa, bool to_delete);

/* When an iface is modified */
void pa_updated_dodhcp(struct pa_core *core, struct pa_iface *iface);

/************************************/
/******* pa_local interface *********/
/************************************/

void pa_update_local(struct pa_core *core,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len);

/************************************/
/******* pa_data interface **********/
/************************************/

void pa_cp_apply(struct pa_data *data, struct pa_cp *cp);
void pa_laa_apply(struct pa_data *data, struct pa_laa *laa);

#endif /* PA_H_ */
