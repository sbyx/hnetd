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

#include "hnetd.h"
#include "iface.h"
#include "prefix_utils.h"

/* Length of router ids */
#define PA_RIDLEN 16

struct pa_rid {
	uint8_t id[PA_RIDLEN];
};

#define PA_RID_L		"%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x"
#define PA_RID_LA(rid)  (rid)->id[0], (rid)->id[1], (rid)->id[2], (rid)->id[3], \
		(rid)->id[4], (rid)->id[5], (rid)->id[6], (rid)->id[7], \
		(rid)->id[8], (rid)->id[9], (rid)->id[10], (rid)->id[11], \
		(rid)->id[12], (rid)->id[13], (rid)->id[15], (rid)->id[15]


typedef struct pa *pa_t;

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
				const struct prefix *excluded, const char *dp_ifname,
				hnetd_time_t valid_until, hnetd_time_t preferred_until,
				const void *dhcpv6_data, size_t dhcpv6_len,
				void *priv);
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
};

struct pa_conf {
	/* Delay between flooding announce and interface level
	 * address assignment (in hnetd_time_t unit).
	 * default = 20 * HNETD_TIME_PER_SECOND */
	uint32_t commit_lap_delay;

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

	/* The iface registration functions.
	 * Defaults are iface_register_user and
	 * iface_unregister_user from iface.h. */
	void (*iface_registration)(struct iface_user *user);
	void (*iface_unregistration)(struct iface_user *user);

};


/* Sets conf values to defaults. */
void pa_conf_default(struct pa_conf *);

/* Initializes the prefix assignment algorithm with a default
 * configuration.
 * Returns a pa struct on success and NULL on error. */
pa_t pa_create(const struct pa_conf *);

/* Starts the pa algorithm
 * All registrations with other modules (uloop, iface, ...) are
 * done here. */
int pa_start(pa_t);

/* Stops and destroys the prefix assignment.
 * Init must be called to use it again. */
void pa_destroy(pa_t);

/* Subscribes to lap change events.
 * Will be used by iface.c to obtain new laps information.
 * Subscribing will override previous subscription (if any). */
void pa_iface_subscribe(pa_t, const struct pa_iface_callbacks *);

/* Sets flooder algorithm callbacks.
 * Subscribing will override previous subscription (if any).
 * The provided structure can be destroyed after function returns. */
void pa_flood_subscribe(pa_t, const struct pa_flood_callbacks *);


/* Sets the router id.
 * This must be called after creation. Otherwise,
 * an rid of zero will be used (lowest priority). */
void pa_set_rid(pa_t, const struct pa_rid *rid);

/* Flooding protocol must call that function whenever an assigned
 * prefix advertised by some *other* node is modified or deleted.
 * @param prefix The assigned prefix
 * @param ifname Interface name when assigned on a connected link.
 *           NULL otherwise.
 * @param do_delete Whether this eap must be deleted
 * @param rid The source router id
 * @return 0 on success. A different value on error. */
int pa_update_eap(pa_t, const struct prefix *prefix,
				const struct pa_rid *rid,
				const char *ifname, bool to_delete);

/* Flooding protocol must call that function whenever a delegated
 * prefix advertised by some *other* node is modified or deleted.
 * @param prefix The delegated prefix
 * @param rid Prefix owner's router id
 * @param excluded Prefix to not assign (NULL if not assigned)
 * @param valid_until Time when the prefix becomes invalid (0 for deletion)
 * @param preferred_until - Time when the prefix is not preferred anymore.
 * @param dhcpv6_data Data provided by the delegating dhcpv6 server (NULL if no data)
 * @param dhcpv6_len The length of the dhcpv6 data (0 if not data)
 * @return 0 on success. A different value on error. */
int pa_update_edp(pa_t, const struct prefix *prefix,
				const struct pa_rid *rid,
				const struct prefix *excluded,
				hnetd_time_t valid_until, hnetd_time_t preferred_until,
				const void *dhcpv6_data, size_t dhcpv6_len);

#endif





