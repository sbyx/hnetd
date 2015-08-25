/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 * This section implements Prefix Assignment related features from HNCP.
 *
 * - Prefix Assignment
 * - Address Assignment
 * - ULA and IPv4 prefix handling
 * - Prefix Delegation
 *
 */

#ifndef HNCP_PA_H_
#define HNCP_PA_H_

#include "hncp.h"
#include "hncp_link.h"
#include "prefix_utils.h"

typedef struct hncp_pa_struct hncp_pa_s, *hncp_pa;

hncp_pa hncp_pa_create(hncp hncp, struct hncp_link *hncp_link);
void hncp_pa_destroy(hncp_pa hpa);

/* Some way to list current available delegated prefixes. */

struct hncp_pa_dp {
	struct list_head le;
	struct prefix prefix;
	bool enabled; //dp should be ignored if not set
	bool local; //Whether it was generated locally or obtained through HNCP
};

#define hncp_pa_for_each_dp(dp, hncp_pa) \
	list_for_each_entry(dp, __hpa_get_dps(hncp_pa), le) \
		if((dp)->enabled)

/********************************
 *     Internal Interfaces      *
 ********************************/

struct hncp_pa_iface_user {
	/* Called whenever a prefix/address is modified. */
	void (*update_address)(struct hncp_pa_iface_user *i, const char *ifname,
			const struct in6_addr *addr, uint8_t plen,
			hnetd_time_t valid_until, hnetd_time_t preferred_until,
			uint8_t *dhcp_data, size_t dhcp_len,
			bool del);

	/* A delegated prefix was added or removed */
	void (*update_dp)(struct hncp_pa_iface_user *,
			const struct hncp_pa_dp *dp, bool del);
};

/**
 * Subscription for iface.c so it gets prefix and addresses callbacks.
 */
void hncp_pa_iface_user_register(hncp_pa hp, struct hncp_pa_iface_user *user);

/********************************
 *       Configuration          *
 ********************************/

/*
 * Prefix assignment behavior can be modified using these functions.
 */

/*  Starts an update, waiting for new prefixes and addresses. */
void hncp_pa_conf_iface_update(hncp_pa hp, const char *ifname);

/* Add a static prefix configuration. */
int hncp_pa_conf_prefix(hncp_pa hp, const char *ifname,
		const struct prefix *p, bool del);

/*  Add a static address configuration by the mean of the last bits of an
 * address. */
int hncp_pa_conf_address(hncp_pa hp, const char *ifname,
		const struct in6_addr *addr, uint8_t mask,
		const struct prefix *filter, bool del);

/* Sets a link ID with its mask length.
 * mask = 0 will remove the link id. */
int hncp_pa_conf_set_link_id(hncp_pa hp, const char *ifname, uint32_t id,
		uint8_t mask);

int hncp_pa_conf_set_ip4_plen(hncp_pa hp, const char *ifname,
		uint8_t ip4_plen);

int hncp_pa_conf_set_ip6_plen(hncp_pa hp, const char *ifname,
		uint8_t ip6_plen);

/* Removes all configuration which was not added or refreshed
 * since last update. */
void hncp_pa_conf_iface_flush(hncp_pa hp, const char *ifname);



/*
 * ULA and IPv4 prefix generation behavior may be modified with the following API.
 */

struct hncp_pa_ula_conf
{
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

	/* Do not generate IPv4 prefix unless we have an uplink
	 * connectivity.
	 * default = 1
	 */
	char no_ipv4_if_no_uplink;

	/* When needed, use that v4 prefix
	 * default = ::ffff:10.0.0.0/104 */
	struct prefix v4_prefix;

	/* Valid lifetime for local prefixes (ula + ipv4)
	 * default = 600 * HNETD_TIME_PER_SECOND */
	hnetd_time_t local_valid_lifetime;

	/* Preferred lifetime for local prefixes
	 * default = 300 * HNETD_TIME_PER_SECOND */
	hnetd_time_t local_preferred_lifetime;

	/* A local prefix lifetime is update when
	 * prefix.valid - local_update_delay <= now
	 * This should be more than valid_lifetime - preferred_lifetime.
	 * default = 330 * HNETD_TIME_PER_SECOND */
	hnetd_time_t local_update_delay;
};

void hncp_pa_ula_conf_default(struct hncp_pa_ula_conf *);
int hncp_pa_ula_conf_set(hncp_pa hncp_pa, const struct hncp_pa_ula_conf *);



/*
 * Stable storage file may be set and updated
 */

int hncp_pa_storage_set(hncp_pa hncp_pa, const char *path);


/********************************
 * Downstream Prefix Delegation *
 ********************************/

#define DHCP_DUID_MAX_LENGTH 20
typedef struct hpa_lease_struct *hpa_lease, hpa_lease_s;
typedef void (*hpa_pd_cb)(const struct in6_addr *prefix, uint8_t plen,
		hnetd_time_t valid_until, hnetd_time_t preferred_util,
		const char *dhcp_data, size_t dhcp_len,
		void *priv);

hpa_lease hpa_pd_add_lease(hncp_pa hp, const char *duid, uint8_t hint_len,
		hpa_pd_cb, void *priv);
void hpa_pd_del_lease(hncp_pa hp, hpa_lease l);

/********************************
 *            Private           *
 ********************************/

struct list_head *__hpa_get_dps(hncp_pa hpa);

#endif /* HNCP_PA_H_ */
