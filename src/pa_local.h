/*
 * pa_data.h
 *
 * Author: Pierre Pfister
 *
 * ULA and IPv4 prefix generation for
 * prefix algorithm.
 *
 */

#ifndef PA_LOCAL_H_
#define PA_LOCAL_H_

#include <stdbool.h>
#include <libubox/uloop.h>

#include "prefix_utils.h"
#include "hnetd.h"
#include "pa_data.h"

struct pa_local;

struct pa_local_elem {
	hnetd_time_t create_start;
	hnetd_time_t timeout;
	struct pa_ldp *ldp;

	uint8_t (*get_status)(struct pa_local *, struct pa_local_elem *);
	void (*create)(struct pa_local *, struct pa_local_elem *);
	hnetd_time_t (*update)(struct pa_local *, struct pa_local_elem *elem, hnetd_time_t now);
};

struct pa_local_conf
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
};

struct pa_local {
	struct pa_local_conf conf;

	struct pa_local_elem ula;
	struct pa_local_elem ipv4;

	hnetd_time_t start_time;
	hnetd_time_t current_timeout;
	struct uloop_timeout timeout;

	struct pa_data_user data_user;
};

void pa_local_conf_defaults(struct pa_local_conf *conf);
void pa_local_init(struct pa_local *, const struct pa_local_conf *conf);
void pa_local_start(struct pa_local *);
void pa_local_stop(struct pa_local *);
void pa_local_term(struct pa_local *);

#endif /* PA_LOCAL_H_ */
