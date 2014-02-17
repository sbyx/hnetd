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

#define PA_FLOOD_DELAY_DEFAULT     5000
#define PA_FLOOD_DELAY_LL_DEFAULT  1000

#define PA_PRIORITY_MIN              0
#define PA_PRIORITY_AUTHORITY_MIN    4
#define PA_PRIORITY_AUTO_MIN         6
#define PA_PRIORITY_DEFAULT          8
#define PA_PRIORITY_AUTO_MAX         10
#define PA_PRIORITY_AUTHORITY_MAX    12
#define PA_PRIORITY_MAX              15

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

	/* Maximum number of stored prefixes
	 * default = 100 */
	size_t max_sp;

	/* Maximum number of stored prefixes per interface
	 * default = 10 */
	size_t max_sp_per_if;
};

struct pa {
	bool started;
	struct pa_core core;                  /* Algorithm core elements */
	struct pa_data data;                  /* PAA database */
	struct pa_conf conf;                  /* Configuration */
	struct pa_local local;                /* Ipv4 and ULA elements */
	struct pa_store store;                /* Stable storage interface */
	struct iface_user ifu;
};

#define pa_data(pa) (&(pa)->data)

void pa_conf_set_defaults(struct pa_conf *conf);
/* Initializes the pa structure. */
void pa_init(struct pa *pa, const struct pa_conf *conf);
/* Start the pa algorithm. */
void pa_start(struct pa *pa);
/* Pause the pa alforithm (In a possibly wrong state). */
void pa_stop(struct pa *pa);
/* Reset pa to post-init state, without modifying configuration. */
void pa_term(struct pa *pa);

#endif /* PA_H_ */
