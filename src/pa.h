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
#include "pa_pd.h"

#include "hnetd.h"

#include "iface.h"

#define PA_PRIORITY_MIN              0
#define PA_PRIORITY_AUTHORITY_MIN    4
#define PA_PRIORITY_AUTO_MIN         6
#define PA_PRIORITY_DEFAULT          8
#define PA_PRIORITY_AUTO_MAX         10
#define PA_PRIORITY_AUTHORITY_MAX    12
#define PA_PRIORITY_MAX              15

struct pa_conf {
	struct pa_data_conf data_conf;
	struct pa_local_conf local_conf;
};

struct pa {
	bool started;
	struct pa_core core;                  /* Algorithm core elements */
	struct pa_data data;                  /* PAA database */
	struct pa_conf conf;                  /* Configuration */
	struct pa_local local;                /* Ipv4 and ULA elements */
	struct pa_store store;                /* Stable storage interface */
	struct pa_pd pd;                      /* Prefix delegation support */
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
