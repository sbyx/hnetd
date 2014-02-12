/*
 * pa_core.h
 *
 * Author: Pierre Pfister
 *
 * Prefix assignment core.
 *
 * This file contains prefix assignment logic elements.
 *
 */

#ifndef PA_CORE_H_
#define PA_CORE_H_

#include "pa_data.h"
#include "hnetd.h"

struct pa_core {
	hnetd_time_t start_time;
	struct {
		bool scheduled;
		struct uloop_timeout to;
	} paa;

	struct {
		bool scheduled;
		struct uloop_timeout to;
	} aaa;
};

void pa_core_init(struct pa_core *);
void pa_core_start(struct pa_core *);
void pa_core_stop(struct pa_core *);
void pa_core_term(struct pa_core *);

/* The prefix assignment algorithm must be scheduled anytime
 * - A dp is created or deleted
 * - An ap is created or deleted
 * - The rid is modified
 * - A link changes state (internal or externel)
 */
void pa_core_schedule(struct pa_core *);

/* Called whenever an eaa is created or deleted */
void pa_address_schedule(struct pa_core *);

/* Called whenever excluded is modified */
void pa_core_update_excluded(struct pa_core *, struct pa_ldp *);

/* Called whenever some prefix apply is modified */
void pa_core_cp_apply_modified(struct pa_core *, struct pa_cp *);

#endif /* PA_CORE_H_ */
