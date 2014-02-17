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
	struct pa_data_user data_user;
};

void pa_core_init(struct pa_core *);
void pa_core_start(struct pa_core *);
void pa_core_stop(struct pa_core *);
void pa_core_term(struct pa_core *);

#endif /* PA_CORE_H_ */
