/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * uloop_timeout encapsulation for PA objects.
 *
 */

#ifndef PA_TIMER_H_
#define PA_TIMER_H_

#include "hnetd.h"
#include <libubox/uloop.h>

struct pa_timer {
	struct uloop_timeout t;
	bool enabled;
	hnetd_time_t when;
	hnetd_time_t not_before;
	hnetd_time_t min_delay;
	void (*cb)(struct pa_timer *);
	const char *name;
};

void pa_timer_init(struct pa_timer *, void (*cb)(struct pa_timer *), const char *name);
void pa_timer_enable(struct pa_timer *);
void pa_timer_disable(struct pa_timer *);

void pa_timer_set(struct pa_timer *, hnetd_time_t time, bool relative);
void pa_timer_set_earlier(struct pa_timer *, hnetd_time_t time, bool relative);
void pa_timer_set_not_before(struct pa_timer *, hnetd_time_t time, bool relative);
void pa_timer_cancel(struct pa_timer *);

#endif /* PA_TIMER_H_ */
