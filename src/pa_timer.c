#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_timer - "

#include "pa_timer.h"

static hnetd_time_t __pat_t;
#define TODELAY(t) (int)(((__pat_t = (t)) > INT32_MAX)?INT32_MAX:(  (__pat_t < 0)?0:__pat_t  ))

static void pa_timer_cb(struct uloop_timeout *t) {
	struct pa_timer *timer = container_of(t, struct pa_timer, t);
	timer->when = -1;
	if(timer->cb)
		timer->cb(timer);
}

void pa_timer_init(struct pa_timer *t, void (*cb)(struct pa_timer *), const char *name)
{
	L_DEBUG("Initialize timer %s", name);
	t->t.pending = false;
	t->t.cb = pa_timer_cb;
	t->enabled = false;
	t->cb = cb;
	t->when = -1;
	t->name = name;
}

static inline void pa_timer_update_to(struct pa_timer *t)
{
	if(t->when >= 0) {
		hnetd_time_t when = t->when;
		int delay;
		if(when < t->not_before)
			when = t->not_before;
		delay = TODELAY(when - hnetd_time());
		L_INFO("Scheduling %s in %d ms", t->name, delay);
		uloop_timeout_set(&t->t, delay);
	} else if(t->t.pending) {
		L_INFO("Canceling %s", t->name);
		uloop_timeout_cancel(&t->t);
	}
}

static inline void pa_timer_set_when(struct pa_timer *t, hnetd_time_t when)
{
	t->when = when;
	if(t->enabled)
		pa_timer_update_to(t);
}

void pa_timer_enable(struct pa_timer *t)
{
	if(t->enabled)
		return;
	L_INFO("Enabling %s", t->name);
	t->enabled = true;
	pa_timer_update_to(t);
}

void pa_timer_disable(struct pa_timer *t)
{
	if(!t->enabled)
		return;
	L_INFO("Disabling %s", t->name);
	t->enabled = false;
	if(t->t.pending)
		uloop_timeout_cancel(&t->t);
}

void pa_timer_set_earlier(struct pa_timer *t, hnetd_time_t time, bool relative)
{
	if(relative)
		time += hnetd_time();

	if(t->when < 0 || t->when > time)
		pa_timer_set_when(t, time);
}

void pa_timer_cancel(struct pa_timer *t)
{
	if(t->when >= 0)
		pa_timer_set_when(t, -1);
}

void pa_timer_set_not_before(struct pa_timer *t, hnetd_time_t time, bool relative)
{
	if(relative)
		time += hnetd_time();

	if(t->not_before == time)
		return;

	t->not_before = time;
	if(t->enabled && t->when >= 0)
		pa_timer_update_to(t);
}
