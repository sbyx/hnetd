#include "pa_local.h"

#define local_pa(local) (container_of(local, struct pa, local))
#define local_rid(local) (&((core_pa(local))->flood.rid))
#define local_p(local, field) (&(core_pa(local)->field))

#define PA_LOCAL_MIN_DELAY 5

static void __pa_local_do(struct pa_local *local)
{
	if(local)
		return;
}

static void __pa_local_do_cb(struct uloop_timeout *to)
{
	__pa_local_do(container_of(to, struct pa_local, timeout));
}

static void pa_local_settimer(struct pa_local *local, hnetd_time_t when, hnetd_time_t now)
{
	if(!local->start_time) {
		if(local->current_timeout > when)
			local->current_timeout = when;
		return;
	}

	if(when < now)
		when = now;

	if(local->current_timeout && local->current_timeout < when)
		return;

	hnetd_time_t delay = when - now;

	if(local->start_time + local_pa(local)->flood.flooding_delay > when)
		delay = local->start_time + local_pa(local)->flood.flooding_delay - now;

	if(delay < PA_LOCAL_MIN_DELAY)
		delay = PA_LOCAL_MIN_DELAY;
	if(delay > INT32_MAX)
		delay = INT32_MAX;

	local->current_timeout = now + delay;
	uloop_timeout_set(&local->timeout, (int) delay);
}

void pa_local_init(struct pa_local *local)
{
	local->ipv4_access.available = false;
	local->start_time = 0;
	local->current_timeout = 0;
	local->timeout.pending = false;
	local->timeout.cb = __pa_local_do_cb;
	local->ula.enabled = false;
	local->ipv4.enabled = false;
}

void pa_local_start(struct pa_local *local)
{
	if(local->start_time)
		return;

	local->start_time = hnetd_time();
	if(local->current_timeout) {
		local->current_timeout = 0;
		pa_local_settimer(local, local->current_timeout, local->start_time);
	}
}

void pa_local_stop(struct pa_local *local)
{
	if(!local->start_time)
		return;

	local->start_time = 0;
	if(local->current_timeout) {
		local->current_timeout = 0;
		uloop_timeout_cancel(&local->timeout);
	}
}

void pa_local_term(struct pa_local *local)
{
	pa_local_stop(local);
	//todo: Remove ula and ipv4
}


void pa_local_update_ipv4(struct pa_local *local, bool available, const void *dhcp_data, size_t dhcp_len)
{
	void *new_dhcp;

	local->ipv4_access.available = available;
	if(local->ipv4_access.dhcp_data)
		free(local->ipv4_access.dhcp_data);

	if(dhcp_data && dhcp_len) {
		new_dhcp = malloc(dhcp_len);
		if(new_dhcp)
			memcpy(new_dhcp, dhcp_data, dhcp_len);
	} else {
		new_dhcp = NULL;
	}

	local->ipv4_access.dhcp_data = new_dhcp;
	local->ipv4_access.dhcp_len = new_dhcp?dhcp_len:0;

	pa_local_schedule(local);
}


void pa_local_schedule(struct pa_local *local)
{
	hnetd_time_t when = hnetd_time() + local_pa(local)->flood.flooding_delay / 10;
	pa_local_settimer(local, when, hnetd_time());
}

