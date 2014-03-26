#include "pa_pd.h"
#include "pa.h"

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_pd - "

#define PA_PD_DFLT_MIN_LEN 60
#define PA_PD_DFLT_RATIO_EXP 2

#define PA_PD_PREFIX_SEARCH_MAX_ROUNDS 32 //Done for each tested prefix length

#define PA_PD_LEASE_CB_DELAY 500

#define pd_pa(pd) (container_of(pd, struct pa, pd))
#define pd_p(pd, field) (&(pd_pa(pd)->field))

static int pa_pd_create_cpd(struct pa_pd *pd, struct pa_dp *dp,
		struct pa_pd_lease *lease, struct prefix *p)
{
	struct pa_cpd *cpd = _pa_cpd(pa_cp_get(&pd_pa(pd)->data, p, PA_CPT_D, true));
	if(!cpd)
		return -1;

	cpd->lease = lease;
	list_add(&cpd->lease_le, &lease->cpds);
	pa_cp_set_advertised(&cpd->cp, true);
	pa_cp_set_dp(&cpd->cp, dp);
	pa_cp_set_apply_to(&cpd->cp, 2*pd_pa(pd)->data.flood.flooding_delay);
	pa_cp_notify(&cpd->cp);
	return 0;
}

static int pa_pd_find_available_prefix(struct pa_pd *pd,
		struct pa_dp *dp, uint8_t plen, struct prefix *dst)
{
	uint32_t rounds;
	int res;

	if(prefix_random(&dp->prefix, dst, plen))
		return -1;

	if(plen - dp->prefix.plen >= 32 || (rounds = 1 << (plen - dp->prefix.plen)) >= PA_PD_PREFIX_SEARCH_MAX_ROUNDS) {
		rounds = PA_PD_PREFIX_SEARCH_MAX_ROUNDS;
	}

	bool looped = false;
	const struct prefix *collision;
	for(; rounds; rounds--) {
		if(!(collision = pa_prefix_getcollision(pd_pa(pd), dst)))
			return 0;

		if(prefix_contains(dst, collision)) {
			if((res = prefix_increment(dst, dst, dp->prefix.plen)) == -1)
				return -1;
		} else { //prefix_contains(collision, new_prefix)
			if((res = prefix_increment(dst, collision, dp->prefix.plen)) == -1)
				return -1;
			dst->plen = plen;
		}

		if(res) {
			if(looped)
				return -1;
			looped = true;
		}
	}

	return -1;
}

/* Will try to find an available prefix and add it */
static int pa_pd_add_dp(struct pa_pd *pd, struct pa_pd_lease *lease,
		struct pa_dp *dp, uint8_t min_len, uint8_t max_len)
{
	struct prefix best_prefix, try_prefix;
	uint8_t try_len, new_len;
	bool best_found;

	/* We want to prevent a single pd to take too many addresses. */
	if(min_len < dp->prefix.plen + pd->conf.pd_min_ratio_exp)
		min_len = dp->prefix.plen + pd->conf.pd_min_ratio_exp;

	if(min_len < pd->conf.pd_min_len)
		min_len = pd->conf.pd_min_len;

	if(max_len > 128 || max_len < min_len || max_len < dp->prefix.plen)
		return -1;

	try_len = min_len;
	best_found = false;
	while(true) {
		if(!pa_pd_find_available_prefix(pd, dp, try_len, &try_prefix)) {
			if(!best_found || try_prefix.plen < best_prefix.plen) {
				best_found = true;
				best_prefix = try_prefix;
			}
			new_len = try_len - (try_len + 1 - min_len)/2;
			max_len = try_len;
		} else {
			new_len = try_len + (max_len + 1 - try_len)/2;
			min_len = try_len;
		}

		if(new_len == try_len)
			break;

		try_len = new_len;
	}

	if(!best_found)
		return -1;

	return pa_pd_create_cpd(pd, dp, lease, &best_prefix);
}

static void pa_pd_lease_schedule(struct pa_pd *pd, struct pa_pd_lease *lease)
{
	if(!lease->cb_to.pending) {
		if(pd->started) {
			uloop_timeout_set(&lease->cb_to, PA_PD_LEASE_CB_DELAY);
		} else {
			lease->cb_to.pending = true;
		}
	}
}

/* pa_core.c takes care of removing deleted dps from all cps. No need to do it here.
 * But when a new dp is created, we want to add it to existing leases. */
static void pa_pd_dps_cb(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{

}

/* This is called when a cp is modified. For example, when the dp is changed.
 * Should ignore deletion and creation, cause it is made here. */
static void pa_pd_cps_cb(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags)
{

}

static void pa_pd_lease_populate(struct pa_pd *pd, struct pa_pd_lease *lease)
{
	struct pa_dp *dp;
	hnetd_time_t now = hnetd_time();

	pa_for_each_dp(dp, pd_p(pd, data)) {
		if(prefix_is_ipv4(&dp->prefix) || dp->valid_until < now)
			continue;

		if(pa_dp_ignore(pd_pa(pd), dp))
			continue;

		pa_pd_add_dp(pd, lease, dp, lease->preferred_len, lease->max_len);
	}
}

static void pa_pd_lease_cb(struct uloop_timeout *to)
{
	struct pa_pd_lease *lease = container_of(to, struct pa_pd_lease, cb_to);

	if(lease->update_cb)
		lease->update_cb(lease);
}

void pa_pd_lease_init(struct pa_pd *pd, struct pa_pd_lease *lease, uint8_t preferred_len, uint8_t max_len)
{
	lease->cb_to.cb = pa_pd_lease_cb;
	lease->cb_to.pending = false;
	lease->pd = pd;
	lease->preferred_len = preferred_len;
	lease->max_len = max_len;
	list_init_head(&lease->cpds);
	list_add(&lease->le, &pd->leases);

	/* */
	pa_pd_lease_populate(pd, lease);
}

void pa_pd_lease_term(struct pa_pd *pd, struct pa_pd_lease *lease)
{
	struct pa_cpd *cpd;
	if(lease->cb_to.pending)
		uloop_timeout_cancel(&lease->cb_to);

	while(!list_empty(&lease->cpds)) {
		cpd = list_first_entry(&lease->cpds, struct pa_cpd, lease_le);
		list_remove(&cpd->lease_le); // This is just for safety in case somebody look at it somewhere...
		cpd->lease = NULL;
		pa_cp_todelete(&cpd->cp);
		pa_cp_notify(&cpd->cp);
	}
	list_remove(&lease->le);
}

void pa_pd_conf_defaults(struct pa_pd_conf *conf)
{
	conf->pd_min_len = PA_PD_DFLT_MIN_LEN;
	conf->pd_min_ratio_exp = PA_PD_DFLT_RATIO_EXP;
}

void pa_pd_init(struct pa_pd *pd, const struct pa_pd_conf *conf)
{
	list_init_head(&pd->leases);
	if(conf)
		pd->conf = *conf;
	memset(&pd->data_user, 0, sizeof(struct pa_data_user));
	pd->data_user.dps = pa_pd_dps_cb;
	pd->data_user.cps = pa_pd_cps_cb;
}

void pa_pd_start(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(!pd->started) {
		pd->started = true;
		pa_data_subscribe(&pd_pa(pd)->data, &pd->data_user);
		list_for_each_entry(lease, &pd->leases, le) {
			if(lease->cb_to.pending) {
				lease->cb_to.pending = false;
				pa_pd_lease_schedule(pd, lease);
			}
		}
	}
}

void pa_pd_stop(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(pd->started) {
		list_for_each_entry(lease, &pd->leases, le) {
			if(lease->cb_to.pending) {
				uloop_timeout_cancel(&lease->cb_to);
				lease->cb_to.pending = true;
			}
		}
		pa_data_unsubscribe(&pd->data_user);
		pd->started = false;
	}
}

void pa_pd_term(struct pa_pd *pd)
{
	pa_pd_stop(pd);
	//todo: clean structure
}
