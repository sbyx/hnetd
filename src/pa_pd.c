#include "pa_pd.h"

#define PA_PD_PREFIX_SEARCH_MAX_ROUNDS 32 //Done for each tested prefix length

static int pa_pd_find_available_prefix(struct pa_pd *pd,
		struct pa_dp *dp, uint8_t plen, struct prefix *dst)
{
	uint32_t rounds;

	if(prefix_random(&dp->prefix, dst, plen))
		return -1;

	if(plen - dp->prefix.plen >= 32 || (rounds = 1 << (plen - dp->prefix.plen)) >= PA_PD_PREFIX_SEARCH_MAX_ROUNDS) {
		rounds = PA_PD_PREFIX_SEARCH_MAX_ROUNDS;
	}

	//todo
	return -1;
}

/* Will try to find an available prefix and add it */
static int pa_pd_add_dp(struct pa_pd *pd, struct pa_pd_lease *lease,
		struct pa_dp *dp, uint8_t preferred_len, uint8_t max_len)
{
	if(prefix_is_ipv4(&dp->prefix))
		return -1; /* No pd for IPv4 */

	/* We want to prevent a single pd to take too many addresses.
	 * For now, it is limited to one quarter of the pd */
	if(preferred_len < dp->prefix.plen + 2)
		preferred_len = dp->prefix.plen + 2;

	if(max_len > 128 || max_len < preferred_len || max_len < dp->prefix.plen)
		return -1;

	if(preferred_len < dp->prefix.plen)
		preferred_len = dp->prefix.plen;

	while(preferred_len <= max_len)
	{
		struct prefix p;
		if(!pa_pd_find_available_prefix(pd, dp, preferred_len, &p))
			return 0;

		// We might want to be clever in the way we find a prefix
	}
	//todo: todo

	return -1;
}

static void pa_pd_lease_schedule(struct pa_pd *pd, struct pa_pd_lease *lease)
{

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

static void pa_pd_lease_cb(struct uloop_timeout *to)
{

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
	pa_pd_lease_schedule(pd, lease);
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

void pa_pd_init(struct pa_pd *pd)
{
	list_init_head(&pd->leases);
	memset(&pd->data_user, 0, sizeof(struct pa_data_user));
	pd->data_user.dps = pa_pd_dps_cb;
	pd->data_user.cps = pa_pd_cps_cb;
}

void pa_pd_start(struct pa_pd *pd)
{
	if(!pd->started) {
		pd->started = true;
	}
}

void pa_pd_stop(struct pa_pd *pd)
{

}

void pa_pd_term(struct pa_pd *pd)
{

}
