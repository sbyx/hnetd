#include "pa_pd.h"
#include "pa.h"

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_pd - "

#define PA_PD_DFLT_MIN_LEN 62
#define PA_PD_DFLT_RATIO_EXP 3

#define PA_PD_PREFIX_SEARCH_MAX_ROUNDS 64 //Done for each tested prefix length

#define PA_PD_LEASE_CB_DELAY 400
#define PA_PD_UPDATE_DELAY   100
#define PA_PD_UPDATE_RATE_DELAY 15000 //Limit DP-wide update
#define PA_PD_UPDATE_TOLERANCE  1000 //Do multiple things at the same uloop call if possible

#define pd_pa(pd) (container_of(pd, struct pa, pd))
#define pd_p(pd, field) (&(pd_pa(pd)->field))

struct pa_pd_dp_req {
	struct pa_dp *dp;
	struct pa_pd_lease *lease;
	struct list_head dp_le; /* reqed in dps reqs list. */
	struct list_head lease_le;
	uint8_t min_len;
	uint8_t max_len;
};

#define pa_for_each_req_in_dp(req, dp) list_for_each_entry(req, &(dp)->lease_reqs, dp_le)
#define pa_for_each_req_in_dp_safe(req, req2, dp) list_for_each_entry_safe(req, req2, &(dp)->lease_reqs, dp_le)
#define pa_for_each_req_in_lease(req, lease) list_for_each_entry(req, &(lease)->dp_reqs, lease_le)
#define pa_for_each_req_in_lease_safe(req, req2, lease) list_for_each_entry_safe(req, req2, &(lease)->dp_reqs, lease_le)

/* This is used to tweek requests into reasonable ones. */
static int pa_pd_filter_lengths(struct pa_pd_lease *lease, struct pa_dp *dp,
		uint8_t *min_len, uint8_t *max_len)
{
	struct pa_pd *pd = lease->pd;
	if(*min_len < dp->prefix.plen + pd->conf.pd_min_ratio_exp)
		*min_len = dp->prefix.plen + pd->conf.pd_min_ratio_exp;

	if(*min_len < pd->conf.pd_min_len)
		*min_len = pd->conf.pd_min_len;

	if(*max_len > 128 || *max_len < *min_len || *max_len < dp->prefix.plen)
		return -1;

	return 0;
}

static int pa_pd_req_create(struct pa_pd_lease *lease, struct pa_dp *dp)
{
	struct pa_pd_dp_req *req = malloc(sizeof(struct pa_pd_dp_req));
	if(!req)
		return -1;

	req->min_len = lease->preferred_len;
	req->max_len = lease->max_len;
	if(pa_pd_filter_lengths(lease, dp, &req->min_len, &req->max_len)) {
		free(req);
		return -1;
	}

	req->dp = dp;
	req->lease = lease;
	list_add(&req->dp_le, &dp->lease_reqs);
	list_add(&req->lease_le, &lease->dp_reqs);
	return 0;
}

static void pa_pd_req_destroy(struct pa_pd_dp_req *req)
{
	list_del(&req->lease_le);
	list_del(&req->dp_le);
	free(req);
}

static void pa_pd_cpd_adopt(struct pa_pd_dp_req *req, struct pa_cpd *cpd)
{
	pa_cp_set_dp(&cpd->cp, req->dp);
	pa_pd_req_destroy(req);
	pa_cp_notify(&cpd->cp);
}


/* We only create cpd from req. And the req is destroyed in the process. */
static int pa_pd_create_cpd(struct pa_pd_dp_req *req, struct prefix *p)
{
	struct pa_pd *pd = req->lease->pd;
	struct pa_cpd *cpd = _pa_cpd(pa_cp_get(&pd_pa(pd)->data, p, PA_CPT_D, true));
	if(!cpd) {
		L_ERR("Could not create cpd from prefix %s (algorithmic error).", PREFIX_REPR(p));
		return -1;
	}

	pa_cpd_set_lease(cpd, req->lease);
	pa_cp_set_advertised(&cpd->cp, true);
	pa_cp_set_dp(&cpd->cp, req->dp);
	pa_cp_set_apply_to(&cpd->cp, 2*pd_pa(pd)->data.flood.flooding_delay);
	pa_pd_req_destroy(req);
	pa_cp_notify(&cpd->cp);
	return 0;
}

/* Look for a prefix of given exact length */
static int pa_pd_find_prefix_plen(struct pa_pd_dp_req *req, struct prefix *dst, uint8_t plen)
{
	uint32_t rounds;
	int res;
	char *lease_id = req->lease->lease_id;
	struct pa_dp *dp = req->dp;
	struct pa_pd *pd = req->lease->pd;
	struct prefix p_init;

	if(lease_id) {
		if(prefix_prandom(lease_id, strlen(lease_id), 0, &dp->prefix, dst, plen))
			goto err;
	} else {
		if(prefix_random(&dp->prefix, dst, plen))
			goto err;
	}

	prefix_cpy(&p_init, dst); //Remember the first chosen

	if(plen - dp->prefix.plen >= 32 || (rounds = 1 << (plen - dp->prefix.plen)) >= PA_PD_PREFIX_SEARCH_MAX_ROUNDS) {
		rounds = PA_PD_PREFIX_SEARCH_MAX_ROUNDS;
	}

	const struct prefix *collision;
	for(; rounds; rounds--) {
		if(!(collision = pa_prefix_getcollision(pd_pa(pd), dst)))
			return 0;

		if(prefix_contains(dst, collision)) {
			if((res = prefix_increment(dst, dst, dp->prefix.plen)) == -1)
				goto err;
		} else { //prefix_contains(collision, new_prefix)
			if((res = prefix_increment(dst, collision, dp->prefix.plen)) == -1)
				goto err;
			dst->plen = plen;
		}

		//todo: That approach may be more clever that what is done in pa_core.
		if(!prefix_cmp(dst, &p_init)) {
			// We looped
			return -1;
		}
	}


	return -1;
err:
	L_ERR("Critical error in random prefix search");
	return -1;
}

static int pa_pd_find_prefix(struct pa_pd_dp_req *req, struct prefix *dst,
		uint8_t min_len_override)
{
	struct prefix try_prefix;
	uint8_t min_len = req->min_len;
	uint8_t max_len = req->max_len;

	if(min_len < min_len_override) {
			min_len = min_len_override;
			if(min_len > max_len)
				return -1;
	}

	uint8_t try_len = min_len;
	uint8_t new_len;
	bool best_found = false;

	/* todo: Maybe the dichotomy is not that good afterall. At least when we do all
	 * requests from a given dp. Maybe using both approach may be good. */

	while(true) {
		if(!pa_pd_find_prefix_plen(req, &try_prefix, try_len)) {
			if(!best_found || try_prefix.plen < dst->plen) {
				best_found = true;
				prefix_cpy(dst, &try_prefix);
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

	return (best_found)?0:-1;
}

//todo: I think those macros may be useful in other pa_foo files
#define pa_pd_to_schedule(to, started, delay, do_also) do { \
	if(!(to)->pending) { \
		do_also; \
		if(started) { \
			uloop_timeout_set(to, delay); \
		} else { \
			(to)->pending = true; \
		}\
	}\
} while(0)

#define pa_pd_to_stop(to) do { \
	if((to)->pending) { \
		uloop_timeout_cancel(to);\
		(to)->pending = true; \
	} \
} while(0)

#define pa_pd_to_start(to, delay) do { \
		if((to)->pending) { \
			(to)->pending = false; \
			uloop_timeout_set(to, delay);\
		} \
} while(0)

static void pa_pd_lease_schedule(struct pa_pd *pd, struct pa_pd_lease *lease)
{
	pa_pd_to_schedule(&lease->cb_to, pd->started, PA_PD_LEASE_CB_DELAY,
			L_DEBUG("Scheduling lease callback "PA_PDL_L, PA_PDL_LA(lease)));
}

static void pa_pd_schedule(struct pa_pd *pd)
{
	pa_pd_to_schedule(&pd->update, pd->started, PA_PD_UPDATE_DELAY,
			L_DEBUG("Scheduling pd computation"));
}

static void pa_pd_dp_schedule(struct pa_pd *pd, struct pa_dp *dp)
{
	hnetd_time_t delay = -1;

	if(list_empty(&dp->lease_reqs))
		return;

	if(dp->compute_leases_last <= 0) {
		delay = 0;
	} else {
		delay = dp->compute_leases_last + PA_PD_UPDATE_RATE_DELAY - hnetd_time();
	}

	if(delay < PA_PD_UPDATE_DELAY)
		delay = PA_PD_UPDATE_DELAY;

	if(delay != -1) {
		if(!pd->started) {
			pa_pd_schedule(pd);
		} else if (!pd->update.pending) {
			uloop_timeout_set(&pd->update, (int) delay);
		} else if (uloop_timeout_remaining(&pd->update) > (int) (delay + PA_PD_UPDATE_TOLERANCE)) {
			uloop_timeout_set(&pd->update, (int) delay);
		}
	}
}

/* This callback can give information about available space (free space).
 * When some new space is found, candidate to recomputation leases should be marked. */
static void pa_pd_cps_cb(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags)
{
	struct pa_cpd *cpd;

	if(!(cpd = _pa_cpd(cp)) || (flags & PADF_CP_TODELETE))
		return;

	if((flags & (PADF_CP_APPLIED)) || (cp->applied && (flags & PADF_CP_DP))) {
		pa_pd_lease_schedule(container_of(user, struct pa_pd, data_user), cpd->lease);
	}
}

/* pa_core.c takes care of removing deleted dps from all cps. No need to do it here.
 * But when a new dp is created, we want to add it to existing leases. */
static void pa_pd_dps_cb(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	struct pa_pd_lease *lease;
	struct pa_pd *pd = container_of(user, struct pa_pd, data_user);
	struct pa_cp *cp, *cp2;
	struct pa_pd_dp_req *req, *req2;

	if(prefix_is_ipv4(&dp->prefix))
		return;

	if (flags & PADF_DP_TODELETE) {
		/* Make orphans */
		pa_for_each_cp_in_dp_safe(cp, cp2, dp) {
			if(cp->type == PA_CPT_D) {
				pa_cp_set_dp(cp, NULL);
				pa_cp_notify(cp);
			}
		}

		/* Remove all unsatisfied */
		pa_for_each_req_in_dp_safe(req, req2, dp)
			pa_pd_req_destroy(req);

	} else if(flags & PADF_DP_CREATED) {
		/* Add new reqs for all existing leases */
		pa_pd_for_each_lease(lease, pd)
			pa_pd_req_create(lease, dp);

		dp->compute_leases_last = 0;
		pa_pd_dp_schedule(pd, dp);
	} else if(flags & (PADF_DP_LIFETIME | PADF_DP_DHCP)) {
		/* Just schedule cb call for concerned leases */
		pa_for_each_cp_in_dp(cp, dp) {
			if(cp->type == PA_CPT_D) {
				//Little trick to tell the dp was modified
				pa_pd_cps_cb(user, cp, PADF_CP_DP);
			}
		}
	}
}

static void pa_pd_update_cb(struct uloop_timeout *to)
{
	struct pa_pd *pd = container_of(to, struct pa_pd, update);
	struct pa_dp *dp;
	struct pa_pd_lease *lease;
	struct pa_cp *cp, *cp2;
	struct pa_cpd *cpd;
	struct pa_pd_dp_req *req, *req2;
	hnetd_time_t now = hnetd_time();

	/* Check for all dps if some wants to be updated */
	pa_for_each_dp(dp, &pd_pa(pd)->data) {
		if(prefix_is_ipv4(&dp->prefix))
			continue;

		if(pa_dp_ignore(pd_pa(pd), dp)) {
			/* Orphan all cpds and add them to unsatisfied */
			pa_for_each_cp_in_dp_safe(cp, cp2, dp) {
				if((cpd = _pa_cpd(cp))) {
					pa_cp_set_dp(cp, NULL);
					pa_cp_notify(cp);
					pa_pd_req_create(cpd->lease, dp); // Add to unsatisfied
				}
			}
		} else if(!dp->compute_leases_last ||
						dp->compute_leases_last + PA_PD_UPDATE_RATE_DELAY <= now) {
			//We do when the dp is new, or when a minimum delay elapsed

			/* Try to satisfy unsatisfied */
			uint8_t min_len = 0;
			pa_for_each_req_in_dp_safe(req, req2, dp) {
				bool found = false;
				/* find orphans */
				pa_pd_for_each_cpd(cpd, req->lease) {
					if(!cpd->cp.dp && prefix_contains(&dp->prefix, &cpd->cp.prefix)) {
						pa_pd_cpd_adopt(req, cpd);
						found = true;
					}
				}

				if(found)
					continue;

				struct prefix p;
				if(!pa_pd_find_prefix(req, &p, min_len)) {
					if(p.plen != req->min_len && p.plen > min_len)
						min_len = p.plen; /* Could not fulfill desire, so let's remember it*/
					pa_pd_create_cpd(req, &p); //That will delete the req as well (and schedule
				} else {
					if(req->max_len > min_len)
						min_len = req->max_len; // Remember it failed up to max_len
				}

			}
			dp->compute_leases_last = now;
		}
	}

	/* Populate just-created leases */
	pa_pd_for_each_lease(lease, pd) {
		if(lease->just_created) {
			pa_for_each_req_in_lease_safe(req, req2, lease) {
				struct prefix p;
				if(!pa_dp_ignore(pd_pa(pd), req->dp) && !pa_pd_find_prefix(req, &p, 0)) {
					pa_pd_create_cpd(req, &p);
				}
			}

			/* If all failed, better tell the requester (or it could wait forever... ) */
			if(list_empty(&lease->cpds))
				pa_pd_lease_schedule(pd, lease);

			lease->just_created = false;
		}
	}
}

static void pa_pd_lease_cb(struct uloop_timeout *to)
{
	struct pa_pd_lease *lease = container_of(to, struct pa_pd_lease, cb_to);
	struct pa_cpd *cpd, *cpd2;

	L_INFO("Lease callback for "PA_PDL_L, PA_PDL_LA(lease));

	if(lease->update_cb)
		lease->update_cb(lease);

	/* Remove orphan cpds */
	pa_pd_for_each_cpd_safe(cpd, cpd2, lease) {
		if(!cpd->cp.dp) {
			pa_cp_todelete(&cpd->cp);
			pa_cp_notify(&cpd->cp);
		}
	}
}

int pa_pd_lease_init(struct pa_pd *pd, struct pa_pd_lease *lease,
		const char *lease_id, uint8_t preferred_len, uint8_t max_len)
{
	if(!lease_id) {
		lease->lease_id = NULL;
	} else if(!(lease->lease_id = strdup(lease_id))) {
		return -1;
	}

	lease->cb_to.cb = pa_pd_lease_cb;
	lease->cb_to.pending = false;
	lease->pd = pd;
	lease->preferred_len = preferred_len;
	lease->max_len = max_len;
	lease->just_created = true;
	INIT_LIST_HEAD(&lease->cpds);
	INIT_LIST_HEAD(&lease->dp_reqs);
	list_add(&lease->le, &pd->leases);

	L_INFO("Initializing "PA_PDL_L, PA_PDL_LA(lease));

	/* Populate for every lease */
	struct pa_dp *dp;
	pa_for_each_dp(dp, pd_p(pd, data)) {
		if(!prefix_is_ipv4(&dp->prefix))
			pa_pd_req_create(lease, dp);
	}

	/* Schedule the pd */
	pa_pd_schedule(pd);

	return 0;
}

void pa_pd_lease_term(__unused struct pa_pd *pd, struct pa_pd_lease *lease)
{
	struct pa_cpd *cpd;
	struct pa_pd_dp_req *req;
	if(lease->cb_to.pending)
		uloop_timeout_cancel(&lease->cb_to);

	L_INFO("Terminating "PA_PDL_L, PA_PDL_LA(lease));

	while(!list_empty(&lease->cpds)) {
		cpd = list_first_entry(&lease->cpds, struct pa_cpd, lease_le);
		list_remove(&cpd->lease_le); // This is just for safety in case somebody look at it somewhere...
		cpd->lease = NULL;
		pa_cp_todelete(&cpd->cp);
		pa_cp_notify(&cpd->cp);
	}

	while(!list_empty(&lease->dp_reqs)) {
		/* Unreqing all dps that lease is unsatisfied with */
		req = list_first_entry(&lease->dp_reqs, struct pa_pd_dp_req, lease_le);
		pa_pd_req_destroy(req);
	}

	list_remove(&lease->le);
	if(lease->lease_id)
		free(lease->lease_id);
}

void pa_pd_conf_defaults(struct pa_pd_conf *conf)
{
	conf->pd_min_len = PA_PD_DFLT_MIN_LEN;
	conf->pd_min_ratio_exp = PA_PD_DFLT_RATIO_EXP;
}

void pa_pd_init(struct pa_pd *pd, const struct pa_pd_conf *conf)
{
	L_NOTICE("Initializing pa_pd");
	list_init_head(&pd->leases);
	if(conf)
		pd->conf = *conf;
	memset(&pd->data_user, 0, sizeof(struct pa_data_user));
	pd->data_user.dps = pa_pd_dps_cb;
	pd->data_user.cps = pa_pd_cps_cb;
	pd->update.cb = pa_pd_update_cb;
	pd->update.pending = false;
}

void pa_pd_start(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(!pd->started) {
		L_NOTICE("Starting pa_pd");
		pd->started = true;
		pa_pd_to_start(&pd->update, PA_PD_UPDATE_DELAY);
		pa_data_subscribe(&pd_pa(pd)->data, &pd->data_user);
		list_for_each_entry(lease, &pd->leases, le)
			pa_pd_to_start(&lease->cb_to, PA_PD_LEASE_CB_DELAY);
	}
}

void pa_pd_stop(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(pd->started) {
		L_NOTICE("Stopping pa_pd");
		list_for_each_entry(lease, &pd->leases, le)
			pa_pd_to_stop(&lease->cb_to);

		pa_data_unsubscribe(&pd->data_user);
		pa_pd_to_stop(&pd->update);
		pd->started = false;
	}
}

void pa_pd_term(struct pa_pd *pd)
{
	L_NOTICE("Terminating pa_pd");
	struct pa_pd_lease *lease;
	pa_pd_stop(pd);

	pa_pd_for_each_lease(lease, pd) {
		pa_pd_lease_term(pd, lease);
	}
}
