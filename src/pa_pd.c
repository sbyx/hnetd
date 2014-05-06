#include "pa_pd.h"
#include "pa.h"

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_pd - "

#define PA_PD_DFLT_MIN_LEN 62
#define PA_PD_DFLT_RATIO_EXP 3

#define PA_PD_PREFIX_SEARCH_MAX_ROUNDS 64 //Done for each tested prefix length

#define PA_PD_LEASE_CB_DELAY 100
#define PA_PD_UPDATE_DELAY   40
#define PA_PD_UPDATE_RATE_DELAY 1500 //Limit DP-wide update
#define PA_PD_UPDATE_TOLERANCE  1000 //Do multiple things at the same uloop call if possible

#define pd_pa(pd) (container_of(pd, struct pa, pd))
#define pd_p(pd, field) (&(pd_pa(pd)->field))

#define pa_pd_for_each_lease_safe(lease, l2, pa_pd) list_for_each_entry_safe(lease, l2, &(pa_pd)->leases, le)

struct pa_pd_dp_req {
	struct pa_dp *dp;
	struct pa_pd_lease *lease;
	struct list_head dp_le; /* reqed in dps reqs list. */
	struct btrie_element lease_be;
	uint8_t min_len;
	uint8_t max_len;
};

#define pa_for_each_req_in_dp(req, dp) list_for_each_entry(req, &(dp)->lease_reqs, dp_le)
#define pa_for_each_req_in_dp_safe(req, req2, dp) list_for_each_entry_safe(req, req2, &(dp)->lease_reqs, dp_le)
#define pa_for_each_req_in_lease(req, lease) btrie_for_each_down_entry(req, &(lease)->dp_reqs, NULL, 0, lease_be)
#define pa_for_each_req_in_lease_safe(req, req2, lease) btrie_for_each_down_entry_safe(req, req2, &(lease)->dp_reqs, NULL, 0, lease_be)
#define pa_pd_for_each_cpd_updown(pa_cpd, lease, p) btrie_for_each_updown_entry(pa_cpd, &(lease)->cpds, (btrie_key_t *)&(p)->prefix, (p)->plen, lease_be)
#define pa_pd_for_each_cpd_down(pa_cpd, lease, p) btrie_for_each_down_entry(pa_cpd, &(lease)->cpds, (btrie_key_t *)&(p)->prefix, (p)->plen, lease_be)

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
	btrie_add(&lease->dp_reqs, &req->lease_be, (btrie_key_t *)&dp->prefix.prefix, dp->prefix.plen);
	return 0;
}

static void pa_pd_req_destroy(struct pa_pd_dp_req *req)
{
	btrie_remove(&req->lease_be);
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
	pa_cp_set_priority(&cpd->cp, PA_PRIORITY_PD);
	pa_cp_set_dp(&cpd->cp, req->dp);
	pa_cp_set_apply_to(&cpd->cp, 2*pd_pa(pd)->data.flood.flooding_delay);
	pa_pd_req_destroy(req);
	pa_cp_notify(&cpd->cp);
	return 0;
}

/* Look for a prefix of seed's prefix length and using the seed as starting point */
static int pa_pd_find_prefix_plen(struct pa_pd_dp_req *req, const struct prefix *seed,
		struct prefix *dst)
{
	struct pa_dp *dp = req->dp;
	struct pa_pd *pd = req->lease->pd;
	const struct prefix *collision;
	const struct prefix *first_collision = NULL;
	prefix_cpy(dst, seed);

	L_DEBUG("Trying with plen %d", (int) seed->plen);

	while(1) {
		if(!(collision = pa_prefix_getcollision(pd_pa(pd), dst)))
			return 0;

		L_DEBUG("Prefix %s can't be used", PREFIX_REPR(dst));

		if(!first_collision) {
			first_collision = collision;
		} else if(!prefix_cmp(collision, first_collision)) { //We looped
			L_INFO("No more available prefix can be found in %s", PREFIX_REPR(&dp->prefix));
			return -1;
		}

		if(dst->plen <= collision->plen) {
			if(prefix_increment(dst, dst, dp->prefix.plen) == -1) {
				L_ERR("Error incrementing %s with protected length %d", PREFIX_REPR(dst), dp->prefix.plen);
				return -1;
			}
		} else {
			if(prefix_increment(dst, collision, dp->prefix.plen) == -1) {
				L_ERR("Error incrementing %s with protected length %d", PREFIX_REPR(collision), dp->prefix.plen);
				return -1;
			}
			dst->plen = seed->plen;
		}
	}
	return -1; //avoid warning
}

static int pa_pd_find_prefix(struct pa_pd_dp_req *req, struct prefix *dst,
		uint8_t min_len_override)
{
	struct prefix seed;
	struct prefix try_prefix;
	struct pa_pd_lease *lease = req->lease;
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

	if(lease->lease_id) {
		if(prefix_prandom(lease->lease_id, strlen(lease->lease_id), 0, &req->dp->prefix, &seed, max_len))
			goto err;
	} else {
		if(prefix_random(&req->dp->prefix, &seed, max_len))
			goto err;
	}

	L_DEBUG("Trying to find a pd in "PA_DP_L" len(%d:%d) seed(%s)",
			PA_DP_LA(req->dp), (int) min_len, (int) max_len, ADDR_REPR(&seed.prefix));

	/* todo: Maybe the dichotomy is not that good afterall. At least when we do all
	 * requests from a given dp. Maybe using both approach may be good. */
	while(true) {
		seed.plen = try_len;
		if(!pa_pd_find_prefix_plen(req, &seed, &try_prefix)) {
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

err:
	L_ERR("Critical error in random prefix search");
	return -1;
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
			L_DEBUG("Scheduling pd computation in %d ms", (int) PA_PD_UPDATE_DELAY));
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
			L_DEBUG("Scheduling pd computation in %d ms", (int) delay);
			uloop_timeout_set(&pd->update, (int) delay);
		} else if (uloop_timeout_remaining(&pd->update) > (int) (delay + PA_PD_UPDATE_TOLERANCE)) {
			L_DEBUG("Scheduling pd computation in %d ms", (int) delay);
			uloop_timeout_set(&pd->update, (int) delay);
		}
	}
}

static void pa_pd_destroy_cpd(struct pa_data *data, struct pa_cp *cp, void *owner)
{
	struct pa_pd *pd = &container_of(data, struct pa, data)->pd;
	struct pa_cpd *cpd = _pa_cpd(cp);
	struct pa_dp *dp;

	if(owner != pd) {
		if(cpd->lease->update_cb) {
			dp = cpd->cp.dp;
			if(dp) {
				pa_cp_set_dp(&cpd->cp, NULL);
				pa_pd_req_create(cpd->lease, dp); // Add to unsatisfied
				pa_pd_dp_schedule(pd, dp); // Schedule the dp for recomputation
			}
			cpd->lease->update_cb(cpd->lease);
		}
	}

	pa_cp_todelete(&cpd->cp);
	pa_cp_notify(&cpd->cp);
}

static void pa_pd_aps_cb(struct pa_data_user *user, struct pa_ap *ap, uint32_t flags)
{
	struct pa_dp *dp;
	struct pa_cpd *cpd;
	struct pa_pd_lease *lease;
	struct pa_pd *pd = container_of(user, struct pa_pd, data_user);

	if(prefix_is_ipv4(&ap->prefix))
		return;

	if(flags & PADF_AP_TODELETE) { //More space is available in this dp
		pa_for_each_dp_updown(dp, pd_p(pd, data), &ap->prefix) {
			if(!list_empty(&dp->lease_reqs) && !dp->ignore) {
				pa_pd_dp_schedule(pd, dp);
				break;
			}
		}
	} else if (flags & PADF_AP_CREATED) {
		//Check for collisions. That should delete cpd whenever an ap forbids its use
		pa_pd_for_each_lease(lease, pd) {
			pa_pd_for_each_cpd_updown(cpd, lease, &ap->prefix) {
				if((pa_precedence_apcp(ap, &cpd->cp) > 0)) {
					pa_cp_set_applied(&cpd->cp, false);    //Unapplied if ever applied
					pa_cp_set_advertised(&cpd->cp, false); //Do not advertise because invalid
					pa_cp_notify(&cpd->cp);
				}
			}
		}
	}
}

/* This callback can give information about available space (free space).
 * When some new space is found, candidate to recomputation leases should be marked. */
static void pa_pd_cps_cb(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags)
{
	struct pa_cpd *cpd;
	struct pa_dp *dp;
	struct pa_pd *pd = container_of(user, struct pa_pd, data_user);
	if(prefix_is_ipv4(&cp->prefix))
		return;

	if(flags & PADF_CP_TODELETE) { //Schedule dp if new space is made
		if(cp->dp) {
			if(!list_empty(&cp->dp->lease_reqs)) {
				pa_pd_dp_schedule(pd, cp->dp);
			}
		} else {
			pa_for_each_dp_updown(dp, pd_p(pd, data), &cp->prefix) {
				if(!list_empty(&dp->lease_reqs) &&
						!dp->ignore) {
					pa_pd_dp_schedule(pd, dp);
					break;
				}
			}
		}
	}

	if(!(cpd = _pa_cpd(cp)) || (flags & (PADF_CP_TODELETE)) ) // if !cpd->lease, it will be deleted afterward anyway
		return;

#ifdef PA_PD_RIGOUROUS_LEASES
	if((flags & (PADF_CP_APPLIED)) || (cp->applied && (flags & PADF_CP_DP))) {
		pa_pd_lease_schedule(pd, cpd->lease);
	}
#else
	if(flags & (PADF_CP_APPLIED | PADF_CP_CREATED | PADF_CP_DP)) {
		pa_pd_lease_schedule(pd, cpd->lease);
	}
#endif
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

	L_INFO("Updating prefix delegation");

	/* Check for all dps if some wants to be updated */
	pa_for_each_dp(dp, &pd_pa(pd)->data) {
		if(prefix_is_ipv4(&dp->prefix))
			continue;

		L_DEBUG("Considering "PA_DP_L, PA_DP_LA(dp));
		if(dp->ignore) {
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
				if(req->lease->just_created) //That will be done later
					continue;

				bool found = false;
				/* find orphans */
				pa_pd_for_each_cpd_down(cpd, req->lease, &dp->prefix) {
					if(!cpd->cp.dp) {
						pa_pd_cpd_adopt(req, cpd);
						found = true;
						break;
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
				if(!req->dp->ignore && !pa_pd_find_prefix(req, &p, 0)) {
					pa_pd_create_cpd(req, &p);
				}
			}

			/* If all failed, better tell the requester (or it could wait forever... ) */
			if(btrie_empty(&lease->cpds))
				pa_pd_lease_schedule(pd, lease);

			lease->just_created = false;
		}
	}

	L_DEBUG("Updating prefix delegation done");
}

static void pa_pd_lease_cb(struct uloop_timeout *to)
{
	struct pa_pd_lease *lease = container_of(to, struct pa_pd_lease, cb_to);
	struct pa_cpd *cpd, *cpd2;

	L_INFO("Lease callback for "PA_PDL_L, PA_PDL_LA(lease));

	pa_pd_for_each_cpd(cpd, lease) {
		if(!cpd->cp.advertised) { //It is invalid and must be deleted
			struct pa_dp *dp = cpd->cp.dp;
			if(dp) {
				pa_cp_set_dp(&cpd->cp, NULL);
				pa_pd_req_create(cpd->lease, dp); // Add to unsatisfied
				pa_pd_dp_schedule(lease->pd, dp); // Schedule the dp for recomputation
			}
		}
	}

	if(lease->update_cb)
		lease->update_cb(lease);

	/* Remove orphan cpds */
	pa_pd_for_each_cpd_safe(cpd, cpd2, lease) {
		if(!cpd->cp.dp) {
			struct pa_pd *pd = lease->pd;
			cpd->cp.destroy(pd_p(pd, data), &cpd->cp, pd);
		} else {
			pa_cp_notify(&cpd->cp); //Do for all because maybe dp was removed before
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
	btrie_init(&lease->cpds);
	btrie_init(&lease->dp_reqs);
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

void pa_pd_lease_term(struct pa_pd *pd, struct pa_pd_lease *lease)
{
	struct pa_cpd *cpd, *cpd2;
	struct pa_pd_dp_req *req, *req2;
	if(lease->cb_to.pending && pd->started)
		uloop_timeout_cancel(&lease->cb_to);

	L_INFO("Terminating "PA_PDL_L, PA_PDL_LA(lease));

	pa_pd_for_each_cpd_safe(cpd, cpd2, lease) {
		btrie_remove(&cpd->lease_be);
		cpd->lease = NULL;
		pa_cp_todelete(&cpd->cp);
		pa_cpd_set_lease(cpd, NULL); //Important to differentiate local deletes
		pa_cp_notify(&cpd->cp);
	}

	pa_for_each_req_in_lease_safe(req, req2, lease) {
		pa_pd_req_destroy(req);
	}

	list_del(&lease->le);
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
	INIT_LIST_HEAD(&pd->leases);
	if(conf)
		pd->conf = *conf;
	else
		pa_pd_conf_defaults(&pd->conf);
	memset(&pd->data_user, 0, sizeof(struct pa_data_user));
	pd->data_user.dps = pa_pd_dps_cb;
	pd->data_user.cps = pa_pd_cps_cb;
	pd->data_user.aps = pa_pd_aps_cb;
	pd->update.cb = pa_pd_update_cb;
	pd->update.pending = false;
	pd->started = false;
}

void pa_pd_start(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(!pd->started) {
		L_NOTICE("Starting pa_pd");
		pd->started = true;
		pa_pd_to_start(&pd->update, PA_PD_UPDATE_DELAY);
		pa_data_subscribe(&pd_pa(pd)->data, &pd->data_user);
		pa_data_register_cp(&pd_pa(pd)->data, PA_CPT_D, pa_pd_destroy_cpd);
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
	struct pa_pd_lease *lease, *lease2;
	pa_pd_stop(pd);

	pa_pd_for_each_lease_safe(lease, lease2, pd) {
		pa_pd_lease_term(pd, lease);
	}
}
