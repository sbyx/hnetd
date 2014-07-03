/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 */

#include "pa_pd.h"
#include "pa.h"

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_pd - "

#define PA_PD_DFLT_MIN_LEN 62
#define PA_PD_DFLT_RATIO_EXP 3

#define PA_PD_FINDRAND_N 256
#define PA_PD_PSEUDORAND_TENTATIVES 10

#define PA_PD_PREFIX_SEARCH_MAX_ROUNDS 64 //Done for each tested prefix length

#define PA_PD_LEASE_CB_DELAY 100
#define PA_PD_UPDATE_DELAY   40
#define PA_PD_UPDATE_RATE_DELAY 1500 //Limit DP-wide update
#define PA_PD_UPDATE_TOLERANCE  1000 //Do multiple things at the same uloop call if possible

#define pd_pa(_pd) (container_of(_pd, struct pa, pd))
#define pd_p(_pd, field) (&(pd_pa(_pd)->field))

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

static int pa_pd_find_prefix(struct pa_pd_dp_req *req, struct prefix *dst,
		uint16_t *prefix_count)
{
	int i;
	uint8_t min_len = req->min_len;
	uint8_t max_len = req->max_len;

	/* Let's see if we can give a big enough pd */
	uint8_t plen = 254;
	for(i = 0; i <= max_len; i++) {
		if(prefix_count[i]) {
			plen = i;
			break;
		}
	}

	if(plen > max_len)
		return -1;

	if(plen < min_len) //Not gonna give to much
		plen = min_len;

	/* Let's now select the best prefixes to give-away */
	uint32_t count;
	min_len = pa_count_available_subset(prefix_count, plen, &count, PA_PD_FINDRAND_N);


	if(!count) {
		L_INFO("No more available prefix of length %d could be found in %s", plen, PREFIX_REPR(&req->dp->prefix));
		return -1;
	}
	L_DEBUG("At least %d available prefixes of length %d have been found in %s", (int)count, plen, PREFIX_REPR(&req->dp->prefix));

	/* First try the pseudo-random prefixes */
	struct prefix tentative;
	i = 0;
	do {
		prefix_prandom(req->lease->lease_id, strlen(req->lease->lease_id), (uint32_t) i, &req->dp->prefix, &tentative, plen);
		L_DEBUG("Trying pseudo-random prefix %s", PREFIX_REPR(&tentative));
		pa_for_each_available_prefix_first(pd_p(req->lease->pd, data), &tentative, req->dp->prefix.plen, dst) {
			//todo: No need for a loop here, should use first result call.
			if(dst->plen <= plen && dst->plen >= min_len && prefix_contains(dst, &tentative)) {
				pa_count_available_decrement(prefix_count, tentative.plen, dst->plen);
				prefix_cpy(dst, &tentative);
				goto chosen;
			}
			break;
		}
		L_DEBUG("This prefix is not available");
	} while(++i < PA_PD_PSEUDORAND_TENTATIVES);

	i = random() % count;
	L_DEBUG("Choosing a random prefix (%dth available prefix)", (int) (i+1));
	/* Go through available prefixes starting by the chosen one */
	pa_for_each_available_prefix(pd_p(req->lease->pd, data), &req->dp->prefix, dst) {
		if(dst->plen <= plen && dst->plen >= min_len) {
			if((plen - dst->plen >= 32)
					|| i < (1 << (plen - dst->plen))) {
				//We choose the i'th prefix in there
				uint8_t id_len = plen - dst->plen;
				prefix_canonical(dst, dst);
				pa_count_available_decrement(prefix_count, plen, dst->plen);
				if(id_len) {
					dst->plen = plen;
					prefix_number(dst, dst, (uint32_t) i, id_len);
				}
				goto chosen;
			}
			i -= (1 << (plen - dst->plen));
		}
	}
	L_ERR("Prefix random selection error (Program should not execute this line !)");
	return -1; //Should never come here
	chosen:
	L_DEBUG("Prefix %s is available", PREFIX_REPR(dst));
	return 0;
}

static void pa_pd_lease_schedule(struct pa_pd_lease *lease)
{
	pa_timer_set_earlier(&lease->timer, PA_PD_LEASE_CB_DELAY, true);
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

	pa_timer_set_earlier(&pd->timer, delay, true);
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
		pa_pd_lease_schedule(cpd->lease);
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
		if(!list_empty(&pd->leases))
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

static void pa_pd_update_cb(struct pa_timer *t)
{
	struct pa_pd *pd = container_of(t, struct pa_pd, timer);
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

			uint16_t prefix_count[129];
			pa_count_available_prefixes(pd_pa(pd), prefix_count, &dp->prefix);

			/* Try to satisfy unsatisfied */
			//uint8_t min_len = 0;
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
				if(!pa_pd_find_prefix(req, &p, prefix_count))
					pa_pd_create_cpd(req, &p);

			}
			dp->compute_leases_last = now;
		}
	}

	/* Populate just-created leases */
	pa_pd_for_each_lease(lease, pd) {
		if(lease->just_created) {
			pa_for_each_req_in_lease_safe(req, req2, lease) {
				if(req->dp->ignore)
					continue;

				uint16_t prefix_count[129];
				pa_count_available_prefixes(pd_pa(pd), prefix_count, &req->dp->prefix);

				struct prefix p;
				if(!pa_pd_find_prefix(req, &p, prefix_count))
					pa_pd_create_cpd(req, &p);
			}

			/* If all failed, better tell the requester (or it could wait forever... ) */
			if(btrie_empty(&lease->cpds))
				pa_pd_lease_schedule(lease);

			lease->just_created = false;
		}
	}

	L_DEBUG("Updating prefix delegation done");
}

static void pa_pd_lease_cb(struct pa_timer *t)
{
	struct pa_pd_lease *lease = container_of(t, struct pa_pd_lease, timer);
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

	pa_timer_init(&lease->timer, pa_pd_lease_cb, "Prefix Delegation Lease");
	if(pd->timer.enabled)
		pa_timer_enable(&lease->timer);

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
	pa_timer_set_earlier(&pd->timer, PA_PD_UPDATE_DELAY, true);

	return 0;
}

void pa_pd_lease_term(__attribute__((unused))struct pa_pd *pd, struct pa_pd_lease *lease)
{
	struct pa_cpd *cpd, *cpd2;
	struct pa_pd_dp_req *req, *req2;

	pa_timer_disable(&lease->timer);

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

	pa_timer_init(&pd->timer, pa_pd_update_cb, "Prefix Delegation");
}

void pa_pd_start(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(!pd->timer.enabled) {
		L_NOTICE("Starting pa_pd");
		pa_timer_enable(&pd->timer);
		if(!list_empty(&pd->leases))
			pa_timer_set_earlier(&pd->timer, PA_PD_UPDATE_DELAY, true);

		pa_data_subscribe(&pd_pa(pd)->data, &pd->data_user);
		pa_data_register_cp(&pd_pa(pd)->data, PA_CPT_D, pa_pd_destroy_cpd);
		list_for_each_entry(lease, &pd->leases, le) {
			pa_timer_enable(&lease->timer);
			pa_timer_set_earlier(&lease->timer, PA_PD_LEASE_CB_DELAY, true);
		}
	}
}

void pa_pd_stop(struct pa_pd *pd)
{
	struct pa_pd_lease *lease;
	if(pd->timer.enabled) {
		L_NOTICE("Stopping pa_pd");
		list_for_each_entry(lease, &pd->leases, le)
			pa_timer_disable(&lease->timer);

		pa_data_unsubscribe(&pd->data_user);
		pa_timer_disable(&pd->timer);
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
