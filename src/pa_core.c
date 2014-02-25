#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_core - "

#include "pa_core.h"
#include "pa.h"
#include "iface.h"

#define PA_CORE_MIN_DELAY 3
#define PA_CORE_DELAY_FACTOR 10

#define PA_CORE_PREFIX_SEARCH_MAX_ROUNDS 256
#define PA_CORE_ADDRESS_SEARCH_MAX_ROUNDS 256

#define core_pa(core) (container_of(core, struct pa, core))
#define core_rid(core) (&((core_pa(core))->flood.rid))
#define core_p(core, field) (&(core_pa(core)->field))

#define PA_CORE_CHECK_DELAY(delay) do { \
	if(delay < PA_CORE_MIN_DELAY) \
		delay = PA_CORE_MIN_DELAY; \
	else if(delay > UINT32_MAX) \
		delay = UINT32_MAX; \
	} while(0)

static void __pa_aaa_schedule(struct pa_core *core);
static void __pa_paa_schedule(struct pa_core *core);

bool __pa_compute_dodhcp(struct pa_iface *iface)
{
	if(!iface->designated)
		return false;

	struct pa_cp *cp;
	pa_for_each_cp_in_iface(cp, iface) {
		if(cp->applied)
			return true;
	}

	return false;
}

void __pa_update_dodhcp(struct pa_core *core, struct pa_iface *iface)
{
	pa_iface_set_dodhcp(iface, __pa_compute_dodhcp(iface));
	pa_iface_notify(core_p(core, data), iface);
}

void __pa_cp_apply_cb(struct uloop_timeout *to)
{
	struct pa_cp *cp = container_of(to, struct pa_cp, apply_to);
	L_DEBUG("Apply callback for "PA_CP_L, PA_CP_LA(cp));
	pa_cp_set_applied(cp, true);
	pa_cp_notify(cp);
	if(cp->iface)
		__pa_update_dodhcp(&container_of(cp->pa_data, struct pa, data)->core, cp->iface);
}

void __pa_laa_apply_cb(struct uloop_timeout *to)
{
	struct pa_laa *laa = container_of(to, struct pa_laa, apply_to);
	L_DEBUG("Apply callback for "PA_AA_L, PA_AA_LA(&laa->aa));
	pa_laa_set_applied(laa, true);
	pa_aa_notify(laa->cp->pa_data, &laa->aa);
}

/* Accepting an ap */
static void pa_core_accept_ap(struct pa_core *core, struct pa_ap *ap, struct pa_dp *dp, bool advertise)
{
	L_INFO("Accepting "PA_AP_L, PA_AP_LA(ap));

	if(!ap->iface) {
		L_WARN("Can't accept "PA_AP_L" because it has no interface", PA_AP_LA(ap));
		return;
	}

	struct pa_cp *cp = pa_cp_get(core_p(core, data), &ap->prefix, true);

	pa_cp_set_iface(cp, ap->iface);
	pa_cp_set_priority(cp, ap->priority);
	pa_cp_set_authoritative(cp, false);
	pa_cp_set_dp(cp, dp);
	pa_cp_set_advertised(cp, advertise);
	pa_cp_notify(cp);

	cp->apply_to.cb = __pa_cp_apply_cb;
	uloop_timeout_set(&cp->apply_to, 2*core_p(core, data.flood)->flooding_delay);
}

static void pa_core_update_cp(struct pa_dp *dp, struct pa_ap *ap, struct pa_cp *cp, bool advertise)
{
	L_INFO("Updating "PA_CP_L" with "PA_AP_L, PA_CP_LA(cp), PA_AP_LA(ap));

	pa_cp_set_dp(cp, dp);
	pa_cp_set_priority(cp, ap->priority);
	pa_cp_set_advertised(cp, advertise);
	pa_cp_notify(cp);
}

static void pa_core_create_cp(struct pa_core *core, const struct prefix *p,
		struct pa_dp *dp, struct pa_iface *iface,
		bool authority, uint8_t priority)
{
	struct pa_cp *cp = pa_cp_get(core_p(core, data), p, true);

	if(!cp) {
		L_WARN("Can't create "PA_CP_L" because it already exists", PA_CP_LA(cp));
		return;
	}

	L_INFO("Creating new "PA_CP_L, PA_CP_LA(cp));

	pa_cp_set_iface(cp, iface);
	pa_cp_set_priority(cp, priority);
	pa_cp_set_authoritative(cp, authority);
	pa_cp_set_dp(cp, dp);
	pa_cp_set_advertised(cp, true);
	pa_cp_notify(cp);

	cp->apply_to.cb = __pa_cp_apply_cb;
	uloop_timeout_set(&cp->apply_to, 2*core_p(core, data.flood)->flooding_delay);
}

static struct prefix *__pa_core_prefix_getcollision(struct pa_core *core, const struct prefix *prefix)
{
	struct pa_ap *ap;
	pa_for_each_ap(ap, core_p(core, data)) {
		if(prefix_contains(prefix, &ap->prefix) || prefix_contains(&ap->prefix, prefix)) {
			return &ap->prefix;
		}
	}

	struct pa_cp *cp;
	pa_for_each_cp(cp, core_p(core, data)) {
		if(prefix_contains(prefix, &cp->prefix) || prefix_contains(&cp->prefix, prefix)) {
			return &cp->prefix;
		}
	}

	return NULL;
}

static int pa_getprefix_random(struct pa_core *core,
		struct pa_dp *dp, struct prefix *new_prefix) {

	int res;
	bool looped;
	uint32_t rounds;
	uint8_t plen;
	struct prefix *collision;


	/* Selecting required prefix length */
	if(dp->prefix.plen < 64) {
		plen = 64;
	} else if (dp->prefix.plen < 104) {
		plen = dp->prefix.plen + 16;
	} else if (dp->prefix.plen < 112) {
		plen = 120;
	} else if (dp->prefix.plen <= 128) { //IPv4
		plen = 120 + (dp->prefix.plen - 112)/2;
	} else {
		L_ERR("Invalid prefix length (%d)", dp->prefix.plen);
		return -1;
	}

	/* The router first choose a random prefix. Then it iterates over all
	 * the next prefixes, with a limit of PA_PREFIX_SEARCH_MAX_ROUNDS iterations. */
	if(plen - dp->prefix.plen >= 32 || (rounds = 1 << (plen - dp->prefix.plen)) >= PA_CORE_PREFIX_SEARCH_MAX_ROUNDS) {
		rounds = PA_CORE_PREFIX_SEARCH_MAX_ROUNDS;
	}

	looped = false;
	prefix_random(&dp->prefix, new_prefix, plen);
	for(; rounds; rounds--) {

		if(!(collision = __pa_core_prefix_getcollision(core, new_prefix)))
			return 0;

		L_DEBUG("Prefix %s can't be used", PREFIX_REPR(new_prefix));

		if(prefix_contains(new_prefix, collision)) {
			if((res = prefix_increment(new_prefix, new_prefix, dp->prefix.plen)) == -1)
				return -1;
		} else if(prefix_contains(collision, new_prefix)) {
			if((res = prefix_increment(new_prefix, collision, dp->prefix.plen)) == -1)
				return -1;
			new_prefix->plen = plen;
		}

		if(res) {
			if(looped)
				return -1;
			looped = true;
		}
	}

	return -1;
}

static const struct prefix * pa_getprefix_storage(struct pa_core *core, struct pa_iface *iface,
		struct pa_dp *dp) {

	struct pa_sp *sp;
	pa_for_each_sp_in_iface(sp, iface) {
		if(prefix_contains(&dp->prefix, &sp->prefix) &&
					!__pa_core_prefix_getcollision(core, &sp->prefix))
			return &sp->prefix;
	}

	return NULL;
}

static void pa_core_make_new_assignment(struct pa_core *core, struct pa_dp *dp, struct pa_iface *iface)
{
	const struct prefix *p;
	struct prefix np;

	/* Get from storage */
	p = pa_getprefix_storage(core, iface, dp);

	/* If no storage */
	if(!p && !pa_getprefix_random(core, dp, &np))
		p = &np;

	if(p)
		pa_core_create_cp(core, p, dp, iface, 0, PA_PRIORITY_DEFAULT);
}

static void pa_core_destroy_cp(struct pa_core *core, struct pa_cp *cp)
{
	L_INFO("Removing "PA_CP_L, PA_CP_LA(cp));

	/* Remove the address if needed */
	if(cp->laa) {
		pa_aa_todelete(&cp->laa->aa);
		pa_aa_notify(core_p(core, data), &cp->laa->aa);
	}

	/* Delete the cp */
	pa_cp_todelete(cp);
	pa_cp_notify(cp);
}

static bool pa_core_dp_ignore(struct pa_core *core, struct pa_dp *dp)
{
	struct pa_data *data = core_p(core, data);
	struct pa_dp *dp2;
	bool seen = false;
	pa_for_each_dp(dp2, data) {
		if(dp2 == dp) {
			seen = true;
			continue;
		}

		if((!seen && !prefix_cmp(&dp->prefix, &dp2->prefix))
				|| prefix_contains(&dp->prefix, &dp2->prefix))
			return true;
	}
	return false;
}

static bool pa_core_iface_is_designated(struct pa_core *core, struct pa_iface *iface)
{
	struct pa_cp *cp, *best_cp;
	struct pa_ap *ap;

	if(list_empty(&iface->aps))
		return true;

	if(list_empty(&iface->cps))
		return false;

	/* Get cp with lowest auth. and priority. */
	best_cp = NULL;
	pa_for_each_cp_in_iface(cp, iface) {
		if(!best_cp
				|| best_cp->authoritative > cp->authoritative
				|| ((best_cp->authoritative == cp->authoritative) && best_cp->priority > cp->priority))
			best_cp = cp;
	}

	/* Compare with all aps on that iface */
	pa_for_each_ap_in_iface(ap, iface) {
		if(ap->authoritative < best_cp->authoritative) {
			return false;
		} else if(ap->authoritative == best_cp->authoritative) {
			if(ap->priority < best_cp->priority) {
				return false;
			} else if (ap->priority == best_cp->priority && (PA_RIDCMP(core_p(core, data.flood.rid), &ap->rid) < 0) ) {
				return false;
			}
		}
	}

	return true;
}

static struct pa_cp *pa_core_getcp(struct pa_dp *dp, struct pa_iface *iface)
{
	struct pa_cp *cp;

	pa_for_each_cp_in_iface(cp, iface) {
		if(cp->dp == dp || prefix_contains(&dp->prefix, &cp->prefix))
			return cp;
	}

	return NULL;
}

static int pa_core_precedence(bool auth1, uint8_t prio1, struct pa_rid *rid1,
		bool auth2, uint8_t prio2, struct pa_rid *rid2) {
	if(auth1 > auth2)
		return 1;

	if(auth1 < auth2)
		return -1;

	if(prio1 > prio2)
		return 1;

	if(prio2 > prio1)
		return -1;

	return PA_RIDCMP(rid1, rid2);
}


static int pa_core_precedence_apap(struct pa_ap *ap1, struct pa_ap *ap2)
{
	return pa_core_precedence(ap1->authoritative, ap1->priority, &ap1->rid,
			ap2->authoritative, ap2->priority, &ap2->rid);
}

static int pa_core_precedence_apcp(struct pa_ap *ap, struct pa_cp *cp)
{
	return pa_core_precedence(ap->authoritative, ap->priority, &ap->rid,
			cp->authoritative, cp->priority, &cp->pa_data->flood.rid);
}

static bool pa_core_cp_check_global_validity(struct pa_core *core, struct pa_cp *cp)
{
	struct pa_ap *ap_iter;

	pa_for_each_ap(ap_iter, core_p(core, data)) {
		if(pa_core_precedence_apcp(ap_iter, cp) > 0
				&& (prefix_contains(&ap_iter->prefix, &cp->prefix) || prefix_contains(&cp->prefix, &ap_iter->prefix)))
			return false;
	}

	return true;
}

static bool pa_core_ap_check_global_validity(struct pa_core *core, struct pa_ap *ap)
{
	struct pa_ap *ap_iter;

	pa_for_each_ap(ap_iter, core_p(core, data)) {
		if(ap != ap_iter
				&& pa_core_precedence_apap(ap_iter, ap) > 0
				&& (prefix_contains(&ap_iter->prefix, &ap->prefix) || prefix_contains(&ap->prefix, &ap_iter->prefix)))
			return false;
	}

	return true;
}

static struct pa_ap *pa_core_getap(struct pa_core *core, struct pa_dp *dp, struct pa_iface *iface, struct pa_cp *cp)
{
	/* Retrieve a valid ap for that dp */
	struct pa_ap *ap = NULL;
	struct pa_ap *ap_iter;

	/* Get the highest priority on that interface */
	pa_for_each_ap_in_iface(ap_iter, iface) {
		if(prefix_contains(&dp->prefix, &ap_iter->prefix)
				&& (!ap || pa_core_precedence_apap(ap_iter, ap) > 0)
				&& pa_core_ap_check_global_validity(core, ap_iter))
				ap = ap_iter;
	}

	if(cp && ap && pa_core_precedence_apcp(ap, cp) < 0)
		return NULL;

	return ap;
}

static inline void pa_core_case1(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp)
{
	if(iface->designated)
		pa_core_make_new_assignment(core, dp, iface);
}

static inline void pa_core_case2(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_ap *ap)
{
	pa_core_accept_ap(core, ap, dp, iface->designated);
}

static inline void pa_core_case3(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_cp *cp)
{
	if(pa_core_cp_check_global_validity(core, cp)) {
		cp->invalid = false;
		pa_cp_set_advertised(cp, true);
		pa_cp_set_dp(cp, dp);
		pa_cp_notify(cp);
	} else {
		pa_core_destroy_cp(core, cp);
		pa_core_case1(core, iface, dp);
	}
}

static inline void pa_core_case4(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_ap *ap, struct pa_cp *cp)
{
	if(prefix_cmp(&ap->prefix, &cp->prefix)) {
		if(!cp->authoritative) {
			pa_core_destroy_cp(core, cp);
			pa_core_case2(core, iface, dp, ap);
		}
		//Valid otherwise
	} else {
		pa_core_update_cp(dp, ap, cp, iface->designated);
		cp->invalid = false;
	}
}

void paa_algo_do(struct pa_core *core)
{
	struct pa_data *data = core_p(core, data);
	struct pa_dp *dp;
	struct pa_iface *iface;
	struct pa_cp *cp;
	struct pa_ap *ap;

	L_INFO("Executing prefix assignment algorithm");

	/* Mark all prefixes as invalid */
	pa_for_each_cp(cp, data)
		cp->invalid = !cp->authoritative;

	/* Compute designated */
	pa_for_each_iface(iface, data)
		iface->designated = pa_core_iface_is_designated(core, iface);

	pa_for_each_dp(dp, data) {

		if(pa_core_dp_ignore(core, dp))
			continue;

		L_DEBUG("Considering "PA_DP_L, PA_DP_LA(dp));

		pa_for_each_iface(iface, data) {

			if(!iface->internal)
				continue;

			cp = pa_core_getcp(dp, iface);
			ap = pa_core_getap(core, dp, iface, cp);

			if(cp) {
				if(ap)
					pa_core_case4(core, iface, dp, ap, cp);
				else
					pa_core_case3(core, iface, dp, cp);
			} else {
				if(ap)
					pa_core_case2(core, iface, dp, ap);
				else
					pa_core_case1(core, iface, dp);
			}

		}
	}

	/* Remove invalid cps */
	struct pa_cp *cpsafe;
	list_for_each_entry_safe(cp, cpsafe, &data->cps, le) {
		if(cp->invalid)
			pa_core_destroy_cp(core, cp);
	}

	/* Evaluate dodhcp ofr all iface */
	pa_for_each_iface(iface, data)
		__pa_update_dodhcp(core, iface);

	L_INFO("End of prefix assignment algorithm");
}

static bool __aaa_addr_available(struct pa_core *core, struct pa_iface *iface, const struct in6_addr *addr)
{
	struct pa_eaa *eaa;

	if(core_p(core, data)->flood.aa_ll_enabled && iface) {
		pa_for_each_eaa_in_iface(eaa, iface) {
			if(!memcmp(&eaa->aa.address, addr, sizeof(struct in6_addr)))
				return false;
		}
	} else {
		pa_for_each_eaa(eaa, core_p(core, data)) {
			if(!memcmp(&eaa->aa.address, addr, sizeof(struct in6_addr)))
				return false;
		}
	}

	struct pa_cp *cp;
	pa_for_each_cp(cp, core_p(core, data)) {
		if(cp->laa && !memcmp(&cp->laa->aa.address, addr, sizeof(struct in6_addr)))
			return false;
	}

	return true;
}

static int __aaa_from_storage(struct pa_core *core, struct pa_cp *cp, struct in6_addr *addr)
{
	struct pa_sa *sa;
	struct prefix p;
	pa_for_each_sa(sa, core_p(core, data)) {
		p.plen = 128;
		memcpy(&p.prefix, &sa->addr, sizeof(struct in6_addr));
		if(prefix_contains(&cp->prefix, &p) && __aaa_addr_available(core, cp->iface, &sa->addr)) {
			memcpy(addr, &sa->addr, sizeof(struct in6_addr));
			return 0;
		}
	}
	return -1;
}

static inline int __aaa_do_slaac(struct pa_cp *cp, struct in6_addr *addr)
{
	struct iface *iface;
	struct prefix can;

	if(cp->prefix.plen > 64 || !cp->iface || !(iface = iface_get(cp->iface->ifname)))
		return -1;

	prefix_canonical(&can, &cp->prefix);
	memcpy(addr, &can.prefix, sizeof(struct in6_addr));
	memcpy(&addr->s6_addr[8], &iface->eui64_addr.s6_addr[8], 8);
	return 0;
}

static inline int __aaa_find_random(struct pa_core *core, struct pa_cp *cp, struct in6_addr *addr)
{
	uint32_t rounds;
	uint8_t diff;
	struct prefix rpool, result;
	int res;

	/* Get routers pool */
	prefix_canonical(&rpool, &cp->prefix);
	if(cp->prefix.plen <= 64) {
		rpool.plen = 64;
	} else if (cp->prefix.plen <= 110) {
		rpool.plen = 112;
	} else if (cp->prefix.plen < 126) {
		rpool.plen = cp->prefix.plen + 2;
	} else if(!cp->iface || pa_core_iface_is_designated(core, cp->iface)) {
		/* Only the designated router can get the only address */
		memcpy(addr, &rpool.prefix, sizeof(struct in6_addr));
		return 0;
	} else {
		return -1;
	}

	/* Selecting rounds duration */
	diff = 128 - rpool.plen;
	if(diff >= 32 || (rounds = 1 << diff) >= PA_CORE_PREFIX_SEARCH_MAX_ROUNDS)
		rounds = PA_CORE_PREFIX_SEARCH_MAX_ROUNDS;

	bool looped = false;
	prefix_random(&rpool, &result, 128);
	for(; rounds; rounds--) {

		/* The first condition is intended to forbid the use of the network address
		 * in the case of IPv4. */
		if((!prefix_is_ipv4(&rpool)
					|| memcmp(&rpool.prefix, &result.prefix, sizeof(struct in6_addr)))
				&& __aaa_addr_available(core, cp->iface, &result.prefix)) {
			memcpy(addr, &result.prefix, sizeof(struct in6_addr));
			return 0;
		}
		if((res = prefix_increment(&result, &result, rpool.plen)) == -1)
			return -1;

		if(res) {
			if(looped)
				return -1;
			looped = true;
		}
	}
	return -1;
}

static bool __aaa_valid(struct pa_core *core, struct in6_addr *addr)
{
	struct pa_eaa *eaa;
	pa_for_each_eaa(eaa, core_p(core, data)) {
		if(!memcmp(&eaa->aa.address, addr, sizeof(struct in6_addr)) && PA_RIDCMP(&eaa->rid, &core_p(core, data)->flood.rid) > 0)
			return false;
	}
	/* No need to check for local because we only give one per cp (won't be true if too much authoritary... )*/
	return true;
}

static void aaa_algo_do(struct pa_core *core)
{
	struct pa_data *data = core_p(core, data);
	struct pa_cp *cp;
	struct pa_laa *laa;
	struct in6_addr addr;

	L_INFO("Executing address assignment algorithm");

	pa_for_each_cp(cp, data) {
		/* Delete if invalid */
		if(cp->laa && (!__aaa_valid(core, &cp->laa->aa.address) || !cp->iface)) {
			pa_aa_todelete(&cp->laa->aa);
			pa_aa_notify(data, &cp->laa->aa);
		}

		/* Create new if no assigned */
		if(!cp->laa && cp->iface) {
			if(!__aaa_from_storage(core, cp, &addr) || !__aaa_do_slaac(cp, &addr) || !__aaa_find_random(core, cp, &addr)) {
				laa = pa_laa_create(&addr, cp);
				if(laa) {
					pa_aa_notify(data, &laa->aa);
					laa->apply_to.cb = __pa_laa_apply_cb;
					if(cp->prefix.plen <= 64) {
						//Immediate assignment
						uloop_timeout_set(&laa->apply_to, 0);
					} else {
						uloop_timeout_set(&laa->apply_to, 2*core_p(core, data.flood)->flooding_delay_ll);
					}
				} else {
					L_WARN("Could not create laa from address %s", ADDR_REPR(&addr));
				}
			} else {
				L_WARN("Could not find address for "PA_CP_L, PA_CP_LA(cp));
			}
		}
	}
}

void pa_core_update_excluded(struct pa_core *core, struct pa_ldp *ldp)
{
	struct pa_cp *cp, *cp2;

	if(ldp->excluded.cp) {
		/* Destroying previous cp */
		pa_core_destroy_cp(core, ldp->excluded.cp);
		ldp->excluded.cp = NULL;
	}

	if(ldp->excluded.valid) {
		/* Invalidate all contained cps */
		pa_for_each_cp_safe(cp, cp2, core_p(core, data)) {
			if(!cp->authoritative &&
					(prefix_contains(&cp->prefix, &ldp->excluded.excluded) ||
							prefix_contains(&ldp->excluded.excluded, &cp->prefix))) {
				pa_cp_todelete(cp);
				pa_cp_notify(cp); /* No loop... Hopefully */
				__pa_paa_schedule(core);
			}
		}
		//todo: When no cp is deleted, we don't need to execute paa, but in case of scarcity, it may be usefull
		/* Creating new cp */
		ldp->excluded.cp = pa_cp_get(core_p(core, data), &ldp->excluded.excluded, true);
		pa_cp_set_authoritative(ldp->excluded.cp, true);
		pa_cp_notify(ldp->excluded.cp);
	}
}

static void __pa_paa_to_cb(struct uloop_timeout *to)
{
	struct pa_core *core = container_of(to, struct pa_core, paa.to);
	core->paa.scheduled = false;
	paa_algo_do(core);
}

static void __pa_aaa_to_cb(struct uloop_timeout *to)
{
	struct pa_core *core = container_of(to, struct pa_core, aaa.to);
	core->aaa.scheduled = false;
	aaa_algo_do(core);
}

static void __pa_paa_schedule(struct pa_core *core)
{
	if(core->paa.scheduled)
		return;

	core->paa.scheduled = true;
	if(!core->start_time || core->paa.to.pending)
		return;

	hnetd_time_t flood = core_p(core, data)->flood.flooding_delay;
	hnetd_time_t delay = flood / PA_CORE_DELAY_FACTOR;
	hnetd_time_t now = hnetd_time();

	if(now + delay < core->start_time + flood)
		delay = core->start_time + flood - now;

	PA_CORE_CHECK_DELAY(delay);
	L_DEBUG("Scheduling prefix assignment algorithm in %d ms", (int) delay);
	uloop_timeout_set(&core->paa.to, (int) delay);
}

static void __pa_aaa_schedule(struct pa_core *core)
{
	if(core->aaa.scheduled)
		return;

	core->aaa.scheduled = true;
	if(!core->start_time || core->aaa.to.pending)
		return;

	hnetd_time_t delay = core_p(core, data)->flood.flooding_delay_ll / PA_CORE_DELAY_FACTOR;
	PA_CORE_CHECK_DELAY(delay);
	L_DEBUG("Scheduling address assignment algorithm in %d ms", (int) delay);
	uloop_timeout_set(&core->aaa.to, (int) delay);
}

/************* Callbacks for pa_data ********************************/

static void __pad_cb_flood(struct pa_data_user *user,
		__attribute__((unused))struct pa_flood *flood, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(flags & PADF_FLOOD_RID) {
		__pa_aaa_schedule(core);
		__pa_paa_schedule(core);
	}

	//todo PADF_FLOOD_DELAY case
}

static void __pad_cb_ifs(struct pa_data_user *user,
		__attribute__((unused))struct pa_iface *iface, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(flags & (PADF_IF_CREATED | PADF_IF_INTERNAL | PADF_IF_TODELETE))
		__pa_paa_schedule(core);
}

static void __pad_cb_dps(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	struct pa_cp *cp;
	if(flags & (PADF_DP_CREATED | PADF_DP_TODELETE))
		__pa_paa_schedule(core);

	if(flags & PADF_DP_TODELETE) {
		/* Need to make assignments orphans */
		while(!(list_empty(&dp->cps))) {
			cp = list_first_entry(&dp->cps, struct pa_cp, dp_le);
			pa_cp_set_dp(cp, NULL);
			pa_cp_notify(cp);
		}
	}

	if((flags & PADF_DP_CREATED) && !pa_core_dp_ignore(core, dp)) {
		/* Remove orphans if possible */
		pa_for_each_cp(cp, core_p(core, data)) {
			if(!cp->dp && prefix_contains(&dp->prefix, &cp->prefix)) {
				pa_cp_set_dp(cp, dp);
				pa_cp_notify(cp);
			}
		}
	}

	if(dp->local && (flags & PADF_LDP_EXCLUDED))
		pa_core_update_excluded(core, container_of(dp, struct pa_ldp, dp));
}

static void __pad_cb_aps(struct pa_data_user *user,
		__attribute__((unused))struct pa_ap *ap, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(flags & (PADF_AP_CREATED | PADF_AP_TODELETE | PADF_AP_IFACE | PADF_AP_AUTHORITY | PADF_AP_PRIORITY))
		__pa_paa_schedule(core);
}

static void __pad_cb_aas(struct pa_data_user *user, struct pa_aa *aa, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(!aa->local && (flags & (PADF_AA_CREATED | PADF_AA_TODELETE | PADF_EAA_IFACE)))
			__pa_aaa_schedule(core);
}

static void __pad_cb_cps(struct pa_data_user *user,
		struct pa_cp *cp, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(!(flags & PADF_CP_TODELETE) && (flags & PADF_CP_CREATED) &&
			(cp->iface || (!cp->iface && (flags & PADF_CP_IFACE))))
		__pa_aaa_schedule(core);
}

/************* Control functions ********************************/

void pa_core_init(struct pa_core *core)
{
	L_INFO("Initializing pa core structure");

	core->start_time = 0;

	core->paa.scheduled = false;
	core->paa.to.pending = false;
	core->paa.to.cb = __pa_paa_to_cb;

	core->aaa.scheduled = false;
	core->aaa.to.pending = false;
	core->aaa.to.cb = __pa_aaa_to_cb;

	memset(&core->data_user, 0, sizeof(struct pa_data_user));
	core->data_user.aas = __pad_cb_aas;
	core->data_user.aps = __pad_cb_aps;
	core->data_user.dps = __pad_cb_dps;
	core->data_user.ifs = __pad_cb_ifs;
	core->data_user.flood = __pad_cb_flood;
	core->data_user.cps = __pad_cb_cps;
}

void pa_core_start(struct pa_core *core)
{
	if(core->start_time)
		return;

	L_INFO("Starting pa core structure");
	pa_data_subscribe(core_p(core, data), &core->data_user);
	core->start_time = hnetd_time();

	/* Always schedule when started */
	core->paa.scheduled = false;
	__pa_paa_schedule(core);

	core->aaa.scheduled = false;
	__pa_aaa_schedule(core);
}

void pa_core_stop(struct pa_core *core)
{
	if(!core->start_time)
		return;

	L_INFO("Stopping pa core structure");
	core->start_time = 0;
	core->paa.scheduled = false;
	core->aaa.scheduled = false;
	if(core->paa.to.pending)
		uloop_timeout_cancel(&core->paa.to);

	if(core->aaa.to.pending)
		uloop_timeout_cancel(&core->aaa.to);

	pa_data_unsubscribe(&core->data_user);
}

void pa_core_term(struct pa_core *core)
{
	L_INFO("Terminating pa core structure");
	pa_core_stop(core);
	//todo: properly destroy cps and laas
}



