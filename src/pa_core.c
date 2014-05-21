/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 */

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_core - "

#include "pa_core.h"
#include "pa.h"
#include "iface.h"

#define PA_CORE_MIN_DELAY 3
#define PA_CORE_DELAY_FACTOR 10

#define PA_CORE_FINDRAND_N 64

#define PAC_PRAND_PRFX 0
#define PAC_PRAND_ADDR 1

#define core_pa(c) (container_of(c, struct pa, core))
#define core_rid(core) (&((core_pa(core))->flood.rid))
#define core_p(core, field) (&(core_pa(core)->field))

#define __pa_paa_schedule(c) pa_timer_set_earlier(&(c)->paa_to, core_p((c), data)->flood.flooding_delay / PA_CORE_DELAY_FACTOR, true)
#define __pa_aaa_schedule(c) pa_timer_set_earlier(&(c)->aaa_to, core_p((c), data)->flood.flooding_delay_ll / PA_CORE_DELAY_FACTOR, true)

static int pa_core_invalidate_cps(struct pa_core *core, struct prefix *prefix, bool delete_auth,
		struct pa_cpl *except);

/* Generates a random or pseudo-random (based on the interface) prefix */
int pa_prefix_prand(struct pa_iface *iface, size_t ctr_index,
		const struct prefix *p, struct prefix *dst,
		uint8_t plen)
{
	struct iface *i;
	char seed[IFNAMSIZ + 10];
	size_t pos = 0;

	if((i = iface_get(iface->ifname))) {
		memcpy(seed, &i->eui64_addr.s6_addr[8], 8);
		pos += sizeof(struct in6_addr);
	}

	memcpy(seed + pos, iface->ifname, strlen(iface->ifname));
	pos += strlen(iface->ifname);

	return prefix_prandom(seed, pos, iface->prand_ctr[ctr_index]++, p, dst, plen);
}

bool __pa_compute_dodhcp(struct pa_iface *iface)
{
	if(!iface->designated)
		return false;

	struct pa_cpl *cpl;
	pa_for_each_cpl_in_iface(cpl, iface) {
		if(cpl->cp.applied)
			return true;
	}

	return false;
}

void __pa_update_dodhcp(struct pa_core *core, struct pa_iface *iface)
{
	pa_iface_set_dodhcp(iface, __pa_compute_dodhcp(iface));
	pa_iface_notify(core_p(core, data), iface);
}

void pa_cpl_set_rule(struct pa_cpl *cpl, struct pa_rule *rule)
{
	if(rule == cpl->rule)
		return;
	if(cpl->rule)
		btrie_remove(&cpl->rule_be);
	if(rule)
		btrie_add(&rule->cpls, &cpl->rule_be, (btrie_key_t *)&cpl->cp.prefix.prefix, cpl->cp.prefix.plen);
	cpl->rule = rule;
}

/* cpl destructor */
static void pa_core_destroy_cpl(struct pa_data *data, struct pa_cp *cp, void *owner)
{
	struct pa_core *core = &container_of(data, struct pa, data)->core;
	struct pa_cpl *cpl = _pa_cpl(cp);

	/* Remove the address if needed */
	if(cpl->laa) {
		pa_aa_todelete(&cpl->laa->aa);
		pa_aa_notify(core_p(core, data), &cpl->laa->aa);
	}

	L_INFO("Removing "PA_CP_L, PA_CP_LA(&cpl->cp));
	pa_cp_todelete(&cpl->cp);
	pa_cpl_set_rule(cpl, NULL);
	pa_cp_notify(&cpl->cp);

	if(owner != core)
		__pa_paa_schedule(core);
}

static void pa_core_destroy_cp(struct pa_core *core, struct pa_cp *cp)
{
	L_DEBUG("Calling "PA_CP_L" destructor %p", PA_CP_LA(cp), cp->destroy);
	cp->destroy(core_p(core, data), cp, core);
}

uint8_t pa_core_default_plen(struct pa_dp *dp, bool scarcity)
{
	if(!scarcity) {
		if(dp->prefix.plen < 64) {
			return 64;
		} else if (dp->prefix.plen < 104) {
			return dp->prefix.plen + 16;
		} else if (dp->prefix.plen < 112) {
			return 120;
		} else if (dp->prefix.plen <= 128) { //IPv4
			return 120 + (dp->prefix.plen - 112)/2;
		} else {
			L_ERR("Invalid prefix length (%d)", dp->prefix.plen);
			return 200;
		}
	} else {
		if(dp->prefix.plen < 64) {
			return 80;
		} else if (dp->prefix.plen < 88) {
			return dp->prefix.plen + 32;
		} else if (dp->prefix.plen < 112) {
			return 124;
		} else if (dp->prefix.plen <= 128) { //IPv4
			return 124 + (dp->prefix.plen - 112)/8;
		} else {
			L_ERR("Invalid prefix length (%d)", dp->prefix.plen);
			return 200;
		}
	}
}

/* This algorithm for finding a random prefix finds the first PA_CORE_FINDRAND_N available prefixes
 * and pick a random one among them.
 * Although this algorithm uses better random, it is sensible when multiple node trie
 * to assign prefixes of different lengths (A single assigned /64 can invalidate lots of /96).  */
static int pa_rule_try_random_plen_firsts(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		struct prefix *first_candidate)
{
	int i;
	if(!iface->designated)
		return -1;

	struct prefix candidates[PA_CORE_FINDRAND_N];
	size_t current_candidate = 0;

	L_DEBUG("Trying to find up to %d available prefixes of length %d in %s",
			PA_CORE_FINDRAND_N, rule->prefix.plen ,PREFIX_REPR(&dp->prefix));

	pa_for_each_available_prefix(core_pa(core), i, first_candidate, dp->prefix.plen, &rule->prefix) {
		prefix_cpy(&candidates[current_candidate], &rule->prefix);
		current_candidate++;
		if(current_candidate == PA_CORE_FINDRAND_N)
			break;
	}

	if(!current_candidate) {
		L_INFO("No more available prefix could be found in %s", PREFIX_REPR(&dp->prefix));
		return -1;
	}

	L_DEBUG("%d different candidates were found in %s", (int) current_candidate, PREFIX_REPR(&dp->prefix));
	prefix_cpy(&rule->prefix, &candidates[random() % current_candidate]);
	return 0;
}

static int pa_rule_try_random_plen(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		uint8_t plen)
{
	struct prefix first;
	struct btrie *n;

	if(!iface->designated || plen > 128)
		return -1;

	// Generate a pseudo-random subprefix
	if(pa_prefix_prand(iface, PAC_PRAND_PRFX, &dp->prefix, &first, plen)) {
		L_ERR("Cannot generate random prefix from "PA_DP_L" of length %d for "PA_IF_L,
				PA_DP_LA(dp), dp->prefix.plen, PA_IF_LA(iface));
		return -1;
	}

	pa_for_each_available_prefix_new(core_p(core, data), n, &first, dp->prefix.plen, &rule->prefix) {
		if(rule->prefix.plen <= plen) {
			if(prefix_contains(&rule->prefix, &first)) { //Only possible at first iteration
				prefix_cpy(&rule->prefix, &first);
			} else {
				prefix_canonical(&rule->prefix, &rule->prefix);
				rule->prefix.plen = plen;
			}
			return 0;
		}
	}

	return -1;
}

static int pa_rule_try_random_scarcity(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		__unused struct pa_ap *strongest_ap, __unused struct pa_cpl *current_cpl)
{
	uint8_t plen = iface->custom_plen?iface->custom_plen(iface, dp, iface->custom_plen_priv, true):pa_core_default_plen(dp, true);
	return pa_rule_try_random_plen(core, rule, dp, iface, plen);
}

static int pa_rule_try_random(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		__unused struct pa_ap *strongest_ap, __unused struct pa_cpl *current_cpl)
{
	uint8_t plen = iface->custom_plen?iface->custom_plen(iface, dp, iface->custom_plen_priv, false):pa_core_default_plen(dp, false);

	/* Space waste avoidance */
	if(plen >  dp->prefix.plen + 12 && !prefix_is_ipv4(&dp->prefix) && plen > 68) {
		struct prefix first;
		struct prefix *smallest = &dp->prefix;
		struct pa_ap *ap;
		pa_for_each_ap_updown(ap, core_p(core, data), &dp->prefix) {
			if(smallest->plen < ap->prefix.plen) {
				smallest = &ap->prefix;
			}
		}
		struct pa_cp *cp;
		pa_for_each_cp_down(cp, core_p(core, data), &dp->prefix) {
			if(smallest->plen < cp->prefix.plen) {
				smallest = &cp->prefix;
			}
		}

		if(smallest->plen < dp->prefix.plen + 10)
			smallest = &dp->prefix;

		prefix_cpy(&first, smallest);
		first.plen = plen - 8;
		prefix_canonical(&first, &first);
		first.plen = plen;
		return pa_rule_try_random_plen_firsts(core, rule, dp, iface, &first);
	}
	return pa_rule_try_random_plen(core, rule, dp, iface, plen);
}

static int pa_rule_try_accept(__attribute__((unused))struct pa_core *core,
		struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp, __attribute__((unused))struct pa_iface *iface,
		struct pa_ap *best_ap, __attribute__((unused))struct pa_cpl *current_cpl)
{
	if(!best_ap)
		return -1;

	prefix_cpy(&rule->prefix, &best_ap->prefix);
	rule->priority = best_ap->priority;
	rule->authoritative = false;
	return 0;
}

static int pa_rule_try_keep(struct pa_core *core, struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp, __attribute__((unused))struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	if(!current_cpl || (best_ap && pa_precedence_apcp(best_ap, &current_cpl->cp) > 0)
			|| !pa_cp_isvalid(core_pa(core), &current_cpl->cp))
		return -1;

	prefix_cpy(&rule->prefix, &current_cpl->cp.prefix);
	rule->priority = current_cpl->cp.priority;
	rule->authoritative = current_cpl->cp.authoritative;
	return 0;
}

static void pa_core_apply_rule(struct pa_core *core, struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp,
		__attribute__((unused))struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	if(current_cpl && prefix_cmp(&current_cpl->cp.prefix, &rule->prefix)) {
		pa_core_destroy_cp(core, &current_cpl->cp);
		current_cpl = NULL;
	}

	if(!current_cpl)
		current_cpl = _pa_cpl(pa_cp_get(core_p(core, data), &rule->prefix, PA_CPT_L, true));

	if(!current_cpl) {
		L_WARN("Can't create cpl with prefix %s", PREFIX_REPR(&rule->prefix));
		return;
	}

	pa_core_invalidate_cps(core, &rule->prefix, false, current_cpl);

	pa_cpl_set_iface(current_cpl, iface);
	pa_cp_set_priority(&current_cpl->cp, rule->priority);
	pa_cp_set_authoritative(&current_cpl->cp, rule->authoritative);

	bool advertise = !best_ap									//Advertise if no-one else does
			|| iface->designated								//Start advertising if designated
			|| rule->authoritative
			|| prefix_cmp(&best_ap->prefix, &rule->prefix)		//The prefix is not the same
			|| ((!best_ap->authoritative) && (best_ap->priority < rule->priority)); //Our assignment has a higher priority
	pa_cp_set_advertised(&current_cpl->cp, advertise);
	pa_cp_set_dp(&current_cpl->cp, dp);

	if(rule != &core->keep_rule)
		pa_cpl_set_rule(current_cpl, rule);

	if(!current_cpl->cp.applied && !current_cpl->cp.apply_to.pending)
		pa_cp_set_apply_to(&current_cpl->cp, 2*core_p(core, data.flood)->flooding_delay);

	current_cpl->invalid = false;

	if(current_cpl->cp.__flags & PADF_CP_CREATED) {
		L_INFO("Created new "PA_CP_L, PA_CP_LA(&current_cpl->cp));
	} else if (current_cpl->cp.__flags) {
		L_INFO("Updating "PA_CP_L, PA_CP_LA(&current_cpl->cp));
	}

	pa_cp_notify(&current_cpl->cp);
}

static void pa_core_try_rules(struct pa_core *core, struct pa_dp *dp,
		struct pa_iface *iface, struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	struct pa_rule *rule;
	list_for_each_entry(rule, &core->rules, le) {
		L_DEBUG("Considering "PA_RULE_L, PA_RULE_LA(rule));
		if(rule->try && !rule->try(core, rule, dp, iface, best_ap, current_cpl)) {
			pa_core_apply_rule(core, rule, dp, iface, best_ap, current_cpl);
			return;
		}
	}
}

static int pa_core_invalidate_cps(struct pa_core *core, struct prefix *prefix, bool delete_auth,
		struct pa_cpl *except)
{
	struct pa_cp *cp, *cp2;
	int ret = 0;
	pa_for_each_cp_updown_safe(cp, cp2, core_p(core, data), prefix) {
		if((delete_auth || !cp->authoritative) && (cp != &except->cp)) {
			pa_core_destroy_cp(core, cp);
			ret = 1;
		}
	}
	return ret;
}

static bool pa_core_iface_is_designated(struct pa_core *core, struct pa_iface *iface)
{
	struct pa_cpl *cpl, *best_cpl;
	struct pa_ap *ap;

	if(btrie_empty(&iface->aps) || iface->adhoc)
		return true;

	if(btrie_empty(&iface->cpls))
		return false;

	/* Get cp with lowest auth. and priority. */
	best_cpl = NULL;
	pa_for_each_cpl_in_iface(cpl, iface) {
		if(cpl->cp.advertised && (!best_cpl
				|| best_cpl->cp.authoritative > cpl->cp.authoritative
				|| ((best_cpl->cp.authoritative == cpl->cp.authoritative) && best_cpl->cp.priority > cpl->cp.priority)))
				best_cpl = cpl;
	}

	if(!best_cpl)
		return false;

	/* Compare with all aps on that iface */
	pa_for_each_ap_in_iface(ap, iface) {
		if(ap->authoritative < best_cpl->cp.authoritative) {
			return false;
		} else if(ap->authoritative == best_cpl->cp.authoritative) {
			if(ap->priority < best_cpl->cp.priority) {
				return false;
			} else if (ap->priority == best_cpl->cp.priority && (PA_RIDCMP(core_p(core, data.flood.rid), &ap->rid) < 0) ) {
				return false;
			}
		}
	}

	return true;
}

static struct pa_cpl *pa_core_getcpl(struct pa_dp *dp, struct pa_iface *iface)
{
	struct pa_cpl *cpl;
	pa_for_each_cpl_in_iface_down(cpl, iface, &dp->prefix) {
		return cpl;
	}
	return NULL;
}

static struct pa_ap *pa_core_getap(struct pa_core *core, struct pa_dp *dp, struct pa_iface *iface, struct pa_cp *cp)
{
	/* Retrieve a valid ap for that dp */
	struct pa_ap *ap = NULL;
	struct pa_ap *ap_iter;

	/* Get the highest priority on that interface */
	pa_for_each_ap_in_iface_down(ap_iter, iface, &dp->prefix) {
		if((!ap || pa_precedence_apap(ap_iter, ap) > 0)
				&& pa_ap_isvalid(core_pa(core), ap_iter)
				&& (!cp || !cp->advertised || pa_precedence_apcp(ap_iter, cp) >= 0))
				ap = ap_iter;
	}
	return ap;
}

void paa_algo_do(struct pa_core *core)
{
	struct pa_data *data = core_p(core, data);
	struct pa_dp *dp;
	struct pa_iface *iface;
	struct pa_cp *cp;
	struct pa_cpl *cpl;
	struct pa_ap *ap;

	L_INFO("Executing prefix assignment algorithm");

	/* Mark all prefixes as invalid */
	pa_for_each_cp(cp, data) {
		if((cpl = _pa_cpl(cp)) && !cpl->cp.authoritative)
			cpl->invalid = true;
	}

	/* Compute designated */
	pa_for_each_iface(iface, data)
		iface->designated = pa_core_iface_is_designated(core, iface);

	pa_for_each_dp(dp, data) {
		if(dp->ignore)
			continue;

		L_DEBUG("Considering "PA_DP_L, PA_DP_LA(dp));

		pa_for_each_iface(iface, data) {
			if(!iface->internal)
				continue;

			cpl = pa_core_getcpl(dp, iface);
			ap = iface->adhoc?NULL:pa_core_getap(core, dp, iface, &cpl->cp);
			pa_core_try_rules(core, dp, iface, ap, cpl);
		}
	}

	/* Remove invalid cps */
	struct pa_cp *cpsafe;
	pa_for_each_cp_safe(cp, cpsafe, data) {
		if((cpl = _pa_cpl(cp)) && cpl->invalid)
			pa_core_destroy_cp(core, &cpl->cp);
	}

	/* Evaluate dodhcp ofr all iface */
	pa_for_each_iface(iface, data)
		__pa_update_dodhcp(core, iface);

	L_INFO("End of prefix assignment algorithm");
}

static int __aaa_from_conf(struct pa_core *core, struct pa_cpl *cpl, struct in6_addr *addr)
{
	struct pa_iface_addr *a;
	uint8_t plen = cpl->cp.prefix.plen;

	list_for_each_entry(a, &core->iface_addrs, le) {
		if(prefix_contains(&a->filter, &cpl->cp.prefix) && plen <= a->mask &&
				(a->ifname[0] == '\0' || !strcmp(a->ifname, cpl->iface->ifname))) {
			memcpy(addr, &cpl->cp.prefix.prefix, sizeof(struct in6_addr));
			bmemcpy(addr, &a->address, plen, 128-plen);
			if(pa_addr_available(core_pa(core), cpl->iface, addr))
				return 0;
		}
	}
	return -1;
}

static int __aaa_from_storage(struct pa_core *core, struct pa_cpl *cpl, struct in6_addr *addr)
{
	struct pa_sa *sa;
	struct prefix p;
	pa_for_each_sa(sa, core_p(core, data)) {
		p.plen = 128;
		memcpy(&p.prefix, &sa->addr, sizeof(struct in6_addr));
		if(prefix_contains(&cpl->cp.prefix, &p) && pa_addr_available(core_pa(core), cpl->iface, &sa->addr)) {
			memcpy(addr, &sa->addr, sizeof(struct in6_addr));
			return 0;
		}
	}
	return -1;
}

static inline int __aaa_do_slaac(struct pa_cpl *cpl, struct in6_addr *addr)
{
	struct iface *iface;
	struct prefix can;

	if(cpl->cp.prefix.plen > 64 || !cpl->iface || !(iface = iface_get(cpl->iface->ifname)))
		return -1;

	prefix_canonical(&can, &cpl->cp.prefix);
	memcpy(addr, &can.prefix, sizeof(struct in6_addr));
	memcpy(&addr->s6_addr[8], &iface->eui64_addr.s6_addr[8], 8);
	return 0;
}

static int __aaa_find_random(struct pa_core *core, struct pa_cpl *cpl, struct in6_addr *addr)
{
	struct prefix rpool, result;
	bool first = true;
	struct in6_addr first_addr;

	/* Get routers pool */
	prefix_canonical(&rpool, &cpl->cp.prefix);
	if(cpl->cp.prefix.plen <= 64) {
		rpool.plen = 64;
	} else if (cpl->cp.prefix.plen <= 110) {
		rpool.plen = 112;
	} else if (cpl->cp.prefix.plen < 126) {
		rpool.plen = cpl->cp.prefix.plen + 2;
	} else if(!cpl->iface || pa_core_iface_is_designated(core, cpl->iface)) {
		/* Only the designated router can get the only address */
		memcpy(addr, &rpool.prefix, sizeof(struct in6_addr));
		return 0;
	} else {
		return -1;
	}

	if(pa_prefix_prand(cpl->iface, PAC_PRAND_ADDR, &rpool, &result, 128)) {
		L_ERR("Cannot generate random address from "PA_CP_L" for "PA_IF_L,
						PA_CP_LA(&cpl->cp), PA_IF_LA(cpl->iface));
		return -1;
	}

	//todo: prefix_increment can't manipulate more than 32 bits
	if(rpool.plen < 96) {
		result.plen = 96;
		prefix_canonical(&rpool, &result);
		result.plen = 128;
	}
	L_DEBUG("Trying to find an address in %s", PREFIX_REPR(&rpool));

	while(1) {
		if((!prefix_is_ipv4(&rpool)
				|| memcmp(&rpool.prefix, &result.prefix, sizeof(struct in6_addr)))
				&& pa_addr_available(core_pa(core), cpl->iface, &result.prefix)) {
			memcpy(addr, &result.prefix, sizeof(struct in6_addr));
			return 0;
		}

		L_DEBUG("Address %s can't be used", ADDR_REPR(&result.prefix));

		if(first) {
			memcpy(&first_addr, &result.prefix,  sizeof(struct in6_addr));
			first = false;
		} else if (!memcmp(&first_addr, &result.prefix, sizeof(struct in6_addr))) {
			L_WARN("No address available in "PA_CP_L, PA_CP_LA(&cpl->cp));
			return -1;
		}

		if(prefix_increment(&result, &result, rpool.plen) == -1) {
			L_ERR("Can't increment address %s in "PA_CP_L, ADDR_REPR(&result.prefix), PA_CP_LA(&cpl->cp));
			return -1;
		}
	}
	return -1;
}

static bool __aaa_valid(struct pa_core *core, struct in6_addr *addr)
{
	struct pa_eaa *eaa;
	pa_for_each_eaa_down(eaa, core_p(core, data), addr, 128) {
		if(PA_RIDCMP(&eaa->rid, &core_p(core, data)->flood.rid) > 0)
			return false;
	}
	return true;
}

static void aaa_algo_do(struct pa_core *core)
{
	struct pa_data *data = core_p(core, data);
	struct pa_cp *cp;
	struct pa_cpl *cpl;
	struct pa_laa *laa;
	struct in6_addr addr;

	L_INFO("Executing address assignment algorithm");

	pa_for_each_cp(cp, data) {
		if(!(cpl = _pa_cpl(cp)))
			continue;

		/* Delete if invalid */
		if(cpl->laa && (!__aaa_valid(core, &cpl->laa->aa.address) || !cpl->iface)) {
			pa_aa_todelete(&cpl->laa->aa);
			pa_aa_notify(data, &cpl->laa->aa);
		}

		if(		(!__aaa_from_conf(core, cpl, &addr) && (!cpl->laa || memcmp(&addr, &cpl->laa->aa.address, sizeof(struct in6_addr))))
				 ||
				(!cpl->laa && (!__aaa_from_storage(core, cpl, &addr) 	||
						!__aaa_do_slaac(cpl, &addr) 					||
						!__aaa_find_random(core, cpl, &addr))))
		{
			if(cpl->laa) {
				pa_aa_todelete(&cpl->laa->aa);
				pa_aa_notify(data, &cpl->laa->aa);
			}

			laa = pa_laa_create(&addr, cpl);
			if(laa) {
				pa_aa_notify(data, &laa->aa);
				if(cp->prefix.plen <= 64) {
					pa_laa_set_apply_to(laa, 0);
				} else {
					//todo: Maybe this delay is not that useful, or slaac needed in any case
					pa_laa_set_apply_to(laa, 2*core_p(core, data.flood)->flooding_delay_ll);
				}
			} else {
				L_WARN("Could not create laa from address %s", ADDR_REPR(&addr));
			}
		}

		if(!cpl->laa) {
			L_WARN("Could not find address for "PA_CP_L, PA_CP_LA(cp));
		}
	}
}

void pa_core_destroy_cpx(struct pa_data *data, struct pa_cp *cp, void *owner)
{
	struct pa_core *core = &container_of(data, struct pa, data)->core;
	struct pa_cpx *cpx = _pa_cpx(cp);

	cpx->ldp->excluded.cpx = NULL;
	pa_cp_todelete(&cpx->cp);
	pa_cp_notify(&cpx->cp);

	if(owner != core) {
		L_WARN("CPXs are not supposed to be removed by anybody else than pa_core");
	}
}

void pa_core_update_excluded(struct pa_core *core, struct pa_ldp *ldp)
{
	if(ldp->excluded.cpx)
		pa_core_destroy_cp(core, &ldp->excluded.cpx->cp);

	if(ldp->excluded.valid) {
		/* Invalidate all contained cps */
		if (pa_core_invalidate_cps(core, &ldp->excluded.excluded, false, NULL))
			__pa_paa_schedule(core);

		//todo: When no cp is deleted, we don't need to execute paa, but in case of scarcity, it may be usefull
		/* Creating new cp */
		ldp->excluded.cpx = _pa_cpx(pa_cp_get(core_p(core, data), &ldp->excluded.excluded, PA_CPT_X, true));
		if(ldp->excluded.cpx) {
			ldp->excluded.cpx->ldp = ldp;
			pa_cp_set_authoritative(&ldp->excluded.cpx->cp, true);
			pa_cp_notify(&ldp->excluded.cpx->cp);
		} else {
			L_ERR("Could not create CPX for "PA_DP_L, PA_DP_LA(&ldp->dp));
		}
	}
}

static void __pa_paa_to_cb(struct pa_timer *t)
{
	paa_algo_do(container_of(t, struct pa_core, paa_to));
}

static void __pa_aaa_to_cb(struct pa_timer *t)
{
	aaa_algo_do(container_of(t, struct pa_core, aaa_to));
}

/************* Rule control ********************************/

void pa_core_rule_init(struct pa_rule *rule, const char *name, uint32_t rule_priority, rule_try try)
{
	rule->name = name;
	rule->rule_priority = rule_priority;
	rule->try = try;
	btrie_init(&rule->cpls);
}

void pa_core_rule_add(struct pa_core *core, struct pa_rule *rule)
{
	struct pa_rule *r2;

	list_for_each_entry(r2, &core->rules, le) {
		if(rule->rule_priority <= r2->rule_priority) {
			list_add_tail(&rule->le, &r2->le);
			goto conf;
		}
	}
	list_add_tail(&rule->le, &core->rules);

conf:
	btrie_init(&rule->cpls);
	__pa_paa_schedule(core);

	//todo: Override may need a change
}

void pa_core_rule_del(struct pa_core *core,
		struct pa_rule *rule)
{
	struct pa_cpl *cpl, *cpl2;
	btrie_for_each_down_entry_safe(cpl, cpl2, &rule->cpls, NULL, 0, rule_be) {
		pa_cpl_set_rule(cpl, NULL);
		pa_cp_set_authoritative(&cpl->cp, false);
		if(cpl->cp.priority > PA_PRIORITY_DEFAULT)
			pa_cp_set_priority(&cpl->cp, PA_PRIORITY_DEFAULT);
		pa_cp_set_advertised(&cpl->cp, &cpl->iface->designated); //This is to avoid changing the designated router
		pa_cp_notify(&cpl->cp);
		__pa_paa_schedule(core);
	}
	list_del(&rule->le);
}

/************* Iface addr control ********************************/

void pa_core_iface_addr_init(struct pa_iface_addr *addr, const char *ifname,
		struct in6_addr *address, uint8_t mask, struct prefix *filter)
{
	memcpy(&addr->address, address, sizeof(struct in6_addr));
	addr->mask = mask;

	if(filter)
		prefix_cpy(&addr->filter, filter);
	else
		addr->filter.plen = 0;

	if(ifname)
		strcpy(addr->ifname, ifname);
	else
		addr->ifname[0] = '\0';
}

void pa_core_iface_addr_add(struct pa_core *core, struct pa_iface_addr *addr)
{
	L_NOTICE("Adding address configuration: "PA_IFACE_ADDR_L, PA_IFACE_ADDR_LA(addr));
	list_add(&addr->le, &core->iface_addrs);
	__pa_aaa_schedule(core);
}

void pa_core_iface_addr_del(__unused struct pa_core *core, struct pa_iface_addr *addr)
{
	L_NOTICE("Removing address configuration: "PA_IFACE_ADDR_L, PA_IFACE_ADDR_LA(addr));
	list_del(&addr->le);
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
		struct pa_iface *iface, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(flags & (PADF_IF_CREATED | PADF_IF_INTERNAL | PADF_IF_TODELETE | PADF_IF_ADHOC))
		__pa_paa_schedule(core);

	if((flags & PADF_IF_TODELETE) || !iface->internal) {
		//Remove all cpls
		struct pa_cpl *cpl, *cpl2;
		pa_for_each_cpl_in_iface_safe(cpl, cpl2, iface) {
			pa_core_destroy_cp(core, &cpl->cp);
		}
	}
}

static void __pad_cb_dps(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	struct pa_cp *cp, *cp2;
	struct pa_ldp *ldp;

	if(flags & (PADF_DP_CREATED | PADF_DP_TODELETE))
		__pa_paa_schedule(core);

	if((flags & PADF_DP_CREATED) && !dp->ignore) {
		/* Remove orphans if possible */
		pa_for_each_cp_down(cp,  core_p(core, data), &dp->prefix) {
			if((cp->type == PA_CPT_L) && !cp->dp) {
				pa_cp_set_dp(cp, dp);
				pa_cp_notify(cp);
			}
		}
	}

	if(flags & PADF_DP_TODELETE) {
		/* Need to make assignments orphans */
		pa_for_each_cp_in_dp_safe(cp, cp2, dp) {
			if(cp->type == PA_CPT_L) {
				pa_cp_set_dp(cp, NULL);
				pa_cp_notify(cp);
			}
		}

		/* When deleted, we need to delete the excluded prefix properly */
		if(dp->local && (ldp = container_of(dp, struct pa_ldp, dp))->excluded.valid) {
			ldp->excluded.valid = false;
			flags |= PADF_LDP_EXCLUDED;
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
	struct pa_cpl *cpl= _pa_cpl(cp);
	struct pa_core *core = container_of(user, struct pa_core, data_user);
	if(cpl && (flags & PADF_CP_CREATED))
		__pa_aaa_schedule(core);

	if(cpl && (flags & PADF_CP_APPLIED)) /* Update dodhcp */
		__pa_update_dodhcp(&container_of(cp->pa_data, struct pa, data)->core, cpl->iface);
}

/************* Static prefixes control ********************************/


static int pa_rule_try_prefix(struct pa_core *core, struct pa_rule *rule,
		struct prefix *prefix, bool hard,
		__unused struct pa_dp *dp, __unused struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	struct pa *pa = core_pa(core);

	if(best_ap && (!hard ||
			(!rule->authoritative && best_ap->priority >= rule->priority)))
		return -1;

	if(current_cpl && (!hard ||
			(!rule->authoritative && current_cpl->cp.priority >= rule->priority)))
		return -1;

	struct pa_ap *ap;
	pa_for_each_ap_updown(ap, &pa->data, prefix) {
		if(!hard ||
				(!rule->authoritative && rule->priority < ap->priority))
			return -1;
	}

	struct pa_cp *cp;
	pa_for_each_cp_updown(cp, &pa->data, prefix) {
		if(!hard ||
				(!rule->authoritative && rule->priority < cp->priority))
			return -1;
	}

	prefix_cpy(&rule->prefix, prefix);
	return 0;
}

static int pa_rule_try_static_prefix(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	struct pa_static_prefix_rule *sprule = container_of(rule, struct pa_static_prefix_rule, rule);

	if(!(btrie_empty(&rule->cpls))
			|| !prefix_contains(&dp->prefix, &sprule->prefix)
			|| (sprule->ifname[0] != '\0' && strcmp(sprule->ifname, iface->ifname)))
		return -1;

	return pa_rule_try_prefix(core, rule, &sprule->prefix, sprule->hard, dp, iface, best_ap, current_cpl);
}

void pa_core_static_prefix_init(struct pa_static_prefix_rule *sprule,
		const char *ifname, const struct prefix* p, bool hard)
{
	snprintf(sprule->rule_name, sizeof(sprule->rule_name), "Static Prefix %s on '%s'", PREFIX_REPR(p), ifname?ifname:"any iface");

	pa_core_rule_init(&sprule->rule, sprule->rule_name, hard?500:2500, pa_rule_try_static_prefix);
	prefix_cpy(&sprule->prefix, p);

	if(ifname)
		strcpy(sprule->ifname, ifname);
	else
		sprule->ifname[0] = '\0';
	sprule->hard = hard;
	sprule->rule.authoritative = false;
	sprule->rule.priority = PA_PRIORITY_AUTO_MIN;
}

static int pa_rule_try_link_id(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	struct pa_link_id_rule *lrule = container_of(rule, struct pa_link_id_rule, rule);
	uint8_t plen;
	struct prefix p;

	if((lrule->ifname[0] != '\0' && strcmp(lrule->ifname, iface->ifname)))
		return -1;

	if(((plen = pa_core_default_plen(dp, false)) > 128) || ((plen - dp->prefix.plen) < lrule->link_id_len))
		return -1;

	prefix_canonical(&p, &dp->prefix);
	p.plen = plen;
	prefix_number(&p, &p, lrule->link_id, lrule->link_id_len);

	return pa_rule_try_prefix(core, rule, &p, lrule->hard, dp, iface, best_ap, current_cpl);
}

void pa_core_link_id_init(struct pa_link_id_rule *lrule, const char *ifname,
		uint32_t link_id, uint8_t link_id_len, bool hard)
{
	snprintf(lrule->rule_name, sizeof(lrule->rule_name), "Link Id %d/%d on '%s'", link_id, link_id_len, ifname?ifname:"any iface");

	pa_core_rule_init(&lrule->rule, lrule->rule_name, hard?600:2600, pa_rule_try_link_id);

	lrule->link_id = link_id;
	lrule->link_id_len = link_id_len;
	if(ifname)
		strcpy(lrule->ifname, ifname);
	else
		lrule->ifname[0] = '\0';
	lrule->hard = hard;
	lrule->rule.authoritative = false;
	lrule->rule.priority = PA_PRIORITY_AUTO_MIN;
}

/************* Control functions ********************************/

void pa_core_init(struct pa_core *core)
{
	L_INFO("Initializing pa core structure");

	pa_timer_init(&core->paa_to, __pa_paa_to_cb, "Prefix Assignment Algorithm");
	core->paa_to.min_delay = PA_CORE_MIN_DELAY;
	pa_timer_init(&core->aaa_to, __pa_aaa_to_cb, "Address Assignment Algorithm");
	core->aaa_to.min_delay = PA_CORE_MIN_DELAY;

	memset(&core->data_user, 0, sizeof(struct pa_data_user));
	core->data_user.aas = __pad_cb_aas;
	core->data_user.aps = __pad_cb_aps;
	core->data_user.dps = __pad_cb_dps;
	core->data_user.ifs = __pad_cb_ifs;
	core->data_user.flood = __pad_cb_flood;
	core->data_user.cps = __pad_cb_cps;

	INIT_LIST_HEAD(&core->rules);
	pa_core_rule_init(&core->keep_rule, "Keep current prefix", PACR_PRIORITY_KEEP, pa_rule_try_keep);
	pa_core_rule_init(&core->accept_rule, "Accept proposed prefix", PACR_PRIORITY_ACCEPT, pa_rule_try_accept);

	pa_core_rule_init(&core->random_rule, "Randomly generated", PACR_PRIORITY_RANDOM, pa_rule_try_random);
	core->random_rule.priority = PA_PRIORITY_DEFAULT;
	core->random_rule.authoritative = false;

	pa_core_rule_init(&core->random_scarcity_rule, "Scarcity random selection", PACR_PRIORITY_SCARCITY, pa_rule_try_random_scarcity);
	core->random_scarcity_rule.priority = PA_PRIORITY_DEFAULT;
	core->random_scarcity_rule.authoritative = false;

	pa_core_rule_add(core, &core->keep_rule);
	pa_core_rule_add(core, &core->accept_rule);
	pa_core_rule_add(core, &core->random_rule);
	pa_core_rule_add(core, &core->random_scarcity_rule);

	INIT_LIST_HEAD(&core->iface_addrs);

	core->started = false;
}

void pa_core_start(struct pa_core *core)
{
	if(core->started)
		return;

	L_INFO("Starting pa core structure");
	pa_data_subscribe(core_p(core, data), &core->data_user);
	pa_data_register_cp(core_p(core, data), PA_CPT_X, pa_core_destroy_cpx);
	pa_data_register_cp(core_p(core, data), PA_CPT_L, pa_core_destroy_cpl);
	core->started = true;

	/* Always schedule when started */
	pa_timer_set_not_before(&core->paa_to, core_p(core, data)->flood.flooding_delay, true);
	pa_timer_enable(&core->paa_to);
	pa_timer_enable(&core->aaa_to);
	__pa_paa_schedule(core);
	__pa_aaa_schedule(core);
}

void pa_core_stop(struct pa_core *core)
{
	if(!core->started)
		return;

	L_INFO("Stopping pa core structure");
	core->started = 0;
	pa_timer_disable(&core->paa_to);
	pa_timer_disable(&core->aaa_to);
	pa_data_unsubscribe(&core->data_user);
}

void pa_core_term(struct pa_core *core)
{
	L_INFO("Terminating pa core structure");
	pa_core_stop(core);

	pa_core_rule_del(core, &core->keep_rule);
	pa_core_rule_del(core, &core->accept_rule);
	pa_core_rule_del(core, &core->random_rule);
	pa_core_rule_del(core, &core->random_scarcity_rule);
}
