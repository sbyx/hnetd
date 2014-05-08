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

#define PAC_PRAND_PRFX 0
#define PAC_PRAND_ADDR 1

#define core_pa(c) (container_of(c, struct pa, core))
#define core_rid(core) (&((core_pa(core))->flood.rid))
#define core_p(core, field) (&(core_pa(core)->field))

#define __pa_paa_schedule(c) pa_timer_set_earlier(&(c)->paa_to, core_p((c), data)->flood.flooding_delay / PA_CORE_DELAY_FACTOR, true)
#define __pa_aaa_schedule(c) pa_timer_set_earlier(&(c)->aaa_to, core_p((c), data)->flood.flooding_delay_ll / PA_CORE_DELAY_FACTOR, true)

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

static int pa_rule_try_random(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		__attribute__((unused))struct pa_ap *strongest_ap,
		__attribute__((unused))struct pa_cpl *current_cpl)
{
	if(!iface->designated)
		return -1;

	uint8_t plen;
	const struct prefix *collision;
	const struct prefix *first_collision = NULL;

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

	if (!iface) {
		L_ERR("No specified interface for prefix random generation");
		return -1;
	}

	/* Generate a pseudo-random subprefix */
	if(pa_prefix_prand(iface, PAC_PRAND_PRFX, &dp->prefix, &rule->prefix, plen)) {
		L_ERR("Cannot generate random prefix from "PA_DP_L" of length %d for "PA_IF_L,
				PA_DP_LA(dp), dp->prefix.plen, PA_IF_LA(iface));
		return -1;
	}

	while(1) {
		if(!(collision = pa_prefix_getcollision(core_pa(core), &rule->prefix)))
			return 0; //prio, auth and adv are set at init

		L_DEBUG("Prefix %s can't be used", PREFIX_REPR(&rule->prefix));

		if(!first_collision) {
			first_collision = collision;
		} else if(!prefix_cmp(collision, first_collision)) { //We looped
			L_INFO("No more available prefix can be found in %s", PREFIX_REPR(&dp->prefix));
			return -1;
		}

		if(rule->prefix.plen <= collision->plen) {
			if(prefix_increment(&rule->prefix, &rule->prefix, dp->prefix.plen) == -1) {
				L_ERR("Error incrementing %s with protected length %d", PREFIX_REPR(&rule->prefix), dp->prefix.plen);
				return -1;
			}
		} else {
			if(prefix_increment(&rule->prefix, collision, dp->prefix.plen) == -1) {
				L_ERR("Error incrementing %s with protected length %d", PREFIX_REPR(collision), dp->prefix.plen);
				return -1;
			}
			rule->prefix.plen = plen;
		}
	}
	return -1; //avoid warning
}

static int pa_rule_try_storage(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		__attribute__((unused))struct pa_ap *strongest_ap,
		__attribute__((unused))struct pa_cpl *current_cpl)
{
	struct pa_sp *sp;

	if(!iface->designated)
		return -1;

	pa_for_each_sp_in_iface(sp, iface) {
		if(prefix_contains(&dp->prefix, &sp->prefix) &&
				!pa_prefix_getcollision(core_pa(core), &sp->prefix)) {
			prefix_cpy(&rule->prefix, &sp->prefix);
			//prio, auth and advertise are set at init
			return 0;
		}
	}

	return -1;
}

static int pa_rule_try_accept(__attribute__((unused))struct pa_core *core,
		struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp, __attribute__((unused))struct pa_iface *iface,
		struct pa_ap *best_ap, __attribute__((unused))struct pa_cpl *current_cpl)
{
	if(!best_ap)
		return -1;

	prefix_cpy(&rule->prefix, &best_ap->prefix);
	rule->advertise = iface->designated;
	rule->priority = best_ap->priority;
	rule->authoriative = false;
	return 0;
}

static int pa_rule_try_keep(struct pa_core *core, struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp, __attribute__((unused))struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl)
{
	if(!current_cpl || (best_ap && pa_precedence_apcp(best_ap, &current_cpl->cp) > 0 && !current_cpl->cp.authoritative)
			|| !pa_cp_isvalid(core_pa(core), &current_cpl->cp))
		return -1;

	prefix_cpy(&rule->prefix, &current_cpl->cp.prefix);
	rule->advertise = current_cpl->cp.advertised ||  iface->designated;
	rule->priority = current_cpl->cp.priority;
	rule->authoriative = current_cpl->cp.authoritative;
	return 0;
}

static void pa_core_apply_rule(struct pa_core *core, struct pa_rule *rule,
		__attribute__((unused))struct pa_dp *dp,
		__attribute__((unused))struct pa_iface *iface,
		struct pa_cpl *current_cpl)
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

	pa_cpl_set_iface(current_cpl, iface);
	pa_cp_set_priority(&current_cpl->cp, rule->priority);
	pa_cp_set_authoritative(&current_cpl->cp, rule->authoriative);
	pa_cp_set_advertised(&current_cpl->cp, rule->advertise);
	pa_cp_set_dp(&current_cpl->cp, dp);

	if(!current_cpl->cp.applied && !current_cpl->cp.apply_to.pending)
		pa_cp_set_apply_to(&current_cpl->cp, 2*core_p(core, data.flood)->flooding_delay);

	pa_cpl_set_rule(current_cpl, rule);
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
			pa_core_apply_rule(core, rule, dp, iface, current_cpl);
			return;
		}
	}
}

static int pa_core_invalidate_cps(struct pa_core *core, struct prefix *prefix, bool delete_auth)
{
	struct pa_cp *cp, *cp2;
	int ret = 0;
	pa_for_each_cp_updown_safe(cp, cp2, core_p(core, data), prefix) {
		if(delete_auth || !cp->authoritative) {
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

	if(btrie_empty(&iface->aps))
		return true;

	if(btrie_empty(&iface->cpls))
		return false;

	/* Get cp with lowest auth. and priority. */
	best_cpl = NULL;
	pa_for_each_cpl_in_iface(cpl, iface) {
		if(!best_cpl
				|| best_cpl->cp.authoritative > cpl->cp.authoritative
				|| ((best_cpl->cp.authoritative == cpl->cp.authoritative) && best_cpl->cp.priority > cpl->cp.priority))
			best_cpl = cpl;
	}

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
				&& pa_ap_isvalid(core_pa(core), ap_iter))
				ap = ap_iter;
	}

	if(cp && ap && pa_precedence_apcp(ap, cp) < 0)
		return NULL;

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
			ap = pa_core_getap(core, dp, iface, &cpl->cp);
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

		/* Create new if no assigned */
		if(!cpl->laa) { //cpl->iface is never NULL
			if(!__aaa_from_storage(core, cpl, &addr) || !__aaa_do_slaac(cpl, &addr) || !__aaa_find_random(core, cpl, &addr)) {
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
			} else {
				L_WARN("Could not find address for "PA_CP_L, PA_CP_LA(cp));
			}
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
		if (pa_core_invalidate_cps(core, &ldp->excluded.excluded, false))
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

void pa_core_rule_init(struct pa_rule *rule, const char *name, uint32_t rule_priority, const char *ifname, rule_try try)
{
	rule->name = name;
	rule->rule_priority = rule_priority;
	if(ifname)
		strcpy(rule->ifname, ifname);
	else
		rule->ifname[0] = '\0';
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

	//todo: Override may need a change
}

void pa_core_rule_del(__attribute__((unused))struct pa_core *core,
		struct pa_rule *rule)
{
	struct pa_cpl *cpl, *cpl2;
	btrie_for_each_down_entry_safe(cpl, cpl2, &rule->cpls, NULL, 0, rule_be) {
		cpl->cp.destroy(core_p(core, data), &cpl->cp, rule);
	}
	list_del(&rule->le);
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
	pa_core_rule_init(&core->keep_rule, "Keep current prefix", PACR_PRIORITY_KEEP, NULL, pa_rule_try_keep);
	pa_core_rule_init(&core->accept_rule, "Accept proposed prefix", PACR_PRIORITY_ACCEPT, NULL, pa_rule_try_accept);
	pa_core_rule_init(&core->storage_rule, "Stable storage", PACR_PRIORITY_STORAGE, NULL, pa_rule_try_storage);
	core->storage_rule.priority = PA_PRIORITY_DEFAULT;
	core->storage_rule.authoriative = false;
	core->storage_rule.advertise = true;

	pa_core_rule_init(&core->random_rule, "Randomly generated", PACR_PRIORITY_RANDOM, NULL, pa_rule_try_random);
	core->random_rule.priority = PA_PRIORITY_DEFAULT;
	core->random_rule.authoriative = false;
	core->random_rule.advertise = true;

	pa_core_rule_add(core, &core->keep_rule);
	pa_core_rule_add(core, &core->accept_rule);
	pa_core_rule_add(core, &core->storage_rule);
	pa_core_rule_add(core, &core->random_rule);

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
	pa_core_rule_del(core, &core->storage_rule);
	pa_core_rule_del(core, &core->random_rule);
}

int pa_core_static_prefix_add(struct pa_core *core, struct prefix *prefix, struct pa_iface *iface)
{
	return -1 || (core && prefix && iface);
}
int pa_core_static_prefix_remove(struct pa_core *core, struct prefix *prefix, struct pa_iface *iface)
{
	return -1 || (core && prefix && iface);
}

