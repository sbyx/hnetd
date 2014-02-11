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

#define PA_CORE_MIN_DELAY 3
#define PA_CORE_DELAY_FACTOR 10

#define core_pa(core) (container_of(core, struct pa, core))
#define core_rid(core) (&((core_pa(core))->flood.rid))
#define core_p(core, field) (&(core_pa(core)->field))

/* Accepting an ap */
static void pa_core_accept_ap(struct pa_core *core, struct pa_ap *ap, struct pa_dp *dp, bool advertise)
{
	L_INFO("Accepting "PA_AP_L, PA_AP_LA(ap));

	if(!ap->iface) {
		L_WARN("Can't accept "PA_AP_L" because it has no interface", PA_AP_LA(ap));
		return;
	}

	bool created = false;
	struct pa_cp *cp = pa_cp_get(core_p(core, data), &ap->prefix, &created);

	pa_cp_set_iface(cp, ap->iface);
	pa_cp_set_priority(cp, ap->priority);
	pa_cp_set_authoritative(cp, false);
	pa_cp_set_dp(cp, dp);
	pa_cp_set_advertised(cp, advertise);
	pa_cp_set_apply_timeout(cp, core_p(core, flood)->flooding_delay);

	pa_updated_cp(core, cp, false, advertise, false);
}

static void pa_core_update_cp(struct pa_core *core, struct pa_ap *ap, struct pa_cp *cp, bool advertise)
{
	L_INFO("Updating "PA_CP_L" with "PA_AP_L, PA_CP_LA(cp), PA_AP_LA(ap));

	if(pa_cp_set_priority(cp, ap->priority)
			| pa_cp_set_advertised(cp, advertise))
		pa_updated_cp(core, cp, false, true, false);
}

static void pa_core_create_cp(struct pa_core *core, const struct prefix *p,
		struct pa_dp *dp, struct pa_iface *iface,
		bool authority, uint8_t priority)
{

	bool created = false;
	struct pa_cp *cp = pa_cp_get(core_p(core, data), p, &created);

	if(!created) {
		L_WARN("Can't create "PA_CP_L" because it already exists", PA_CP_LA(cp));
		return;
	}

	L_INFO("Creating new "PA_CP_L, PA_CP_LA(cp));

	pa_cp_set_iface(cp, iface);
	pa_cp_set_priority(cp, priority);
	pa_cp_set_authoritative(cp, authority);
	pa_cp_set_dp(cp, dp);
	pa_cp_set_advertised(cp, true);
	pa_cp_set_apply_timeout(cp, core_p(core, flood)->flooding_delay);

	pa_updated_cp(core, cp, false, true, false);
}

static void pa_core_make_new_assignment(struct pa_core *core, struct pa_dp *dp, struct pa_iface *iface)
{

}

static void pa_core_destroy_cp(struct pa_core *core, struct pa_cp *cp)
{
	L_INFO("Removing "PA_CP_L, PA_CP_LA(cp));

	/* Remove the address if needed */
	if(cp->laa) {
		pa_updated_laa(core, cp->laa, true);
		pa_cp_set_address(cp, NULL);
	}

	/* Delete the cp */
	pa_updated_cp(core, cp, true, cp->advertised, cp->applied);
	pa_cp_destroy(cp);
}

static bool pa_core_dp_ignore(struct pa_core *core, struct pa_dp *dp)
{
	struct pa_data *data = core_p(core, data);
	struct pa_dp *dp2;
	bool seen;
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
				|| best_cp->priority > cp->priority)
			best_cp = cp;
	}

	/* Compare with all aps */
	pa_for_each_ap_in_iface(ap, iface) {
		if(ap->authoritative < best_cp->authoritative
				|| ap->priority < best_cp->priority
				|| ((ap->priority == best_cp->priority) && (PA_RIDCMP(&ap->rid, core_p(core, flood.rid))) ))
			return false;
	}

	return true;
}

static struct pa_cp *pa_core_getcp(struct pa_core *core, struct pa_dp *dp, struct pa_iface *iface)
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
			cp->authoritative, cp->priority, &(container_of(cp->pa_data, struct pa, data))->flood.rid);
}

static bool pa_core_cp_check_global_validity(struct pa_core *core, struct pa_cp *cp)
{
	struct pa_data *data = core_p(core, data);
	struct pa_ap *ap_iter;

	if(cp->authoritative)
		return true;

	//Todo: use same code for cp and ap validity
	pa_for_each_ap(ap_iter, data) {
		if(pa_core_precedence_apcp(ap_iter, cp) > 0
				&& (prefix_contains(&ap_iter->prefix, &cp->prefix) || prefix_contains(&cp->prefix, &ap_iter->prefix)))
			return false;
	}

	return true;
}

static bool pa_core_ap_check_global_validity(struct pa_core *core, struct pa_ap *ap)
{
	struct pa_data *data = core_p(core, data);
	struct pa_ap *ap_iter;

	pa_for_each_ap(ap_iter, data) {
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
				&& pa_core_ap_check_global_validity(core, ap_iter)
				&& (!ap || pa_core_precedence_apap(ap_iter, ap) > 0))
				ap = ap_iter;
	}

	if(cp && ap && pa_core_precedence_apcp(ap, cp) < 0)
		return NULL;

	return NULL;
}

static void pa_core_case1(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp)
{
	if(iface->designated)
		pa_core_make_new_assignment(core, dp, iface);
}

static void pa_core_case2(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_ap *ap)
{
	pa_core_accept_ap(core, ap, dp, iface->designated);
}

static void pa_core_case3(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_cp *cp)
{
	if(pa_core_cp_check_global_validity(core, cp)) {
		cp->invalid = false;
	} else {
		pa_core_destroy_cp(core, cp);
		pa_core_case1(core, iface, dp);
	}
}

static void pa_core_case4(struct pa_core *core, struct pa_iface *iface, struct pa_dp *dp, struct pa_ap *ap, struct pa_cp *cp)
{
	if(prefix_cmp(&ap->prefix, &cp->prefix)) {
		if(!cp->authoritative) {
			pa_core_destroy_cp(core, cp);
			pa_core_case2(core, iface, dp, ap);
		}
		//Valid otherwise
	} else {
		pa_core_update_cp(core, ap, cp, iface->designated);
	}
}

void pa_algo_do(struct pa_core *core)
{
	struct pa_data *data = core_p(core, data);
	struct pa_dp *dp;
	struct pa_iface *iface;
	struct pa_cp *cp;
	struct pa_ap *ap;

	/* Mark all prefixes as invalid */
	pa_for_each_cp(cp, data) {
		if(!cp->authoritative)
			cp->invalid = true;
	}

	/* Compute designated */
	pa_for_each_iface(iface, data) {
		iface->designated = pa_core_iface_is_designated(core, iface);
	}

	pa_for_each_dp(dp, data) {

		if(pa_core_dp_ignore(core, dp))
			continue;


		pa_for_each_iface(iface, data) {

			if(!iface->internal)
				continue;

			cp = pa_core_getcp(core, dp, iface);
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
	pa_for_each_cp(cp, data) {
		if(cp->invalid)
			pa_core_destroy_cp(core, cp);
	}
}

void pa_core_update_excluded(struct pa_core *core, struct pa_ldp *ldp)
{
	bool create;

	if(ldp->excluded.cp) {
		/* Destroying previous cp */
		pa_updated_cp(core, ldp->excluded.cp, true, true, false);
		pa_cp_destroy(ldp->excluded.cp);
	}

	if(ldp->excluded.valid) {
		/* Creating new cp */
		ldp->excluded.cp = pa_cp_get(core_p(core, data), &ldp->excluded.excluded, &create);

		if(create) /* Otherwise, there is a problem */
			pa_updated_cp(core, ldp->excluded.cp, false, true, false);
	} else {
		ldp->excluded.cp = NULL;
	}
}

static void __pa_core_to_cb(struct uloop_timeout *to)
{
	struct pa_core *core = container_of(to, struct pa_core, timeout);
	pa_algo_do(core);
}

static void __pa_core_schedule(struct pa_core *core, bool first)
{
	if(core->timeout.pending)
		return;

	hnetd_time_t delay = core_pa(core)->flood.flooding_delay;

	if(!first)
		delay /= PA_CORE_DELAY_FACTOR;

	if(delay < PA_CORE_MIN_DELAY)
		delay = PA_CORE_MIN_DELAY;
	if(delay > INT32_MAX)
		delay = INT32_MAX;

	uloop_timeout_set(&core->timeout, (int) delay);
}

void pa_core_init(struct pa_core *core)
{
	core->scheduled = false;
	core->started = false;
	core->timeout.pending = false;
	core->timeout.cb = __pa_core_to_cb;
}

void pa_core_start(struct pa_core *core)
{
	if(core->started)
		return;

	core->started = true;
	if(core->scheduled)
		__pa_core_schedule(core, true);
}

void pa_core_stop(struct pa_core *core)
{
	if(!core->started)
		return;

	core->started = false;
	if(core->timeout.pending)
		uloop_timeout_cancel(&core->timeout);
}

void pa_core_term(struct pa_core *core)
{
	pa_core_stop(core);
	//todo: destroy cps and laas
}

void pa_core_schedule(struct pa_core *core)
{
	if(core->scheduled)
		return;

	core->scheduled = true;

	if(core->started)
		__pa_core_schedule(core, false);
}

void pa_address_schedule(struct pa_core *core)
{

}
