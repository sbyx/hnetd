/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 */

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_local - "

#include "pa_local.h"
#include "pa.h"

#define local_pa(local) (container_of(local, struct pa, local))
#define local_rid(local) (&((local_pa(local))->flood.rid))
#define local_p(local, field) (&(local_pa(local)->field))

#define PA_LOCAL_MIN_DELAY 5

#define PA_LOCAL_CAN_CREATE 0x01
#define PA_LOCAL_CAN_KEEP	0x02

#define PAL_CONF_DFLT_USE_ULA             1
#define PAL_CONF_DFLT_NO_ULA_IF_V6        1
#define PAL_CONF_DFLT_USE_V4              1
#define PAL_CONF_DFLT_NO_V4_IF_V6         0
#define PAL_CONF_DFLT_USE_RDM_ULA         1
#define PAL_CONF_DFLT_ULA_RDM_PLEN        48

#define PAL_CONF_DFLT_LOCAL_VALID       600 * HNETD_TIME_PER_SECOND
#define PAL_CONF_DFLT_LOCAL_PREFERRED   300 * HNETD_TIME_PER_SECOND
#define PAL_CONF_DFLT_LOCAL_UPDATE      330 * HNETD_TIME_PER_SECOND

static struct prefix PAL_CONF_DFLT_V4_PREFIX = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff,  0x0a }},
		.plen = 104 };

static bool __pa_has_globalv6(struct pa_local *local)
{
	struct pa_dp *dp;
	pa_for_each_dp_down(dp, local_p(local, data), &ipv6_global_prefix) {
		return true;
	}
	return false;
}

static bool __pa_has_highest_rid(struct pa_local *local)
{
	struct pa_ap *ap;

	pa_for_each_ap(ap, local_p(local, data)) {
		if(PA_RIDCMP(&ap->rid, local_p(local, data.flood.rid)) > 0)
			return false;
	}

	struct pa_dp *dp;
	pa_for_each_dp(dp, local_p(local, data)) {
		if(!dp->local && PA_RIDCMP(&container_of(dp, struct pa_edp, dp)->rid, local_p(local, data.flood.rid)) > 0)
			return false;
	}

	return true;
}

static void __pa_local_elem_term(struct pa_local *local, struct pa_local_elem *elem)
{
	struct pa_ldp *ldp = elem->ldp;
	if(ldp) {
		pa_dp_todelete(&ldp->dp);
		pa_dp_notify(local_p(local, data), &ldp->dp);
		elem->ldp = NULL;
	}
	elem->create_start = 0;
	elem->timeout = 0;
}

static uint8_t pa_local_ula_get_status(struct pa_local *local, struct pa_local_elem *elem)
{
	if(!local->conf.use_ula
			|| (local->conf.no_ula_if_glb_ipv6 && __pa_has_globalv6(local)))
		return 0;

	struct pa_dp *dp;
	bool has_other = false;
	pa_for_each_dp_down(dp, local_p(local, data), &ipv6_ula_prefix) {
		if(dp->local) {
			if(dp != &elem->ldp->dp)
				return 0;
		} else {
			has_other = true;
			struct pa_edp *edp = container_of(dp, struct pa_edp, dp);
			if(PA_RIDCMP(&edp->rid, &local_p(local, data.flood)->rid) > 0)
				return 0;
		}
	}

	uint8_t status = PA_LOCAL_CAN_KEEP;
	if(!has_other && __pa_has_highest_rid(local))
		status |= PA_LOCAL_CAN_CREATE;

	return status;
}

static void pa_local_ula_create(struct pa_local *local, struct pa_local_elem *elem)
{
	const struct prefix *p = NULL;
	struct prefix pr;

	p = pa_store_ula_get(local_p(local, store));

	if(!p) {
		if(local->conf.use_random_ula) {
			if(!prefix_random(&ipv6_ula_prefix, &pr, local->conf.random_ula_plen))
				p = &pr;
		} else {
			p = &local->conf.ula_prefix;
		}
	}

	if(p)
		elem->ldp = pa_ldp_get(local_p(local, data), p, true);
}

static hnetd_time_t pa_local_generic_update(struct pa_local *local, struct pa_local_elem *elem, hnetd_time_t now)
{
	if(!elem->ldp)
		return 0;

	pa_dp_set_lifetime(&elem->ldp->dp,
			now + local->conf.local_preferred_lifetime,
			now + local->conf.local_valid_lifetime);
	pa_dp_notify(local_p(local, data), &elem->ldp->dp);

	return elem->ldp->dp.valid_until - local->conf.local_update_delay;
}

static uint8_t pa_local_ipv4_get_status(struct pa_local *local, struct pa_local_elem *elem)
{
	if(!local->conf.use_ipv4 ||
			!local_p(local, data.ipv4)->iface ||
			(local->conf.no_ipv4_if_glb_ipv6 && __pa_has_globalv6(local)))
		return 0;

	struct pa_dp *dp;
	bool has_other = false;
	pa_for_each_dp_down(dp, local_p(local, data), &ipv4_in_ipv6_prefix) {
		if(dp->local) {
			if(dp != &elem->ldp->dp)
				return 0;
		} else {
			has_other = true;
			struct pa_edp *edp = container_of(dp, struct pa_edp, dp);
			if(PA_RIDCMP(&edp->rid, &local_p(local, data.flood)->rid) > 0)
				return 0;
		}
	}

	return PA_LOCAL_CAN_KEEP | ((has_other)?0:(PA_LOCAL_CAN_CREATE));
}

static void pa_local_ipv4_create(struct pa_local *local, struct pa_local_elem *elem)
{
	elem->ldp = pa_ldp_get(local_p(local, data), &local->conf.v4_prefix, true);
	if(elem->ldp)
		pa_ldp_set_iface(elem->ldp, local_p(local, data.ipv4)->iface);
}

/* Generic function for IPv4 and ULA generation */
static void pa_local_algo(struct pa_local *local, struct pa_local_elem *elem, hnetd_time_t now)
{
	uint8_t status = elem->get_status(local, elem);
	if(!status)
		goto destroy;

	if(elem->ldp) {
		if(!(status & PA_LOCAL_CAN_KEEP)) {
			goto destroy;
		} else if (elem->timeout <= now) {
			elem->timeout = elem->update(local, elem, now);
		}
	} else if (status & PA_LOCAL_CAN_CREATE) {
		if(!elem->create_start) {
			elem->create_start = now;
			elem->timeout = now + 2*local_p(local, data.flood)->flooding_delay;
		} else if (now >= elem->create_start + 2*local_p(local, data.flood)->flooding_delay) {
			elem->create(local, elem);
			elem->create_start = 0;
			elem->timeout = elem->update(local, elem, now);
		}
	} else {
		elem->timeout = 0;
	}
	return;

destroy:
	__pa_local_elem_term(local, elem);
	return;
}

static void __pa_local_do(struct pa_local *local)
{
	L_INFO("Executing spontaneous prefix generation algorithm");
	hnetd_time_t now = hnetd_time();
	pa_local_algo(local, &local->ula, now);
	pa_local_algo(local, &local->ipv4, now);
	if(local->ipv4.timeout)
		pa_timer_set_earlier(&local->t, local->ipv4.timeout, false);
	if(local->ula.timeout)
		pa_timer_set_earlier(&local->t, local->ula.timeout, false);
}

static void __pa_local_do_cb(struct pa_timer *t)
{
	__pa_local_do(container_of(t, struct pa_local, t));
}

static void __pa_local_flood_cb(struct pa_data_user *user,
		__attribute__((unused))struct pa_flood *flood, uint32_t flags)
{
	struct pa_local *local = container_of(user, struct pa_local, data_user);
	if(flags & (PADF_FLOOD_RID | PADF_FLOOD_DELAY))
		pa_timer_set_earlier(&local->t, 0, true);
}

static void __pa_local_ipv4_cb(struct pa_data_user *user,
		__attribute__((unused))struct pa_ipv4 *ipv4, uint32_t flags)
{
	struct pa_local *local = container_of(user, struct pa_local, data_user);
	if(flags & PADF_IPV4_IFACE) {
		//Not best way to do it (destroyes the ldp), but changing interface should not happen so often
		__pa_local_elem_term(local, &local->ipv4);
		pa_timer_set_earlier(&local->t, 0, true);
	} else if(flags & PADF_IPV4_DHCP) { /* If only dhcp is changed, just update it */
		if(local->ipv4.ldp) {
			pa_dp_set_dhcp(&local->ipv4.ldp->dp, local_p(local, data.ipv4)->dhcp_data, local_p(local, data.ipv4)->dhcp_len);
			pa_dp_notify(local_p(local, data), &local->ipv4.ldp->dp);
		}
	}
}

static void __pa_local_dps_cb(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	struct pa_local *local = container_of(user, struct pa_local, data_user);
	if((flags & (PADF_DP_CREATED | PADF_DP_TODELETE)) && (!local->ipv4.ldp || &local->ipv4.ldp->dp != dp) &&
			(!local->ula.ldp || &local->ula.ldp->dp != dp))
		pa_timer_set_earlier(&local->t, 0, true);
}

void pa_local_conf_defaults(struct pa_local_conf *conf)
{
	conf->use_ula = PAL_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PAL_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_ipv4 = PAL_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PAL_CONF_DFLT_NO_V4_IF_V6;
	conf->use_random_ula = PAL_CONF_DFLT_USE_RDM_ULA;
	conf->random_ula_plen = PAL_CONF_DFLT_ULA_RDM_PLEN;

	prefix_cpy(&conf->v4_prefix, &PAL_CONF_DFLT_V4_PREFIX);

	conf->local_valid_lifetime = PAL_CONF_DFLT_LOCAL_VALID;
	conf->local_preferred_lifetime = PAL_CONF_DFLT_LOCAL_PREFERRED;
	conf->local_update_delay = PAL_CONF_DFLT_LOCAL_UPDATE;
}

void pa_local_init(struct pa_local *local, const struct pa_local_conf *conf)
{
	if(conf)
		memcpy(&local->conf, conf, sizeof(struct pa_data_conf));
	else
		pa_local_conf_defaults(&local->conf);

	pa_timer_init(&local->t, __pa_local_do_cb, "Spontaneous Prefix Generation");
	local->t.min_delay = PA_LOCAL_MIN_DELAY;

	local->ula.ldp = NULL;
	local->ula.create = pa_local_ula_create;
	local->ula.get_status = pa_local_ula_get_status;
	local->ula.update = pa_local_generic_update;
	local->ula.timeout = 0;
	local->ula.create_start = 0;

	local->ipv4.ldp = NULL;
	local->ipv4.create = pa_local_ipv4_create;
	local->ipv4.get_status = pa_local_ipv4_get_status;
	local->ipv4.update = pa_local_generic_update;
	local->ipv4.timeout = 0;
	local->ipv4.create_start = 0;

	memset(&local->data_user, 0, sizeof(struct pa_data_user));
	local->data_user.flood = __pa_local_flood_cb;
	local->data_user.ipv4 = __pa_local_ipv4_cb;
	local->data_user.dps = __pa_local_dps_cb;

	//todo: DO not generate if no internal interface ?
}

void pa_local_start(struct pa_local *local)
{
	if(local->t.enabled)
		return;

	pa_timer_enable(&local->t);
	pa_timer_set_not_before(&local->t, local_p(local, data.flood)->flooding_delay, true);
	pa_timer_set_earlier(&local->t, 0, true);

	pa_data_subscribe(local_p(local, data), &local->data_user);
}

void pa_local_stop(struct pa_local *local)
{
	if(!local->t.enabled)
		return;

	pa_data_unsubscribe(&local->data_user);
	__pa_local_elem_term(local, &local->ipv4);
	__pa_local_elem_term(local, &local->ula);

	pa_timer_disable(&local->t);
}

void pa_local_term(struct pa_local *local)
{
	pa_local_stop(local);
}
