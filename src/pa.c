#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa - "

#include "pa.h"

#include "iface.h"

#define PA_FLOOD_DELAY_DEFAULT     5000
#define PA_FLOOD_DELAY_LL_DEFAULT  1000


/************************************/
/********** Main interface **********/
/************************************/

void pa_conf_set_defaults(struct pa_conf *conf)
{

#define PA_CONF_DFLT_USE_ULA             1
#define PA_CONF_DFLT_NO_ULA_IF_V6        1
#define PA_CONF_DFLT_USE_V4              1
#define PA_CONF_DFLT_NO_V4_IF_V6         0
#define PA_CONF_DFLT_USE_RDM_ULA         1
#define PA_CONF_DFLT_ULA_RDM_PLEN        48

#define PA_CONF_DFLT_LOCAL_VALID       600 * HNETD_TIME_PER_SECOND
#define PA_CONF_DFLT_LOCAL_PREFERRED   300 * HNETD_TIME_PER_SECOND
#define PA_CONF_DFLT_LOCAL_UPDATE      330 * HNETD_TIME_PER_SECOND

	conf->use_ula = PA_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PA_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_ipv4 = PA_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PA_CONF_DFLT_NO_V4_IF_V6;
	conf->use_random_ula = PA_CONF_DFLT_USE_RDM_ULA;
	conf->random_ula_plen = PA_CONF_DFLT_ULA_RDM_PLEN;

	conf->local_valid_lifetime = PA_CONF_DFLT_LOCAL_VALID;
	conf->local_preferred_lifetime = PA_CONF_DFLT_LOCAL_PREFERRED;
	conf->local_update_delay = PA_CONF_DFLT_LOCAL_UPDATE;

	conf->storage = NULL;
}

static void __pa_ifu_intiface(struct iface_user *u, const char *ifname, bool enabled);
static void __pa_ifu_pd(struct iface_user *u, __attribute__((unused))const char *ifname,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len);
static void __pa_ifu_ipv4(struct iface_user *u, bool available,
		const void *dhcp_data, size_t dhcp_len);

/************************************/
/************* Utilities ************/
/************************************/
static void __pa_iface_clean_maybe(struct pa *pa, struct pa_iface *iface)
{
	/* In case nobody cares about that interface */
	if(!iface->internal
			&& list_empty(&iface->aps)
			&& list_empty(&iface->cps)
			&& !iface->do_dhcp) {
		pa_iface_destroy(&pa->data, iface);
	}
}


/************************************/
/********** Main interface **********/
/************************************/

void pa_init(struct pa *pa, const struct pa_conf *conf)
{
	/* Set default flooding values */
	pa->flood.flooding_delay = PA_FLOOD_DELAY_DEFAULT;
	pa->flood.flooding_delay_ll = PA_FLOOD_DELAY_LL_DEFAULT;
	memset(&pa->flood.rid, 0, sizeof(struct pa_rid));

	/* Init data structures */
	pa_data_init(&pa->data);
	pa_core_init(&pa->core);
	pa_local_init(&pa->local);

	if(conf)
		memcpy(&pa->conf, conf, sizeof(struct pa_conf));
	else
		pa_conf_set_defaults(&pa->conf);

	memset(&pa->flood_cbs, 0, sizeof(struct pa_flood_callbacks));
	memset(&pa->iface_cbs, 0, sizeof(struct pa_iface_callbacks));
	pa->ifu.cb_intiface = __pa_ifu_intiface;
	pa->ifu.cb_prefix = __pa_ifu_pd;
	pa->ifu.cb_extdata = NULL; //TODO ?
	pa->ifu.ipv4_update = __pa_ifu_ipv4;
}

void pa_start(struct pa *pa)
{
	pa_core_start(&pa->core);
	pa_local_start(&pa->local);
	iface_register_user(&pa->ifu);
}

void pa_stop(struct pa *pa)
{
	pa_core_stop(&pa->core);
	pa_local_stop(&pa->local);
}

void pa_term(struct pa *pa)
{
	iface_unregister_user(&pa->ifu);
	pa_local_term(&pa->local);
	pa_core_term(&pa->core);
	pa_data_term(&pa->data);
	memset(&pa->flood_cbs, 0, sizeof(struct pa_flood_callbacks));
	memset(&pa->iface_cbs, 0, sizeof(struct pa_iface_callbacks));
}

/************************************/
/********* General private **********/
/************************************/

struct pa_ldp *__pa_update_ldp(struct pa *pa,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len, bool local)
{
	struct pa_ldp *ldp;
	bool created = false;
	bool excl = false;

	if(valid_until < 0)
		valid_until = 0;

	if(!(ldp = pa_ldp_get(&pa->data, prefix, valid_until?&created:NULL)))
		return NULL;


	if(created | !valid_until
			| pa_dp_set_lifetime(&ldp->dp, preferred_until, valid_until)
			| pa_dp_set_dhcp(&ldp->dp, dhcp_data, dhcp_len)
			| (excl = pa_ldp_set_excluded(ldp, excluded))) {


		/* Tell core */
		pa_core_schedule(&pa->core);
		if(excl)
			pa_core_update_excluded(&pa->core, ldp);

		/* Tell flood */
		if(pa->flood_cbs.updated_ldp)
			pa->flood_cbs.updated_ldp(&ldp->dp.prefix, ldp->dp.valid_until, ldp->dp.preferred_until,
					ldp->dp.dhcp_data, ldp->dp.dhcp_len, pa->flood_cbs.priv);

		/* Tell local if not local */
		if(!local)
			pa_local_schedule(&pa->local);
	}

	if(valid_until)
		return ldp;

	pa_ldp_destroy(ldp);
	return NULL;
}

/************************************/
/********* Iface interface **********/
/************************************/

void pa_iface_subscribe(struct pa *pa, const struct pa_iface_callbacks *cb)
{
	L_DEBUG("Iface just subscribed (%d,%d)",
			!!cb->update_link_owner, !!cb->update_prefix);
	memcpy(&pa->iface_cbs, cb, sizeof(struct pa_iface_callbacks));
}

static void __pa_ifu_intiface(struct iface_user *u, const char *ifname, bool enabled)
{
	struct pa *pa = container_of(u, struct pa, ifu);

	struct pa_iface *iface;
	bool created = false;

	if(!(iface = pa_iface_get(&pa->data, ifname, &created)))
		return;

	if(pa_iface_set_internal(iface, enabled))
		pa_core_schedule(&pa->core);

	if(!enabled)
		__pa_iface_clean_maybe(pa, iface);
}

static void __pa_ifu_pd(struct iface_user *u, __attribute__((unused))const char *ifname,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len)
{
	struct pa *pa = container_of(u, struct pa, ifu);
	__pa_update_ldp(pa, prefix, excluded, valid_until, preferred_until, dhcp_data, dhcp_len, false);
}

static void __pa_ifu_ipv4(struct iface_user *u, bool available,
		const void *dhcp_data, size_t dhcp_len)
{
	struct pa *pa = container_of(u, struct pa, ifu);
	pa_local_update_ipv4(&pa->local, available, dhcp_data, dhcp_len);
}


/************************************/
/********** Hcp interface ***********/
/************************************/

void pa_flood_subscribe(struct pa *pa, const struct pa_flood_callbacks *cb)
{
	L_DEBUG("Flooding protocol just subscribed (%d,%d)",
			!!cb->updated_lap, !!cb->updated_ldp);
	memcpy(&pa->flood_cbs, cb, sizeof(struct pa_flood_callbacks));
}

void pa_set_rid(struct pa *pa, const struct pa_rid *rid)
{
	memcpy(&pa->flood.rid, rid, sizeof(struct pa_rid));
	pa_core_schedule(&pa->core);
	pa_local_schedule(&pa->local);
}

int pa_update_ap(struct pa *pa, const struct prefix *prefix,
		const struct pa_rid *rid,
		const char *ifname, bool authoritative, uint8_t priority,
		bool to_delete)
{
	struct pa_ap *ap;
	struct pa_iface *iface;
	bool created = false;

	iface = ifname?pa_iface_get(&pa->data, ifname, &created):NULL;

	if(!(ap = pa_ap_get(&pa->data, prefix, rid, (to_delete)?NULL:&created)))
		return (to_delete)?0:-1;

	if(to_delete | created | pa_ap_set_iface(ap, iface)
			| pa_ap_set_authoritative(ap, authoritative)
			| pa_ap_set_priority(ap, priority))
		pa_core_schedule(&pa->core); /* Tell core */

	if(to_delete) {
		pa_ap_destroy(&pa->data, ap);
		__pa_iface_clean_maybe(pa, iface);
	}

	return 0;
}

int pa_update_edp(struct pa *pa, const struct prefix *prefix,
				const struct pa_rid *rid,
				hnetd_time_t valid_until, hnetd_time_t preferred_until,
				const void *dhcp_data, size_t dhcp_len)
{
	struct pa_edp *edp;
	bool created = false;

	if(valid_until < 0)
		valid_until = 0;

	if(!(edp = pa_edp_get(&pa->data, prefix, rid, valid_until?&created:NULL)))
		return valid_until?-1:0;

	if(created | !valid_until
			| pa_dp_set_lifetime(&edp->dp, preferred_until, valid_until)
			| pa_dp_set_dhcp(&edp->dp, dhcp_data, dhcp_len)) {
		pa_core_schedule(&pa->core);
		pa_local_schedule(&pa->local);
	}

	if(!valid_until)
		pa_edp_destroy(edp);

	return 0;
}

int pa_update_eaa(struct pa *pa, const struct in6_addr *addr,
				const struct pa_rid *rid, bool to_delete)
{
	struct pa_eaa *eaa;
	bool created = false;

	if(!(eaa = pa_eaa_get(&pa->data, addr, rid, to_delete?NULL:&created)))
		return to_delete?0:-1;

	if(created | to_delete)
		pa_address_schedule(&pa->core);

	if(to_delete)
		pa_eaa_destroy(eaa);

	return 0;
}

/************************************/
/******** pa_core interface *********/
/************************************/

void pa_updated_cp(struct pa_core *core, struct pa_cp *cp, bool to_delete, bool tell_flood, bool tell_iface)
{
	struct pa *pa = container_of(core, struct pa, core);

	/* Tell flood */
	if(tell_flood && pa->flood_cbs.updated_lap)
		pa->flood_cbs.updated_lap(&cp->prefix, (cp->iface)?cp->iface->ifname:NULL,
				cp->authoritative, cp->priority,
				to_delete || !cp->advertised, pa->flood_cbs.priv);

	/* Tell iface */
	if(tell_iface && pa->iface_cbs.update_prefix) {
			if(to_delete)
				cp->applied = false;
			pa->iface_cbs.update_prefix(&cp->prefix, cp->iface?cp->iface->ifname:NULL,
					cp->applied?cp->dp->valid_until:0, cp->applied?cp->dp->preferred_until:0,
					cp->dp->dhcp_data, cp->dp->dhcp_len, pa->iface_cbs.priv);
	}
}

void pa_updated_laa(struct pa_core *core, struct pa_laa *laa, bool to_delete)
{
	struct pa *pa = container_of(core, struct pa, core);
	/* Tell flood */
	if(pa->flood_cbs.updated_laa)
		pa->flood_cbs.updated_laa(&laa->aa.address, (laa->cp->iface)?laa->cp->iface->ifname:NULL,
				to_delete, pa->flood_cbs.priv);

	/* Tell iface */
	if(laa->applied && pa->iface_cbs.update_address && laa->cp->iface) {
		if(to_delete)
			laa->applied = false;
		pa->iface_cbs.update_address(laa->cp->iface->ifname, &laa->aa.address, to_delete, pa->iface_cbs.priv);
	}
}

void pa_updated_dodhcp(struct pa_core *core, struct pa_iface *iface)
{
	struct pa *pa = container_of(core, struct pa, core);
	/* Tell iface */
	if(pa->iface_cbs.update_link_owner)
		pa->iface_cbs.update_link_owner(iface->ifname, iface->do_dhcp, pa->iface_cbs.priv);

	if(!iface->do_dhcp)
		__pa_iface_clean_maybe(pa, iface);
}


/************************************/
/******** pa_data callbacks *********/
/************************************/

void pa_cp_apply(struct pa_data *data, struct pa_cp *cp)
{
	struct pa *pa = container_of(data, struct pa, data);
	/* Tell iface */
	if(!cp->applied && pa->iface_cbs.update_prefix && cp->iface && cp->dp) {
		cp->applied = true;
		//Todo: Find a more clever way to manage cp->dp
		//Todo: Tell do_dhcp if needed
		pa->iface_cbs.update_prefix(&cp->prefix, cp->iface->ifname,
				cp->dp->valid_until, cp->dp->preferred_until,
				cp->dp->dhcp_data, cp->dp->dhcp_len, pa->iface_cbs.priv);
	}
}

void pa_laa_apply(struct pa_data *data, struct pa_laa *laa)
{
	struct pa *pa = container_of(data, struct pa, data);
	/* Tell iface */
	if(!laa->applied && pa->iface_cbs.update_address && laa->cp->iface) {
		laa->applied = true;
		pa->iface_cbs.update_address(laa->cp->iface->ifname, &laa->aa.address, false, pa->iface_cbs.priv);
	}
}


/************************************/
/******* pa_local interface *********/
/************************************/

void pa_update_local(struct pa_core *core,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len)
{
	__pa_update_ldp(container_of(core, struct pa, core), prefix, excluded,
			valid_until, preferred_until, dhcp_data, dhcp_len, true);
}

