#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa - "

#include "pa.h"

/************************************/
/********** Main interface **********/
/************************************/

void pa_conf_set_defaults(struct pa_conf *conf)
{
	L_DEBUG("Setting configuration options to default");

#define PA_CONF_DFLT_USE_ULA             1
#define PA_CONF_DFLT_NO_ULA_IF_V6        1
#define PA_CONF_DFLT_USE_V4              1
#define PA_CONF_DFLT_NO_V4_IF_V6         0
#define PA_CONF_DFLT_USE_RDM_ULA         1
#define PA_CONF_DFLT_ULA_RDM_PLEN        48

#define PA_CONF_DFLT_LOCAL_VALID       600 * HNETD_TIME_PER_SECOND
#define PA_CONF_DFLT_LOCAL_PREFERRED   300 * HNETD_TIME_PER_SECOND
#define PA_CONF_DFLT_LOCAL_UPDATE      330 * HNETD_TIME_PER_SECOND

#define PA_CONF_DFLT_MAX_SP      100
#define PA_CONF_DFLT_MAX_SP_P_IF 10

	conf->use_ula = PA_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PA_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_ipv4 = PA_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PA_CONF_DFLT_NO_V4_IF_V6;
	conf->use_random_ula = PA_CONF_DFLT_USE_RDM_ULA;
	conf->random_ula_plen = PA_CONF_DFLT_ULA_RDM_PLEN;

	conf->local_valid_lifetime = PA_CONF_DFLT_LOCAL_VALID;
	conf->local_preferred_lifetime = PA_CONF_DFLT_LOCAL_PREFERRED;
	conf->local_update_delay = PA_CONF_DFLT_LOCAL_UPDATE;

	conf->max_sp = PA_CONF_DFLT_MAX_SP;
	conf->max_sp_per_if = PA_CONF_DFLT_MAX_SP_P_IF;
}

static void __pa_ifu_intiface(struct iface_user *u, const char *ifname, bool enabled);
static void __pa_ifu_pd(struct iface_user *u, __attribute__((unused))const char *ifname,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len);
static void __pa_ifu_ipv4(struct iface_user *u, char *ifname,
		const void *dhcp_data, size_t dhcp_len);

/************************************/
/********** Main interface **********/
/************************************/

void pa_init(struct pa *pa, const struct pa_conf *conf)
{
	L_NOTICE("Initializing prefix assignment structures");

	pa->started = false;

	/* Init data structures */
	pa_data_init(&pa->data);
	pa_core_init(&pa->core);
	pa_local_init(&pa->local);

	if(conf)
		memcpy(&pa->conf, conf, sizeof(struct pa_conf));
	else
		pa_conf_set_defaults(&pa->conf);

	pa->ifu.cb_intiface = __pa_ifu_intiface;
	pa->ifu.cb_prefix = __pa_ifu_pd;
	pa->ifu.cb_extdata = NULL; //TODO ?
	pa->ifu.ipv4_update = __pa_ifu_ipv4;
}

void pa_start(struct pa *pa)
{
	L_NOTICE("Starting prefix assignment");

	if(!pa->started) {
		pa->started = true;
		pa_core_start(&pa->core);
		pa_local_start(&pa->local);
		iface_register_user(&pa->ifu);
	}
}

void pa_stop(struct pa *pa)
{
	L_NOTICE("Stopping prefix assignment");

	if(pa->started) {
		iface_unregister_user(&pa->ifu);
		pa_local_stop(&pa->local);
		pa_core_stop(&pa->core);
		pa->started = false;
	}
}

void pa_term(struct pa *pa)
{
	L_NOTICE("Terminating prefix assignment structures");

	pa_stop(pa);
	pa_local_term(&pa->local);
	pa_core_term(&pa->core);
	pa_data_term(&pa->data);
}

/************************************/
/********* Iface interface **********/
/************************************/

static void __pa_ifu_intiface(struct iface_user *u, const char *ifname, bool enabled)
{
	L_INFO("Iface callback for interior interface %s -> %s", ifname, enabled?"intern":"extern");

	struct pa *pa = container_of(u, struct pa, ifu);
	struct pa_iface *iface;

	if(!(iface = pa_iface_get(&pa->data, ifname, enabled)))
		return;

	pa_iface_set_internal(iface, enabled);
	pa_iface_notify(&pa->data, iface);
}

static void __pa_ifu_pd(struct iface_user *u, const char *ifname,
		const struct prefix *prefix, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len)
{
	L_INFO("Iface callback for delegated prefix %s", PREFIX_REPR(prefix));

	struct pa *pa = container_of(u, struct pa, ifu);
	struct pa_ldp *ldp;
	struct pa_iface *iface = NULL;
	if(!(ldp = pa_ldp_get(&pa->data, prefix, valid_until)))
		return;

	pa_ldp_set_excluded(ldp, excluded);
	pa_dp_set_lifetime(&ldp->dp, preferred_until, valid_until);
	pa_dp_set_dhcp(&ldp->dp, dhcp_data, dhcp_len);

	if(ifname)
		iface = pa_iface_get(&pa->data, ifname, true);
	pa_ldp_set_iface(ldp, iface);

	if(iface)
		pa_iface_notify(&pa->data, ldp);

	pa_dp_notify(&pa->data, &ldp->dp);
}

static void __pa_ifu_ipv4(struct iface_user *u, char *ifname,
		const void *dhcp_data, size_t dhcp_len)
{
	//TODO: Change iface.h callback type
	struct pa *pa = container_of(u, struct pa, ifu);
	struct pa_iface *iface = NULL;
	if(ifname)
		iface = pa_iface_get(&pa->data, ifname, true);

	L_INFO("Iface callback for IPv4 connectivity (iface = "PA_IFNAME_L")", PA_IFNAME_LA(iface));
	pa_ipv4_set_dhcp(&pa->data, dhcp_data, dhcp_len);
	pa_ipv4_set_uplink(&pa->data, iface);
	pa_ipv4_notify(&pa->data);
}


