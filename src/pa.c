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

	pa_data_conf_defaults(&conf->data_conf);
	pa_local_conf_defaults(&conf->local_conf);
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
	pa_data_init(&pa->data, conf?&conf->data_conf:NULL);
	pa_store_init(&pa->store);
	pa_core_init(&pa->core);
	pa_local_init(&pa->local, conf?&conf->local_conf:NULL);

	memset(&pa->ifu, 0, sizeof(struct iface_user));
	pa->ifu.cb_intiface = __pa_ifu_intiface;
	pa->ifu.cb_prefix = __pa_ifu_pd;
	pa->ifu.ipv4_update = __pa_ifu_ipv4;
}

void pa_start(struct pa *pa)
{
	if(!pa->started) {
		L_NOTICE("Starting prefix assignment");
		pa->started = true;

		pa_store_start(&pa->store);
		pa_core_start(&pa->core);
		pa_local_start(&pa->local);
		iface_register_user(&pa->ifu);
	}
}

void pa_stop(struct pa *pa)
{
	if(pa->started) {
		L_NOTICE("Stopping prefix assignment");
		iface_unregister_user(&pa->ifu);
		pa_local_stop(&pa->local);
		pa_core_stop(&pa->core);
		pa_store_stop(&pa->store);
		pa->started = false;
	}
}

void pa_term(struct pa *pa)
{
	L_NOTICE("Terminating prefix assignment structures");

	pa_stop(pa);
	pa_local_term(&pa->local);
	pa_core_term(&pa->core);
	pa_store_term(&pa->store);
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

	if(valid_until >= hnetd_time()) {

		pa_ldp_set_excluded(ldp, excluded);
		pa_dp_set_lifetime(&ldp->dp, preferred_until, valid_until);
		pa_dp_set_dhcp(&ldp->dp, dhcp_data, dhcp_len);

		if(ifname)
			iface = pa_iface_get(&pa->data, ifname, true);
		pa_ldp_set_iface(ldp, iface);

		if(iface)
			pa_iface_notify(&pa->data, iface);
	} else {
		pa_dp_todelete(&ldp->dp);
	}

	pa_dp_notify(&pa->data, &ldp->dp);
}

static void __pa_ifu_ipv4(struct iface_user *u, char *ifname,
		const void *dhcp_data, __unused size_t dhcp_len)
{
	struct pa *pa = container_of(u, struct pa, ifu);
	struct pa_iface *iface = NULL;
	if(ifname)
		iface = pa_iface_get(&pa->data, ifname, true);

	if(!iface)
		return;

	pa_iface_notify(&pa->data, iface);
	iface->ipv4_uplink = dhcp_data?true:false;

	if((pa->data.ipv4.iface == iface && !iface->ipv4_uplink) ||
			(!pa->data.ipv4.iface && iface->ipv4_uplink)) {
		iface = NULL;
		bool found = false;
		pa_for_each_iface(iface, &pa->data) {
			if(iface->ipv4_uplink) {
				found = true;
				break;
			}
		}
		if(!found)
			iface = NULL;

		L_INFO("Changing IPv4 uplink to iface = "PA_IFNAME_L"", PA_IFNAME_LA(iface));
		pa_ipv4_set_dhcp(&pa->data, NULL, 0);
		pa_ipv4_set_uplink(&pa->data, iface);
		pa_ipv4_notify(&pa->data);
	}
}
