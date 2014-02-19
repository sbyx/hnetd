
#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_data - "

#include "pa_data.h"

#include <stdio.h>

#define PA_P_ALLOC(pa_struct) \
	do { \
		pa_struct = malloc(sizeof(*pa_struct)); \
		if(!pa_struct) { \
			L_ERR("malloc(%lu) failed in %s", (unsigned long)sizeof(*pa_struct), __FUNCTION__);\
			return NULL; \
		} \
	} while(0)

#define PA_SET_SCALAR(value, newvalue, flag, newflag) \
	if(value != newvalue) { \
		value = newvalue; \
		flag |= newflag; \
	}

#define PA_NOTIFY(data, function, object, destroy)	\
	struct pa_data_user *user; 						\
	if(!(object)->__flags) 							\
		return; 									\
	uint32_t f = (object)->__flags;					\
	(object)->__flags = 0; 							\
	list_for_each_entry(user, &(data)->users, le) { \
		if((user)->function) 						\
		user->function(user, object, f);			\
	} 												\
	if(f & PADF_ALL_TODELETE)	{ destroy; }

#define PA_SET_IFACE(object, iface, listname, flags)  \
	if((object)->iface == iface) \
		return; \
	if((object)->iface) \
		list_remove(&(object)->if_le); \
	if(iface) \
		list_add(&(object)->if_le, &(iface)->listname); \
	(object)->iface = iface; \
	flags |= PADF_ALL_IFACE;


/* Generic way to change dhcp data */
static int __pa_set_dhcp(void **dhcp_data, size_t *dhcp_len,
		const void *new_dhcp_data, size_t new_dhcp_len,
		uint32_t *flags)
{
	void *new_data;

	if(!new_dhcp_data || !new_dhcp_len) {
		new_dhcp_data = NULL;
		new_dhcp_len = 0;
	}

	if(*dhcp_len == new_dhcp_len && (!new_dhcp_len || !memcmp(*dhcp_data, new_dhcp_data, new_dhcp_len)))
		return 0;


	if(*dhcp_data)
		free(*dhcp_data);

	if(new_dhcp_data) {
		new_data = malloc(new_dhcp_len);
		if(!new_data) {
			L_ERR("malloc(%lu) failed in while setting dhcp data value", (unsigned long)dhcp_len);
			new_dhcp_len = 0;
			*flags |= PADF_ALL_ERROR;
		} else {
			memcpy(new_data, new_dhcp_data, new_dhcp_len);
		}
	} else {
		new_data = NULL;
	}

	*dhcp_data = new_data;
	*dhcp_len = new_dhcp_len;
	*flags |= PADF_ALL_DHCP;
	return 1;
}


static int pa_data_avl_prefix_cmp (const void *k1, const void *k2,
		__attribute__((unused))void *ptr)
{
	int i = prefix_cmp((struct prefix *)k1, (struct prefix *)k2);
	if(!i)
		return 0;
	return (i>0)?1:-1;
}

void pa_dp_init(struct pa_data *data, struct pa_dp *dp, const struct prefix *p)
{
	dp->dhcp_data = NULL;
	dp->dhcp_len = 0;
	dp->preferred_until = 0;
	dp->valid_until = 0;
	prefix_cpy(&dp->prefix, p);
	INIT_LIST_HEAD(&dp->cps);
	list_add(&dp->le, &data->dps);
	dp->__flags = PADF_DP_CREATED;
	L_DEBUG("Initialized "PA_DP_L, PA_DP_LA(dp));
}

void pa_dp_set_dhcp(struct pa_dp *dp, const void *dhcp_data, size_t dhcp_len)
{
	if(__pa_set_dhcp(&dp->dhcp_data, &dp->dhcp_len, dhcp_data, dhcp_len, &dp->__flags)) {
		L_DEBUG("Changing "PA_DP_L" dhcp (length %lu)", PA_DP_LA(dp), dhcp_len);
	}
}

void pa_dp_set_lifetime(struct pa_dp *dp, hnetd_time_t preferred, hnetd_time_t valid)
{
	if(dp->preferred_until == preferred &&
			dp->valid_until == valid)
		return;

	L_DEBUG("Changing "PA_DP_L " lifetimes (%ld, %ld)", PA_DP_LA(dp), preferred, valid);

	dp->preferred_until = preferred;
	dp->valid_until = valid;
	dp->__flags |= PADF_DP_LIFETIME;
}

void pa_dp_destroy(struct pa_dp *dp)
{
	L_DEBUG("Terminating "PA_DP_L, PA_DP_LA(dp));
	while(!(list_empty(&dp->cps))) {
		pa_cp_set_dp(list_first_entry(&dp->cps, struct pa_cp, dp_le), NULL);
	}
	pa_dp_set_dhcp(dp, NULL, 0);
	list_remove(&dp->le);
	if(dp->local) {
		struct pa_ldp *ldp = container_of(dp, struct pa_ldp, dp);
		if(ldp->iface)
			list_remove(&ldp->if_le);
		free(ldp);
	} else {
		struct pa_edp *edp = container_of(dp, struct pa_edp, dp);
		free(edp);
	}
}

void pa_dp_notify(struct pa_data *data, struct pa_dp *dp)
{
	PA_NOTIFY(data, dps, dp, pa_dp_destroy(dp));
}

struct pa_ldp *__pa_ldp_get(struct pa_data *data, const struct prefix *p)
{
	struct pa_dp *dp;
	pa_for_each_dp(dp, data) {
		if(dp->local && !prefix_cmp(p, &dp->prefix))
			return container_of(dp, struct pa_ldp, dp);
	}
	return NULL;
}

struct pa_ldp *pa_ldp_get(struct pa_data *data, const struct prefix *p, bool goc)
{
	struct pa_ldp *ldp;

	if((ldp = __pa_ldp_get(data, p)) || !goc)
		return ldp;

	PA_P_ALLOC(ldp);
	ldp->dp.local = true;
	pa_dp_init(data, &ldp->dp, p);
	ldp->excluded.valid = false;
	ldp->excluded.cp = NULL;
	ldp->iface = NULL;
	ldp->dp.__flags = PADF_DP_CREATED;
	return ldp;
}

void pa_ldp_set_excluded(struct pa_ldp *ldp, const struct prefix *excluded)
{
	if((!excluded && !ldp->excluded.valid) ||
			(excluded && ldp->excluded.valid && !prefix_cmp(excluded, &ldp->excluded.excluded)))
			return;

	if(excluded) {
		prefix_cpy(&ldp->excluded.excluded, excluded);
		ldp->excluded.valid = true;
	} else {
		ldp->excluded.valid = false;
	}

	ldp->dp.__flags |= PADF_LDP_EXCLUDED;
}

void pa_ldp_set_iface(struct pa_ldp *ldp, struct pa_iface *iface)
{
	PA_SET_IFACE(ldp, iface, ldps, ldp->dp.__flags);
}

struct pa_edp *__pa_edp_get(struct pa_data *data, const struct prefix *p, const struct pa_rid *rid)
{
	struct pa_dp *dp;
	struct pa_edp *edp;
	pa_for_each_dp(dp, data) {
		if(dp->local)
			continue;
		edp = container_of(dp, struct pa_edp, dp);
		if(!prefix_cmp(p, &dp->prefix) && !PA_RIDCMP(rid, &edp->rid))
			return edp;
	}
	return NULL;
}

struct pa_edp *pa_edp_get(struct pa_data *data, const struct prefix *p,
		const struct pa_rid *rid, bool goc)
{
	struct pa_edp *edp;

	if((edp = __pa_edp_get(data, p, rid)) || !goc)
		return edp;

	PA_P_ALLOC(edp);
	edp->dp.local = false;
	pa_dp_init(data, &edp->dp, p);
	PA_RIDCPY(&edp->rid, rid);
	edp->dp.__flags = PADF_DP_CREATED;
	return edp;
}

struct pa_ap *__pa_ap_get(struct pa_data *data, const struct prefix *p, const struct pa_rid *rid)
{
	struct pa_ap *ap, *first, *last;

	first = avl_find_ge_element(&data->aps, p, ap, avl_node);
	last = avl_find_le_element(&data->aps, p, ap, avl_node);

	if(!(first && last))
		return NULL;

	avl_for_element_range(first, last, ap, avl_node) {
		if(!PA_RIDCMP(rid, &ap->rid))
			return ap;
	}

	return NULL;
}

struct pa_ap *pa_ap_get(struct pa_data *data, const struct prefix *p,
		const struct pa_rid *rid, bool goc)
{
	struct pa_ap *ap;
	if((ap = __pa_ap_get(data, p, rid)) || !goc)
		return ap;

	PA_P_ALLOC(ap);
	ap->authoritative = false;
	ap->priority = PAD_PRIORITY_DEFAULT;
	ap->iface = NULL;
	prefix_cpy(&ap->prefix, p);
	PA_RIDCPY(&ap->rid, rid);
	ap->avl_node.key = &ap->prefix;
	if(avl_insert(&data->aps, &ap->avl_node)) {
		L_ERR("Could not insert "PA_AP_L" in avl_tree", PA_AP_LA(ap));
		free(ap);
		return NULL;
	}
	ap->__flags = PADF_AP_CREATED;
	L_INFO("Created "PA_AP_L, PA_AP_LA(ap));
	return ap;
}

void pa_ap_set_iface(struct pa_ap *ap, struct pa_iface *iface)
{
	PA_SET_IFACE(ap, iface, aps, ap->__flags);
}

void pa_ap_set_priority(struct pa_ap *ap, uint8_t priority)
{
	PA_SET_SCALAR(ap->priority, priority, ap->__flags, PADF_AP_PRIORITY);
}

void pa_ap_set_authoritative(struct pa_ap *ap, bool authoritative)
{
	PA_SET_SCALAR(ap->authoritative, authoritative, ap->__flags, PADF_AP_AUTHORITY);
}

void pa_ap_destroy(struct pa_data *data, struct pa_ap *ap)
{
	L_DEBUG("Destroying "PA_AP_L, PA_AP_LA(ap));
	pa_ap_set_iface(ap, NULL);
	avl_delete(&data->aps, &ap->avl_node);
	free(ap);
}

void pa_ap_notify(struct pa_data *data, struct pa_ap *ap)
{
	PA_NOTIFY(data, aps, ap, pa_ap_destroy(data, ap));
}

struct pa_laa *pa_laa_create(const struct in6_addr *addr, struct pa_cp *cp)
{
	struct pa_laa *laa;

	if(cp->laa || !addr)
			return NULL;

	PA_P_ALLOC(laa);
	laa->cp = cp;
	cp->laa = laa;
	memcpy(&laa->aa.address, addr, sizeof(struct in6_addr));
	laa->aa.local = true;
	laa->applied = false;
	laa->apply_to.pending = false;
	laa->apply_to.cb = NULL;
	laa->aa.__flags = PADF_AA_CREATED;
	L_DEBUG("Created "PA_AA_L, PA_AA_LA(&laa->aa));
	return laa;
}

void pa_laa_set_applied(struct pa_laa *laa, bool applied)
{
	PA_SET_SCALAR(laa->applied, applied, laa->aa.__flags, PADF_LAA_APPLIED);
}

void pa_aa_destroy(struct pa_aa *aa)
{
	L_DEBUG("Destroying "PA_AA_L, PA_AA_LA(aa));

	if(aa->local) {
		struct pa_laa *laa = container_of(aa, struct pa_laa, aa);
		if(laa->cp)
			laa->cp->laa = NULL;
		if(laa->apply_to.pending)
			uloop_timeout_cancel(&laa->apply_to);
		free(laa);
	} else {
		struct pa_eaa *eaa = container_of(aa, struct pa_eaa, aa);
		pa_eaa_set_iface(eaa, NULL);
		list_remove(&eaa->le);
		free(eaa);
	}
}

struct pa_cp *__pa_cp_get(struct pa_data *data, const struct prefix *prefix)
{
	struct pa_cp *cp;
	pa_for_each_cp(cp, data) {
		if(!prefix_cmp(prefix, &cp->prefix))
			return cp;
	}
	return NULL;
}

struct pa_cp *pa_cp_get(struct pa_data *data, const struct prefix *prefix, bool goc)
{
	struct pa_cp *cp;

	if((cp = __pa_cp_get(data, prefix)) || !goc)
		return cp;

	PA_P_ALLOC(cp);
	prefix_cpy(&cp->prefix, prefix);
	cp->pa_data = data;

	cp->laa = NULL;
	cp->advertised = false;
	cp->applied = false;
	cp->authoritative = false;
	cp->priority = PAD_PRIORITY_DEFAULT;
	cp->iface = NULL;
	cp->invalid = false;
	list_add(&cp->le, &data->cps);
	cp->apply_to.pending = false;
	cp->apply_to.cb = NULL;
	cp->dp = NULL;
	cp->__flags = PADF_CP_CREATED;
	L_DEBUG("Created "PA_CP_L, PA_CP_LA(cp));
	return cp;
}

void pa_cp_set_iface(struct pa_cp *cp, struct pa_iface *iface)
{
	PA_SET_IFACE(cp, iface, cps, cp->__flags);
}

void pa_cp_set_dp(struct pa_cp *cp, struct pa_dp *dp)
{
	if(cp->dp == dp)
		return;

	if(cp->dp)
		list_remove(&cp->dp_le);

	if(dp)
		list_add(&cp->dp_le, &dp->cps);

	cp->dp = dp;
	cp->__flags |= PADF_CP_DP;
}

void pa_cp_set_priority(struct pa_cp *cp, uint8_t priority)
{
	PA_SET_SCALAR(cp->priority, priority, cp->__flags, PADF_CP_PRIORITY);
}

void pa_cp_set_authoritative(struct pa_cp *cp, bool authoritative)
{
	PA_SET_SCALAR(cp->authoritative, authoritative, cp->__flags, PADF_CP_AUTHORITY);
}

void pa_cp_set_advertised(struct pa_cp *cp, bool adv)
{
	PA_SET_SCALAR(cp->advertised, adv, cp->__flags, PADF_CP_ADVERTISE);
}

void pa_cp_set_applied(struct pa_cp *cp, bool applied)
{
	PA_SET_SCALAR(cp->applied, applied, cp->__flags, PADF_CP_APPLIED);
}

void pa_cp_destroy(struct pa_cp *cp)
{
	L_DEBUG("Destroying "PA_CP_L, PA_CP_LA(cp));
	pa_cp_set_dp(cp, NULL);
	pa_cp_set_iface(cp, NULL);
	if(cp->laa)
		pa_aa_destroy(&cp->laa->aa);
	if(cp->apply_to.pending)
		uloop_timeout_cancel(&cp->apply_to);
	list_remove(&cp->le);
	free(cp);
}

void pa_cp_notify(struct pa_cp *cp)
{
	PA_NOTIFY(cp->pa_data, cps, cp, pa_cp_destroy(cp));
}

struct pa_eaa *__pa_eaa_get(struct pa_data *data, const struct in6_addr *addr, const struct pa_rid *rid)
{
	struct pa_eaa *eaa;
	pa_for_each_eaa(eaa, data) {
		if(!PA_RIDCMP(rid, &eaa->rid) &&
				!memcmp(addr, &eaa->aa.address, sizeof(struct in6_addr)))
			return eaa;
	}
	return NULL;
}

struct pa_eaa *pa_eaa_get(struct pa_data *data, const struct in6_addr *addr, const struct pa_rid *rid, bool goc)
{
	struct pa_eaa *eaa;

	if((eaa = __pa_eaa_get(data, addr, rid)) || !goc)
		return eaa;

	PA_P_ALLOC(eaa);
	PA_RIDCPY(&eaa->rid, rid);
	memcpy(&eaa->aa.address, addr, sizeof(struct in6_addr));
	eaa->aa.local = false;
	eaa->aa.__flags = PADF_AA_CREATED;
	eaa->iface = NULL;
	list_add(&eaa->le, &data->eaas);
	L_DEBUG("Created "PA_AA_L, PA_AA_LA(&eaa->aa));
	return eaa;
}

void pa_eaa_set_iface(struct pa_eaa *eaa, struct pa_iface *iface)
{
	PA_SET_IFACE(eaa, iface, eaas, eaa->aa.__flags);
}

void pa_aa_notify(struct pa_data *data, struct pa_aa *aa)
{
	PA_NOTIFY(data, aas, aa, pa_aa_destroy(aa));
}

struct pa_sp *__pa_sp_get(struct pa_iface *iface, const struct prefix *p)
{
	struct pa_sp *sp;
	pa_for_each_sp_in_iface(sp, iface) {
		if(!prefix_cmp(p, &sp->prefix))
			return sp;
	}
	return NULL;
}

void pa_sp_destroy(struct pa_data *data, struct pa_sp *sp)
{
	L_DEBUG("Destroying "PA_SP_L, PA_SP_LA(sp));
	--data->sp_count;
	--sp->iface->sp_count;
	list_remove(&sp->le);
	list_remove(&sp->if_le);
	free(sp);
}

struct pa_sp *pa_sp_get(struct pa_data *data, struct pa_iface *iface, const struct prefix *p, bool goc)
{
	struct pa_sp *sp;
	if((sp = __pa_sp_get(iface, p)) || !goc)
		return sp;

	if(!data->conf.max_sp || !data->conf.max_sp_per_if)
		return NULL;

	PA_P_ALLOC(sp);
	prefix_cpy(&sp->prefix, p);
	sp->iface = iface;
	list_add(&sp->if_le, &iface->sps);
	list_add(&sp->le, &data->sps);
	data->sp_count++;
	iface->sp_count++;
	L_DEBUG("Created "PA_SP_L, PA_SP_LA(sp));

	/* remove last if too many sps */
	struct pa_sp *last;
	if(data->conf.max_sp_per_if < iface->sp_count) {
		last = list_last_entry(&iface->sps, struct pa_sp, if_le);
		pa_sp_destroy(data, last);
	} else if (data->conf.max_sp < data->sp_count) {
		last = list_last_entry(&data->sps, struct pa_sp, le);
		pa_sp_destroy(data, last);
	}

	return sp;
}

void pa_sp_promote(struct pa_data *data, struct pa_sp *sp)
{
	L_DEBUG("Promoting "PA_SP_L, PA_SP_LA(sp));
	list_move(&sp->if_le, &sp->iface->sps);
	list_move(&sp->le, &data->sps);
}

struct pa_iface *__pa_iface_get(struct pa_data *data, const char *ifname)
{
	struct pa_iface *iface;
	pa_for_each_iface(iface, data) {
		if(!strcmp(iface->ifname, ifname))
			return iface;
	}
	return NULL;
}

struct pa_iface *pa_iface_get(struct pa_data *data, const char *ifname, bool goc)
{
	struct pa_iface *iface;

	if(strlen(ifname) >= IFNAMSIZ)
		return NULL;

	if((iface = __pa_iface_get(data, ifname)) || !goc)
		return iface;

	PA_P_ALLOC(iface);
	strcpy(iface->ifname, ifname);
	INIT_LIST_HEAD(&iface->aps);
	INIT_LIST_HEAD(&iface->cps);
	INIT_LIST_HEAD(&iface->eaas);
	INIT_LIST_HEAD(&iface->ldps);
	INIT_LIST_HEAD(&iface->sps);
	iface->designated = false;
	iface->do_dhcp = false;
	iface->internal = false;
	iface->is_ipv4_uplink = false;
	list_add(&iface->le, &data->ifs);
	iface->__flags = PADF_IF_CREATED;
	iface->sp_count = 0;
	L_INFO("Created "PA_IF_L, PA_IF_LA(iface));
	return iface;
}

void pa_iface_set_internal(struct pa_iface *iface, bool internal)
{
	PA_SET_SCALAR(iface->internal, internal, iface->__flags, PADF_IF_INTERNAL);
}

void pa_iface_set_dodhcp(struct pa_iface *iface, bool dodhcp)
{
	PA_SET_SCALAR(iface->do_dhcp, dodhcp, iface->__flags, PADF_IF_DODHCP);
}

void pa_iface_destroy(struct pa_data *data, struct pa_iface *iface)
{
	L_INFO("Destroying "PA_IF_L, PA_IF_LA(iface));

	if(iface->is_ipv4_uplink)
		data->ipv4.iface = NULL;

	while(!list_empty(&iface->aps))
		pa_ap_destroy(data, list_first_entry(&iface->aps, struct pa_ap, if_le));

	while(!list_is_empty(&iface->cps))
		pa_cp_destroy(list_first_entry(&iface->cps, struct pa_cp, if_le));

	while(!list_is_empty(&iface->ldps))
		pa_dp_destroy(&(list_first_entry(&iface->ldps, struct pa_ldp, if_le))->dp);

	while(!list_is_empty(&iface->eaas))
		pa_aa_destroy(&(list_first_entry(&iface->eaas, struct pa_eaa, if_le))->aa);

	while(!list_empty(&iface->sps))
		pa_sp_destroy(data, list_first_entry(&iface->sps, struct pa_sp, if_le));

	list_remove(&iface->le);
	free(iface);
}

void pa_iface_notify(struct pa_data *data, struct pa_iface *iface)
{
	PA_NOTIFY(data, ifs, iface, pa_iface_destroy(data, iface));
}

void pa_flood_set_rid(struct pa_data *data, const struct pa_rid *rid)
{
	if(!PA_RIDCMP(rid, &data->flood.rid))
		return;

	L_NOTICE("Setting rid "PA_RID_L, PA_RID_LA(rid));
	PA_RIDCPY(&data->flood.rid, rid);
	data->flood.__flags |= PADF_FLOOD_RID;
}

void pa_flood_set_flooddelays(struct pa_data *data, hnetd_time_t delay, hnetd_time_t ll_delay)
{
	if(data->flood.flooding_delay == delay && data->flood.flooding_delay_ll == ll_delay)
		return;

	L_INFO("Setting flooding delays %ld - %ld", delay, ll_delay);
	data->flood.flooding_delay = delay;
	data->flood.flooding_delay_ll = ll_delay;
	data->flood.__flags |= PADF_FLOOD_DELAY;
}

void pa_flood_notify(struct pa_data *data)
{
	PA_NOTIFY(data, flood, &data->flood, );
}

void pa_ipv4_set_uplink(struct pa_data *data, struct pa_iface *iface)
{
	if(data->ipv4.iface == iface)
		return;

	L_INFO("Setting IPv4 uplink interface "PA_IF_L, PA_IF_LA(iface));
	data->ipv4.iface = iface;
	if(iface)
		iface->is_ipv4_uplink = true;
	data->ipv4.__flags |= PADF_IPV4_IFACE;
}

void pa_ipv4_set_dhcp(struct pa_data *data, const void *dhcp_data, size_t dhcp_len)
{
	L_DEBUG("Setting IPv4 DHCP");
	__pa_set_dhcp(&data->ipv4.dhcp_data, &data->ipv4.dhcp_len,
			dhcp_data, dhcp_len, &data->ipv4.__flags);
}

void pa_ipv4_notify(struct pa_data *data)
{
	PA_NOTIFY(data, ipv4, &data->ipv4, );
}

void pa_data_subscribe(struct pa_data *data, struct pa_data_user *user)
{
	L_INFO("Somebody subscribed (%p).", user);
	list_add(&user->le, &data->users);
}

void pa_data_unsubscribe(struct pa_data_user *user)
{
	L_INFO("Somebody unsubscribed (%p).", user);
	list_remove(&user->le);
}

void pa_data_conf_defaults(struct pa_data_conf *conf)
{
	conf->max_sp = PAD_CONF_DFLT_MAX_SP;
	conf->max_sp_per_if = PAD_CONF_DFLT_MAX_SP_P_IF;
}

void pa_data_init(struct pa_data *data, const struct pa_data_conf *conf)
{
	L_NOTICE("Initializing data structure.");

	if(conf)
		memcpy(&data->conf, conf, sizeof(struct pa_data_conf));
	else
		pa_data_conf_defaults(&data->conf);

	avl_init(&data->aps, pa_data_avl_prefix_cmp, true, NULL);
	INIT_LIST_HEAD(&data->ifs);
	INIT_LIST_HEAD(&data->eaas);
	INIT_LIST_HEAD(&data->dps);
	INIT_LIST_HEAD(&data->cps);
	INIT_LIST_HEAD(&data->sps);
	INIT_LIST_HEAD(&data->users);

	data->flood.flooding_delay = PAD_FLOOD_DELAY_DEFAULT;
	data->flood.flooding_delay_ll = PAD_FLOOD_DELAY_LL_DEFAULT;
	memset(&data->flood.rid, 0, sizeof(struct pa_rid));
	data->flood.__flags = 0;

	data->ipv4.dhcp_data = NULL;
	data->ipv4.dhcp_len = 0;
	data->ipv4.iface = NULL;
	data->ipv4.__flags = 0;

	data->sp_count = 0;
}

void pa_data_term(struct pa_data *data)
{
	L_NOTICE("Terminating database structure.");

	struct pa_ap *ap;
	while(!avl_is_empty(&data->aps))
		pa_ap_destroy(data, avl_first_element(&data->aps, ap, avl_node));

	while(!list_empty(&data->cps))
		pa_cp_destroy( list_first_entry(&data->cps, struct pa_cp, le));

	while(!list_empty(&data->dps))
		pa_dp_destroy(list_first_entry(&data->dps, struct pa_dp, le));

	while(!list_empty(&data->eaas))
		pa_aa_destroy(&(list_first_entry(&data->eaas, struct pa_eaa, le))->aa);

	while(!list_empty(&data->sps))
		pa_sp_destroy(data, list_first_entry(&data->sps, struct pa_sp, le));

	while(!list_is_empty(&data->ifs))
		pa_iface_destroy(data, list_first_entry(&data->ifs, struct pa_iface, le));
}

