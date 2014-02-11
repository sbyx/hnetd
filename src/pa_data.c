
#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7

#ifdef L_PREFIX
#undef L_PREFIX
#endif
#define L_PREFIX "pa_data - "

#include "pa_data.h"
#include "pa.h"

#include <stdio.h>

#define PA_P_ALLOC(pa_struct) \
	do { \
		pa_struct = malloc(sizeof(*pa_struct)); \
		if(!pa_struct) { \
			L_ERR("malloc(%lu) failed in %s", (unsigned long)sizeof(*pa_struct), __FUNCTION__);\
			return NULL; \
		} \
	} while(0)

static int pa_data_avl_prefix_cmp (const void *k1, const void *k2,
		__attribute__((unused))void *ptr)
{
	int i = prefix_cmp((struct prefix *)k1, (struct prefix *)k2);
	if(!i)
		return 0;
	return (i>0)?1:-1;
}

void pa_data_init(struct pa_data *data)
{
	L_NOTICE("Initializing data structure.");

	avl_init(&data->aps, pa_data_avl_prefix_cmp, false, NULL);
	INIT_LIST_HEAD(&data->ifs);
	INIT_LIST_HEAD(&data->eaas);
	INIT_LIST_HEAD(&data->dps);
	INIT_LIST_HEAD(&data->cps);
}

void pa_data_term(struct pa_data *data)
{
	L_NOTICE("Terminating database structure.");

	struct pa_ap *ap;
	pa_for_each_ap(ap, data) {
		pa_ap_destroy(data, ap);
	}

	struct pa_cp *cp;
	pa_for_each_cp(cp, data) {
		pa_cp_destroy(cp);
	}

	struct pa_dp *dp;
	pa_for_each_dp(dp, data) {
		if(dp->local)
			pa_ldp_destroy(container_of(dp, struct pa_ldp, dp));
		else
			pa_edp_destroy(container_of(dp, struct pa_edp, dp));
	}

	struct pa_eaa *eaa;
	pa_for_each_eaa(eaa, data) {
		pa_eaa_destroy(eaa);
	}

	struct pa_iface *iface;
	pa_for_each_iface(iface, data) {
		pa_iface_destroy(data, iface);
	}

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

struct pa_iface *pa_iface_get(struct pa_data *data, const char *ifname, bool *created)
{
	struct pa_iface *iface;

	if(created)
		*created = false;

	if(strlen(ifname) >= IFNAMSIZ)
		return NULL;

	if((iface = __pa_iface_get(data, ifname)) || !created)
		return iface;

	PA_P_ALLOC(iface);
	strcpy(iface->ifname, ifname);
	INIT_LIST_HEAD(&iface->aps);
	INIT_LIST_HEAD(&iface->cps);
	iface->designated = false;
	iface->do_dhcp = false;
	iface->internal = false;
	list_add(&iface->le, &data->ifs);
	*created = true;
	L_INFO("Created "PA_IF_L, PA_IF_LA(iface));
	return iface;
}

void pa_iface_destroy(struct pa_data *data, struct pa_iface *iface)
{
	L_INFO("Destroying "PA_IF_L, PA_IF_LA(iface));
	struct pa_ap *ap;
	pa_for_each_ap_in_iface(ap, iface) {
		pa_ap_destroy(data, ap);
	}
	struct pa_cp *cp;
	pa_for_each_cp_in_iface(cp, iface) {
		pa_cp_destroy(cp);
	}
	list_remove(&iface->le);
	free(iface);
}


void pa_dp_init(struct pa_data *data, struct pa_dp *dp, const struct prefix *p)
{
	dp->dhcp_data = NULL;
	dp->dhcp_len = 0;
	dp->preferred_until = 0;
	dp->valid_until = 0;
	prefix_cpy(&dp->prefix, p);
	list_add(&dp->le, &data->dps);
	INIT_LIST_HEAD(&dp->cps);
	L_DEBUG("Initialized "PA_DP_L, PA_DP_LA(dp));
}

int pa_dp_set_dhcp(struct pa_dp *dp, const void *dhcp_data, size_t dhcp_len)
{
	void *new_data;

	if(!dhcp_data)
		dhcp_len = 0;

	if(dhcp_len == dp->dhcp_len && (!dhcp_len || !memcmp(dp->dhcp_data, dhcp_data, dhcp_len)))
		return 0;

	L_DEBUG("Changing "PA_DP_L" dhcp (length %lu)", PA_DP_LA(dp), dhcp_len);

	if(dp->dhcp_data)
		free(dp->dhcp_data);

	if(dhcp_data) {
		new_data = malloc(dhcp_len);
		if(!new_data) {
			L_ERR("malloc(%lu) failed in %s", (unsigned long)dhcp_len, __FUNCTION__);
			dp->dhcp_data = NULL;
			dp->dhcp_len = 0;
			return -1;
		}
		memcpy(new_data, dhcp_data, dhcp_len);
	} else {
		new_data = NULL;
	}

	dp->dhcp_data = new_data;
	dp->dhcp_len = dhcp_len;

	return 1;
}

int pa_dp_set_lifetime(struct pa_dp *dp, hnetd_time_t preferred, hnetd_time_t valid)
{
	if(dp->preferred_until == preferred &&
			dp->valid_until == valid)
		return 0;

	L_DEBUG("Changing "PA_DP_L " lifetimes (%ld, %ld)", PA_DP_LA(dp), preferred, valid);

	dp->preferred_until = preferred;
	dp->valid_until = valid;

	return 1;
}

void pa_dp_term(struct pa_dp *dp)
{
	L_DEBUG("Terminating "PA_DP_L, PA_DP_LA(dp));
	struct pa_cp *cp;
	pa_for_each_cp_in_dp(cp, dp) {
		pa_cp_set_dp(cp, NULL);
	}
	pa_dp_set_dhcp(dp, NULL, 0);
	pa_dp_set_lifetime(dp, 0, 0);
	list_remove(&dp->le);
}

struct pa_ldp *__pa_ldp_get(struct pa_data *data, const struct prefix *p)
{
	struct pa_ldp *ldp;
	pa_for_each_ldp_begin(ldp, data) {
		if(!prefix_cmp(p, &ldp->dp.prefix))
			return ldp;
	} pa_for_each_ldp_end;
	return NULL;
}

struct pa_ldp *pa_ldp_get(struct pa_data *data, const struct prefix *p, bool *created)
{
	struct pa_ldp *ldp;

	if(created)
		*created = false;

	if((ldp = __pa_ldp_get(data, p)) || !created)
		return ldp;

	PA_P_ALLOC(ldp);
	ldp->dp.local = true;
	pa_dp_init(data, &ldp->dp, p);
	ldp->excluded.valid = false;
	ldp->excluded.cp = NULL;
	*created = true;
	return ldp;
}

int pa_ldp_set_excluded(struct pa_ldp *ldp, const struct prefix *excluded)
{
	if((!excluded && !ldp->excluded.valid) || (excluded && !prefix_cmp(excluded, &ldp->excluded.excluded)))
			return 0;

	if(excluded) {
		prefix_cpy(&ldp->excluded.excluded, excluded);
		ldp->excluded.valid = true;
	} else {
		ldp->excluded.valid = false;
	}

	return 1;
}

void pa_ldp_destroy(struct pa_ldp *ldp) {
	pa_dp_term(&ldp->dp);
	free(ldp);
}

struct pa_edp *__pa_edp_get(struct pa_data *data, const struct prefix *p, const struct pa_rid *rid)
{
	struct pa_edp *edp;
	pa_for_each_edp_begin(edp, data) {
		if(!prefix_cmp(p, &edp->dp.prefix) && !PA_RIDCMP(rid, &edp->rid))
					return edp;
	} pa_for_each_edp_end;
	return NULL;
}

struct pa_edp *pa_edp_get(struct pa_data *data, const struct prefix *p,
		const struct pa_rid *rid, bool *created)
{
	struct pa_edp *edp;

	if(created)
		*created = false;

	if((edp = __pa_edp_get(data, p, rid)) || !created)
		return edp;

	PA_P_ALLOC(edp);
	edp->dp.local = false;
	pa_dp_init(data, &edp->dp, p);
	PA_RIDCPY(&edp->rid, rid);
	*created = true;
	return edp;
}

void pa_edp_destroy(struct pa_edp *edp) {
	pa_dp_term(&edp->dp);
	free(edp);
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
		const struct pa_rid *rid, bool *created)
{
	struct pa_ap *ap;

	if(created)
		*created = false;

	if((ap = __pa_ap_get(data, p, rid)) || ! created)
		return ap;

	PA_P_ALLOC(ap);
	ap->authoritative = false;
	ap->priority = PA_PRIORITY_DEFAULT;
	ap->iface = NULL;
	prefix_cpy(&ap->prefix, p);
	PA_RIDCPY(&ap->rid, rid);
	ap->avl_node.key = &ap->prefix;
	if(avl_insert(&data->aps, &ap->avl_node)) {
		L_ERR("Could not insert "PA_AP_L" in avl_tree", PA_AP_LA(ap));
		free(ap);
		return NULL;
	}
	*created = true;
	L_INFO("Created "PA_AP_L, PA_AP_LA(ap));
	return ap;
}

int pa_ap_set_iface(struct pa_ap *ap, struct pa_iface *iface)
{
	if(ap->iface == iface)
		return 0;

	L_DEBUG("Changing "PA_AP_L "iface to "PA_IF_L, PA_AP_LA(ap), PA_IF_LA(iface));

	if(ap->iface)
		list_remove(&ap->if_le);

	if(iface)
		list_add(&ap->if_le, &iface->aps);

	ap->iface = iface;
	return 1;
}

void pa_ap_destroy(struct pa_data *data, struct pa_ap *ap)
{
	L_DEBUG("Destroying "PA_AP_L, PA_AP_LA(ap));
	pa_ap_set_iface(ap, NULL);
	avl_delete(&data->aps, &ap->avl_node);
	free(ap);
}

static void pa_laa_apply_cb(struct uloop_timeout *to)
{
	struct pa_laa *laa = container_of(to, struct pa_laa, apply_to);
	L_DEBUG("Applying "PA_AA_L, PA_AA_LA(&laa->aa));
	pa_laa_apply(laa->cp->pa_data, laa);
}


struct pa_laa *pa_laa_create(struct pa_cp *cp, const struct in6_addr *addr)
{
	struct pa_laa *laa;
	if(cp->laa)
		return NULL;

	PA_P_ALLOC(laa);
	laa->cp = cp;
	cp->laa = laa;
	memcpy(&laa->aa.address, addr, sizeof(struct in6_addr));
	laa->applied = 0;
	laa->apply_to.pending = false;
	laa->apply_to.cb = pa_laa_apply_cb;
	laa->applied = false;
	laa->aa.local = true;
	L_DEBUG("Created "PA_AA_L, PA_AA_LA(&laa->aa));
	return laa;
}

void pa_laa_destroy(struct pa_laa *laa)
{
	L_DEBUG("Destroying "PA_AA_L, PA_AA_LA(&laa->aa));
	pa_laa_set_apply_timeout(laa, 0);
	if(laa->cp)
		laa->cp->laa = NULL;
	free(laa);
}

void pa_laa_set_apply_timeout(struct pa_laa *laa, int msecs)
{
	if(msecs <= 0) {
		if(laa->apply_to.pending)
			L_DEBUG("Canceling "PA_AA_L" apply timeout", PA_AA_LA(&laa->aa));
			uloop_timeout_cancel(&laa->apply_to);
	} else {
		L_DEBUG("Setting "PA_AA_L" apply timeout to %d ms", PA_AA_LA(&laa->aa), msecs);
		uloop_timeout_set(&laa->apply_to, msecs);
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

static void pa_cp_apply_cb(struct uloop_timeout *to)
{
	struct pa_cp *cp = container_of(to, struct pa_cp, apply_to);
	L_DEBUG("Applying "PA_CP_L, PA_CP_LA(cp));
	pa_cp_apply(cp->pa_data, cp);
}

struct pa_cp *pa_cp_get(struct pa_data *data, const struct prefix *prefix, bool *created)
{
	struct pa_cp *cp;

	if(created)
		*created = false;

	if((cp = __pa_cp_get(data, prefix)) || !created)
		return cp;

	PA_P_ALLOC(cp);
	prefix_cpy(&cp->prefix, prefix);
	cp->pa_data = data;

	cp->laa = NULL;
	cp->advertised = false;
	cp->applied = false;
	cp->authoritative = false;
	cp->priority = PA_PRIORITY_DEFAULT;
	cp->iface = NULL;
	cp->invalid = false;
	list_add(&cp->le, &data->cps);
	cp->apply_to.pending = false;
	cp->apply_to.cb = pa_cp_apply_cb;
	cp->dp = NULL;
	*created = true;
	L_DEBUG("Created "PA_CP_L, PA_CP_LA(cp));
	return cp;
}

int pa_cp_set_iface(struct pa_cp *cp, struct pa_iface *iface)
{
	if(cp->iface == iface)
		return 0;

	L_DEBUG("Changing "PA_CP_L" iface to "PA_IF_L, PA_CP_LA(cp), PA_IF_LA(iface));

	if(cp->iface)
		list_remove(&cp->if_le);

	if(iface)
		list_add(&cp->if_le, &iface->cps);

	cp->iface = iface;
	return 1;
}

void pa_cp_set_apply_timeout(struct pa_cp *cp, int msecs)
{
	if(msecs <= 0) {
		if(cp->apply_to.pending)
			L_DEBUG("Canceling "PA_CP_L" apply timeout", PA_CP_LA(cp));
			uloop_timeout_cancel(&cp->apply_to);
	} else {
		L_DEBUG("Setting "PA_CP_L" apply timeout to %d ms", PA_CP_LA(cp), msecs);
		uloop_timeout_set(&cp->apply_to, msecs);
	}
}

int pa_cp_set_address(struct pa_cp *cp, const struct in6_addr *addr)
{
	if((!cp->laa && !addr) ||
			(cp->laa && !memcmp(addr, &cp->laa->aa.address, sizeof(struct in6_addr))))
		return 0;

	if(cp->laa)
		pa_laa_destroy(cp->laa);

	if(addr && !pa_laa_create(cp, addr)) {
		L_ERR("Could not create laa from address %s for "PA_CP_L, ADDR_REPR(addr), PA_CP_LA(cp));
		return -1;
	}

	L_DEBUG("Changing "PA_CP_L" address to "PA_AA_L, PA_CP_LA(cp), PA_AA_LA(&cp->laa->aa));

	return 1;
}

int pa_cp_set_dp(struct pa_cp *cp, struct pa_dp *dp)
{
	if(cp->dp == dp)
		return 0;

	if(cp->dp)
		list_remove(&cp->dp_le);

	if(dp)
		list_add(&cp->dp_le, &dp->cps);

	cp->dp = dp;

	return 1;
}

void pa_cp_destroy(struct pa_cp *cp)
{
	pa_cp_set_dp(cp, NULL);
	pa_cp_set_iface(cp, NULL);
	pa_cp_set_address(cp, NULL);
	list_remove(&cp->le);
	free(cp);
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

struct pa_eaa *pa_eaa_get(struct pa_data *data, const struct in6_addr *addr, const struct pa_rid *rid, bool *created)
{
	struct pa_eaa *eaa;

	if(created)
		*created = false;

	if((eaa = __pa_eaa_get(data, addr, rid)) || !created)
		return eaa;

	PA_P_ALLOC(eaa);
	PA_RIDCPY(&eaa->rid, rid);
	memcpy(&eaa->aa.address, addr, sizeof(struct in6_addr));
	eaa->aa.local = false;
	list_add(&eaa->le, &data->eaas);
	*created = true;
	L_DEBUG("Created "PA_AA_L, PA_AA_LA(&eaa->aa));
	return eaa;
}

void pa_eaa_destroy(struct pa_eaa *eaa)
{
	L_DEBUG("Destroying "PA_AA_L, PA_AA_LA(&eaa->aa));
	list_remove(&eaa->le);
	free(eaa);
}

