/*
 * Author: Pierre Pfister
 *
 */

#include "pa_data.h"

#define PA_P_ALLOC(pa_struct) \
	do { \
		pa_struct = malloc(sizeof(*pa_struct)); \
		if(!pa_struct) \
			return NULL; \
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
	avl_init(&data->aps, pa_data_avl_prefix_cmp, false, NULL);
	INIT_LIST_HEAD(&data->ifs);
	INIT_LIST_HEAD(&data->aas);
	INIT_LIST_HEAD(&data->cps);
	INIT_LIST_HEAD(&data->dps);
}

void pa_dp_init(struct pa_data *data, struct pa_dp *dp, const struct prefix *p)
{
	INIT_LIST_HEAD(&dp->cps);
	dp->dhcp_data = NULL;
	dp->dhcp_len = 0;
	dp->preferred_until = 0;
	dp->valid_until = 0;
	prefix_cpy(&dp->prefix, p);
	list_add(&dp->le, &data->dps);
}

int pa_dp_set_dhcp(struct pa_dp *dp, const void *dhcp_data, size_t dhcp_len)
{
	void *new_data;

	if(!dhcp_data)
		dhcp_len = 0;

	if(dhcp_len == dp->dhcp_len && !memcmp(dp->dhcp_data, dhcp_data, dhcp_len))
		return 0;

	if(dp->dhcp_data)
		free(dp->dhcp_data);

	if(dhcp_data) {
		new_data = malloc(dhcp_len);
		if(!new_data) {
			dp->dhcp_data = NULL;
			dp->dhcp_len = 0;
			return -1;
		}
	} else {
		new_data = NULL;
	}

	dp->dhcp_data = new_data;

	return 1;
}

struct pa_ldp *pa_ldp_get(struct pa_data *data, const struct prefix *p)
{
	struct pa_dp *dp;
	pa_for_each_dp(data, dp) {
		if(!dp->local)
			continue;
		if(!prefix_cmp(p, &dp->prefix))
			return (struct pa_ldp *)dp;
	}
	return NULL;
}

struct pa_ldp *pa_ldp_goc(struct pa_data *data, const struct prefix *p) {

	struct pa_ldp *ldp;

	ldp = pa_ldp_get(data, p);

	if(ldp)
		return ldp;

	PA_P_ALLOC(ldp);
	pa_dp_init(&ldp->dp);
	ldp->iface = NULL;
	ldp->cp = NULL;
	ldp->dp.local = true;
	return ldp;
}

int pa_ldp_set_iface( struct pa_ldp *ldp, struct pa_iface *iface)
{
	if(ldp->iface == iface)
		return 0;

	if(ldp->iface)
		list_remove(&ldp->if_le);

	if(iface)
		list_add(&ldp->if_le, &iface->ldps);

	ldp->iface = iface;
	return 1;
}

void pa_ldp_destroy(struct pa_data *data, struct pa_ldp *ldp) {
	pa_ldp_set_iface(NULL);
	free(ldp);
}
