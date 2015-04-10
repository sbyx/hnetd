/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 */

#include "pa_filters.h"

int pa_filters_or(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct pa_filters *fs = container_of(filter, struct pa_filters, filter);
	list_for_each_entry(filter, &fs->filters, le) {
		if(filter->accept(rule, ldp, filter))
			return !fs->negate;
	}
	return !!fs->negate;
}

int pa_filters_and(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct pa_filters *fs = container_of(filter, struct pa_filters, filter);
	list_for_each_entry(filter, &fs->filters, le) {
		if(!filter->accept(rule, ldp, filter))
			return !!fs->negate;
	}
	return !fs->negate;
}

int pa_filter_ldp(__unused struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct pa_filter_ldp *fb = container_of(filter, struct pa_filter_ldp, filter);
	if(fb->link && fb->link != ldp->link)
		return 0;
	if(fb->dp && fb->dp != ldp->dp)
		return 0;
	return 1;
}

#ifdef PA_DP_TYPE
int pa_filter_type_dp(__unused struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct pa_filter_type *ft = container_of(filter, struct pa_filter_type, filter);
	return ldp->dp->type == ft->type;
}
#endif

#ifdef PA_LINK_TYPE
int pa_filter_type_link(__unused struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct pa_filter_type *ft = container_of(filter, struct pa_filter_type, filter);
	return ldp->link->type == ft->type;
}
#endif

