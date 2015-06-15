/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 * Prefix Assignment Rule Filters.
 *
 * Filters are used by the algorithm in order to allow a single rule to match
 * or not match given different contexts.
 *
 */

#ifndef PA_FILTERS_H_
#define PA_FILTERS_H_

#include "pa_core.h"

struct pa_filter;
typedef int (*pa_filter_f)(struct pa_rule *, struct pa_ldp *,
		struct pa_filter *filter);

/**
 * Filter structure used by all filters defined in this file.
 */
struct pa_filter {
	pa_filter_f accept;
	struct list_head le;
};

/* Configure a rule to use the specified filter. */
#define pa_rule_set_filter(rule, filter) do { \
		(rule)->filter_accept = (int (*)(struct pa_rule *, struct pa_ldp *, void *p)) (filter)->accept; \
		(rule)->filter_private = filter; \
	} while(0)

/* Remove the filter from a given rule. */
#define pa_rule_unset_filter(rule) (rule)->filter_accept = NULL



/*
 * Multiple filters can be combined together in order
 * to form more complex combination.
 * AND, OR, NAND and NOR are supported.
 */
struct pa_filters;
struct pa_filters {
	struct pa_filter filter;
	struct list_head filters;
	uint8_t negate; //When set, the result is inverted
};

int pa_filters_or(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter);
int pa_filters_and(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter);

#define pa_filters_init(fs, accept_f, neg) do{ \
	(fs)->filter.accept = accept_f; \
	(fs)->negate = neg;\
	INIT_LIST_HEAD(&(fs)->filters); \
} while(0)

#define pa_filters_or_init(fs, negate) pa_filters_init(fs, pa_filters_or, negate)
#define pa_filters_and_init(fs, negate) pa_filters_init(fs, pa_filters_and, negate)

#define pa_filters_add(fs, f) list_add(&(f)->le ,&(fs)->filters)
#define pa_filters_del(f) list_del(&(f)->le)


/*
 * Simple filter used to filter for a given link, dp, or both.
 */
struct pa_filter_ldp {
	struct pa_filter filter;
	struct pa_link *link;
	struct pa_dp *dp;
};

int pa_filter_ldp(struct pa_rule *, struct pa_ldp *, struct pa_filter *);

#define pa_filter_ldp_init(fb, l, d) \
	((fb)->filter.accept = pa_filter_ldp, (fb)->link = l, (fb)->dp = d)

/*
 * Filter which only matches for a given dp or link type.
 */
struct pa_filter_type {
	struct pa_filter filter;
	uint8_t type;
};

#ifdef PA_DP_TYPE
int pa_filter_type_dp(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter);
#define pa_filter_type_dp_init(ft, typ) \
	((ft)->filter.accept = pa_filter_type_dp, (ft)->type = typ)

#endif

#ifdef PA_LINK_TYPE
int pa_filter_type_link(struct pa_rule *rule, struct pa_ldp *ldp, struct pa_filter *filter);
#define pa_filter_type_link_init(ft, typ) \
	((ft)->filter.accept = pa_filter_type_link, (ft)->type = typ)
#endif


#endif /* PA_FILTERS_H_ */
