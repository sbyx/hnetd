/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Prefix Assignment Rules.
 *
 * This file provides some pre-defined rules to be used with PA core.
 *
 */


#ifndef PA_RULES_H_
#define PA_RULES_H_

#include "pa_core.h"

#define pa_rule_init(rule, get_prio, max_prio, match_f) do{ \
	(rule)->get_max_priority = get_prio; \
	(rule)->max_priority = max_prio; \
	(rule)->match = match_f; \
	(rule)->filter_accept = NULL; \
	(rule)->filter_private = NULL;} while(0)

/**
 * Simple adoption rule.
 *
 * When a prefix is assigned and valid, but advertised by no-one, it may be
 * adopted after some random delay.
 * The adopt rule will always adopt a prefix when possible, using the specified
 * rule_priority and advertising the adopted prefix with the specified
 * priority.
 */
struct pa_rule_adopt {
	/* Parent rule. Set by pa_rule_adopt_init. */
	struct pa_rule rule;

	/* The internal rule priority used by this rule when matching.  */
	pa_rule_priority rule_priority;

	/* The Advertised Prefix Priority used when publishing the adopted prefix. */
	pa_priority priority;
};

pa_rule_priority pa_rule_adopt_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp);
enum pa_rule_target pa_rule_adopt_match(struct pa_rule *rule, struct pa_ldp *ldp,
			pa_rule_priority, struct pa_rule_arg *);

#define pa_rule_adopt_init(rule_adopt) pa_rule_init(&(rule_adopt)->rule, \
						pa_rule_adopt_get_max_priority, 0, pa_rule_adopt_match)

/**
 * Randomized prefix selection.
 *
 * When no prefix is assigned on a given Link, a new prefix may be picked.
 * This rule implements the prefix selection algorithm detailed in the prefix
 * assignment specifications.
 */
struct pa_rule_random {
	/* Parent rule. Initialized with pa_rule_random_init. */
	struct pa_rule rule;

	/* The internal rule priority */
	pa_rule_priority rule_priority;

	/* The Advertised Prefix Priority used when publishing the new prefix. */
	pa_priority priority;

	/* The desired prefix length. When desired_plen_cb is not NULL, it is
	 * called with the available prefix count for each prefix length.
	 * desired_plen is used otherwise. */
	pa_plen (*desired_plen_cb)(struct pa_rule_random *, struct pa_ldp *,
			uint16_t prefix_count[PA_RAND_MAX_PLEN + 1]);
	pa_plen desired_plen;

	/* When set, pseudo-random or random prefixes which are suitable are
	 * proposed by calling this function. If 0 is returned, another prefix is
	 * tried. The prefix is used otherwise.
	 */
	int (*accept_proposed_cb)(struct pa_rule_random *, struct pa_ldp *,
			pa_prefix *prefix, pa_plen plen);

	/* Pseudo-random and random prefixes are picked in a given set of
	 * candidates.
	 * The larger the set, the lower the collision probability.
	 * The smaller the set, the more space efficient the algorithm is. */
	uint16_t random_set_size;

	/* The algorithm first makes pseudo_random_tentatives pseudo-random
	 * tentatives. */
	uint16_t pseudo_random_tentatives;

	/* Seed and seed length used for the pseudo-random tentatives. */
	uint8_t *pseudo_random_seed;
	uint16_t pseudo_random_seedlen;

	/* If an available prefix cannot be found, another assigned prefix might
	 * be overridden. Prefix of smaller length is preferred.
	 */
	pa_rule_priority override_rule_priority;
	pa_priority override_priority;
	uint8_t safety;
};

pa_rule_priority pa_rule_random_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp);
enum pa_rule_target pa_rule_random_match(struct pa_rule *rule, struct pa_ldp *ldp,
			pa_rule_priority, struct pa_rule_arg *);

#define pa_rule_random_init(rule_random) pa_rule_init(&(rule_random)->rule,  \
			pa_rule_random_get_max_priority, 0, pa_rule_random_match)


/**
 * Prefix static configuration.
 *
 * This rule is used to reflect the desire to assign a given prefix.
 * It may override existing assignment depending on overriding priorities.
 */
struct pa_rule_static {
	/* Parent rule. Initialized with pa_rule_static_init. */
	struct pa_rule rule;

	/* Called in order to get the prefix and prefix length values.
	 * Must return 0 in case of success, a non-null value otherwise.
	 * Any prefix may be returned. If it is invalid, it will be ignored. */
	int (*get_prefix)(struct pa_rule_static *, struct pa_ldp *,
			pa_prefix *prefix, pa_plen *plen);

	/* The internal rule priority */
	pa_rule_priority rule_priority;

	/* The Advertised Prefix Priority used when publishing the new prefix. */
	pa_priority priority;

	/* The prefix may override any Advertised Prefix
	 * advertised by another node with an Advertised
	 * Prefix Priority strictly lower than the
	 * override_priority.
	 * And any Assigned Prefix which is Published
	 * by the local node with a rule_priority
	 * strictly lower than the override_rule_priority. */

	/* This rule may override prefixes advertised with a priority
	 * strictly lower than this priority. */
	pa_priority override_priority;

	/* This rule may override prefixes locally published with a rule priority
	 * strictly lower than this rule priority. */
	pa_rule_priority override_rule_priority;

	/* When set, published prefixes are not override unless the Advertised
	 * Prefix Priority is lower or equal to override_priority.
	 * When disabled, assignment loop may happen with other nodes. */
	uint8_t safety;

	/* Private */
	pa_prefix _prefix;
	pa_plen _plen;
};

pa_rule_priority pa_rule_static_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp);
enum pa_rule_target pa_rule_static_match(struct pa_rule *rule, struct pa_ldp *ldp,
			pa_rule_priority, struct pa_rule_arg *);

#define pa_rule_static_init(rule_static) pa_rule_init(&(rule_static)->rule,  \
		pa_rule_static_get_max_priority, 0, pa_rule_static_match)

#endif
