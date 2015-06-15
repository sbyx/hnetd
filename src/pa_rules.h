/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 * Prefix Assignment Rules.
 *
 * This file provides some pre-defined rules to be used with PA core.
 *
 */


#ifndef PA_RULES_H_
#define PA_RULES_H_

#include "pa_core.h"

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

void pa_rule_adopt_init(struct pa_rule_adopt *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority);

struct pa_rule_random;
typedef pa_plen (*pa_rule_desired_plen_cb)(struct pa_rule *, struct pa_ldp *,
			uint16_t prefix_count[PA_RAND_MAX_PLEN + 1]);
typedef int (*pa_rule_subprefix_cb)(struct pa_rule *, struct pa_ldp *, pa_prefix *prefix, pa_plen *plen);
typedef int (*pa_rule_accept_proposed_cb)(struct pa_rule *, struct pa_ldp *,
		pa_prefix *prefix, pa_plen plen);

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

	/* Optional sub-prefix callback.
	 * If set, it is called first in order to override the delegated prefix value.
	 * Should return 0 if the prefix value is set, a different value otherwise.
	 */
	pa_rule_subprefix_cb subprefix_cb;

	/* The desired prefix length callback.
	 * It is called with the available prefix count for each prefix length. */
	pa_rule_desired_plen_cb desired_plen_cb;

	/* When set, pseudo-random or random prefixes which are suitable are
	 * proposed by calling this function. If 0 is returned, another prefix is
	 * tried. The prefix is used otherwise.
	 */
	pa_rule_accept_proposed_cb accept_proposed_cb;

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

void pa_rule_random_init(struct pa_rule_random *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority,
		pa_rule_desired_plen_cb desired_plen_cb,
		uint16_t random_set_size);

void pa_rule_random_prandconf(struct pa_rule_random *r,
		uint16_t pseudo_random_tentatives,
		uint8_t *pseudo_random_seed, uint16_t pseudo_random_seedlen);

/**
 * Pseudo-random prefix selection based on Hamming weights.
 * This approach genuinely sorts all possible prefixes and
 * picks the first available one. That way, preferred prefixes
 * are preferred no matter the current state is.
 *
 * The algorithm is as follows:
 * 1. Computes the amount of available prefixes.
 * 2. Requests a desired prefix length using the callback.
 * 3. Construct a candidate prefix set of given size and desired prefix length.
 * 4. Generates a pseudo-random address.
 * 5. Take the candidate prefix with smallest Hamming distance with the pseudo-random address.
 *    with the pseudo-random prefix.
 */
struct pa_rule_hamming {
	struct pa_rule rule;
	pa_rule_subprefix_cb subprefix_cb;
	pa_rule_desired_plen_cb desired_plen_cb;

	/* Priorities used by this rule */
	pa_rule_priority rule_priority;
	pa_priority priority;

	/* Seed used for pseudo-random address generation */
	uint8_t *pseudo_random_seed;
	size_t pseudo_random_seedlen;

	uint16_t random_set_size;
};

void pa_rule_hamming_init(struct pa_rule_hamming *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority,
		pa_rule_desired_plen_cb desired_plen_cb,
		uint16_t random_set_size,
		uint8_t *seed, size_t seedlen);

/**
 * Prefix static configuration.
 *
 * This rule is used to reflect the desire to assign a given prefix.
 * It may override existing assignment depending on overriding priorities.
 */
struct pa_rule_static;
typedef int (*pa_rule_get_prefix_cb)(struct pa_rule_static *, struct pa_ldp *,
		pa_prefix *prefix, pa_plen *plen);
struct pa_rule_static {
	/* Parent rule. Initialized with pa_rule_static_init. */
	struct pa_rule rule;

	/* Called in order to get the prefix and prefix length values.
	 * Must return 0 in case of success, a non-null value otherwise.
	 * Any prefix may be returned. If it is invalid, it will be ignored. */
	pa_rule_get_prefix_cb get_prefix;

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

void pa_rule_static_init(struct pa_rule_static *r, const char *name,
		pa_rule_get_prefix_cb get_prefix,
		pa_rule_priority rule_priority, pa_priority priority);

#endif
