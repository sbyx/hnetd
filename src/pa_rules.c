/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 */

#include "pa_rules.h"

#include <libubox/md5.h>
#include <string.h>

#include "bitops.h"

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#define pa_rule_init(rule, get_prio, max_prio, match_f, name) do{ \
	(rule)->get_max_priority = get_prio; \
	(rule)->max_priority = max_prio; \
	(rule)->match = match_f; \
	(rule)->filter_accept = NULL; \
	(rule)->filter_private = NULL; \
	(rule)->name = name; } while(0)

void pa_rule_prefix_nth(pa_prefix *dst, pa_prefix *container, pa_plen container_len, uint32_t n, pa_plen plen)
{
	uint32_t i = htonl(n);
	__unused pa_plen pp;
	memset(dst, 0, sizeof(*dst));
	pa_prefix_cpy(container, container_len, dst, pp);
	if((plen - container_len) > 32)
		container_len = plen - 32;

	bmemcpy_shift(dst, container_len, &i, 32 - (plen - container_len), plen - container_len);
}

void pa_rule_prefix_count(struct pa_core *core,
		pa_prefix *subprefix, pa_plen subplen,
		uint16_t *count, pa_plen max_plen) {
	pa_prefix p;
	pa_plen plen;
	struct btrie *n;

	for(plen = 0; plen <= max_plen; plen++)
		count[plen] = 0;

	btrie_for_each_available(&core->prefixes, n, (btrie_key_t *)&p, (btrie_plen_t *)&plen, (btrie_key_t *)subprefix, subplen) {
		if(count[plen] != UINT16_MAX)
			count[plen]++;
	}
}

/* Computes the candidate subset. */
uint32_t pa_rule_candidate_subset( //Returns the number of found prefixes
		const uint16_t *count,    //The prefix count returned by pa_rule_prefix_count
		pa_plen desired_plen,     //The desired prefix length
		uint32_t desired_set_size,//Number of desired prefixes in the set
		pa_plen *min_plen,        //The minimal prefix length of containing available prefixes
		uint32_t *overflow_n      //Number of prefixes in set and included in an available prefix of length overflow_plen
		                          //When overflow_n == 0, all prefixes of length desired_plen
								  //included in available prefixes of length >= min_plen are candidate prefixes.
		)
{
	pa_plen plen = desired_plen;
	uint64_t c = 0;
	*overflow_n = 0;
	do {
		if(count[plen]) {
			*min_plen = plen;
			if(desired_plen - plen >= 32 || ((c + count[plen] * ((uint64_t)(1 << (desired_plen - plen)))) > desired_set_size)) {
				*overflow_n = desired_set_size - c; //Number of prefixes contained in this prefix length to reach the desired size
				return desired_set_size;
			}
			c += count[plen] * ((uint64_t)(1 << (desired_plen - plen)));
			if(c == desired_set_size)
				break;
		}
	} while(plen--); //plen-- returns plen value before decrement
	return (uint32_t)c;
}

/* Returns the nth (starting from 0) candidate prefix of given length,
 * included in an available prefix of length > min_plen and < max_plen */
int pa_rule_candidate_pick(struct pa_core *core, pa_prefix *subprefix, pa_plen subplen,
		uint32_t n, pa_prefix *p, pa_plen plen, pa_plen min_plen, pa_plen max_plen)
{
	struct btrie *node;
	pa_plen i;
	pa_prefix iter;
	int pass = 0;
	do{
		btrie_for_each_available(&core->prefixes, node, (btrie_key_t *)&iter, (btrie_plen_t *)&i,
				(btrie_key_t *)subprefix, subplen) {
			if((pass && i == min_plen) || (!pass && i > min_plen && i <= max_plen)) {
				if((plen - i >= 32) || (n < (((uint32_t)1) << (plen - i)))) {
					//The nth prefix is in this available prefix
					pa_rule_prefix_nth(p, &iter, i, n, plen);
					return 0;
				}
				n -= 1 << (plen - i);
			}
		}
	} while(!(pass++));
	return -1;
}

void pa_rule_prefix_prandom(const uint8_t *seed, size_t seedlen, uint32_t ctr,
		const pa_prefix *container_prefix, pa_plen container_len,
		pa_prefix *dst, pa_plen plen)
{
	uint32_t hash[4];
	md5_ctx_t ctx;

	uint32_t ctr2 = 0;
	uint8_t *buff = (uint8_t *)dst;
	uint32_t bytelen = (((uint32_t)plen) + 7)/8;
	while(bytelen) {
		uint8_t write = bytelen>16?16:bytelen;
		md5_begin(&ctx);
		md5_hash(seed, seedlen, &ctx);
		md5_hash(&ctr,  sizeof(ctr), &ctx);
		md5_hash(&ctr2, sizeof(ctr), &ctx);
		md5_end(hash, &ctx);
		memcpy(buff, hash, write);
		buff += 16;
		bytelen -= write;
		ctr2++;
	}

	bmemcpy(dst, container_prefix, 0, container_len);
}

/***** Adopt rule ****/

pa_rule_priority pa_rule_adopt_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	if(!ldp->assigned || ldp->best_assignment || ldp->published) //No override
		return 0;
	return container_of(rule, struct pa_rule_adopt, rule)->rule_priority;
}

enum pa_rule_target pa_rule_adopt_match(struct pa_rule *rule, __unused struct pa_ldp *ldp,
			__unused pa_rule_priority best_match_priority,
			struct pa_rule_arg *pa_arg)
{
	struct pa_rule_adopt *rule_a = container_of(rule, struct pa_rule_adopt, rule);
	//No need to check the best_match_priority because the rule uses a unique rule priority
	pa_arg->rule_priority = rule_a->rule_priority;
	pa_arg->priority = rule_a->priority;
	return PA_RULE_ADOPT;
}

void pa_rule_adopt_init(struct pa_rule_adopt *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority)
{
	pa_rule_init(&(r)->rule, pa_rule_adopt_get_max_priority,
			0, pa_rule_adopt_match, name);
	r->rule_priority = rule_priority;
	r->priority = priority;
}


/**** Random rule ****/

pa_rule_priority pa_rule_random_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	struct pa_rule_random *rule_r = container_of(rule, struct pa_rule_random, rule);
	if(ldp->best_assignment || ldp->published) //No override
			return 0;

	return rule_r->rule_priority;
}

enum pa_rule_target pa_rule_random_override_match(struct pa_rule *rule,
			struct pa_ldp *ldp, pa_prefix *subprefix, pa_plen subplen,
			__unused pa_rule_priority best_match_priority, struct pa_rule_arg *pa_arg,
			pa_plen desired_plen)
{
	struct pa_rule_random *rule_r = container_of(rule, struct pa_rule_random, rule);

	if(!rule_r->override_priority && !rule_r->override_rule_priority)
		return PA_RULE_NO_MATCH;

	//Let's try to find a prefix we could override.
	pa_prefix *best_p = NULL;
	pa_plen best_plen;
	uint8_t best_type;
	struct pa_pentry *pe;
	btrie_for_each_down_entry(pe, &ldp->core->prefixes,
			(btrie_key_t *)subprefix, subplen, be) {
		pa_prefix *p;
		pa_plen plen;
		if(pe->type == PAT_ASSIGNED) {
			struct pa_ldp *ldp2 = container_of(pe, struct pa_ldp, in_core);
			p = &ldp2->prefix;
			plen = ldp2->plen;
		} else {
			struct pa_advp *advp = container_of(pe, struct pa_advp, in_core);
			p = &advp->prefix;
			plen = advp->plen;
		}

		if((plen > desired_plen) || !pa_rule_valid_assignment(ldp, p, plen,
				rule_r->override_rule_priority, rule_r->override_priority,
				rule_r->safety))
			continue;

		if(!best_p || best_plen > plen || (best_plen == plen &&
				best_type == PAT_ADVERTISED && pe->type == PAT_ASSIGNED)) {
			best_p = p;
			best_plen = plen;
			best_type = pe->type;
		}
	}

	if(!best_p) {
		PA_INFO("No existing prefix can be overridden");
		return PA_RULE_NO_MATCH;
	}

	PA_INFO("Overriding %s prefix %s",
			(best_type==PAT_ADVERTISED)?"distant":"local",
					pa_prefix_repr(best_p, best_plen));

	uint32_t set_size = ((desired_plen - best_plen) >= 32)?
			(1<<31):(1<<(desired_plen - best_plen));
	if(set_size > rule_r->random_set_size)
		set_size = rule_r->random_set_size;

	/* Select a random prefix */
	int i;
	pa_prefix tentative;
	for(i=0; i<100; i++) { //No more than 100 tentatives if they are all rejected
		uint32_t id = htonl(pa_rand() % set_size);
		memset(&tentative, 0, sizeof(tentative));
		pa_prefix_cpy(best_p, desired_plen, &tentative, desired_plen);
		bmemcpy_shift(&tentative, best_plen, &id, 32 - (desired_plen - best_plen),
				desired_plen - best_plen);

		if(!rule_r->accept_proposed_cb || rule_r->accept_proposed_cb(&rule_r->rule, ldp, &tentative, desired_plen)) {
			goto choose;
		} else {
			PA_DEBUG("Random prefix %s was rejected by user", pa_prefix_repr(&tentative, desired_plen));
		}
	}
	PA_DEBUG("All random prefixes were rejected by user");
	return PA_RULE_NO_MATCH;

choose:
	pa_prefix_cpy(&tentative, desired_plen, &pa_arg->prefix, pa_arg->plen);
	return PA_RULE_PUBLISH;
}

enum pa_rule_target pa_rule_random_match(struct pa_rule *rule, struct pa_ldp *ldp,
			__unused pa_rule_priority best_match_priority, struct pa_rule_arg *pa_arg)
{
	struct pa_rule_random *rule_r = container_of(rule, struct pa_rule_random, rule);
	pa_prefix sp, *subprefix;
	pa_plen subplen;
	pa_prefix tentative;
	uint16_t i;

	pa_arg->priority = rule_r->priority;
	pa_arg->rule_priority = rule_r->rule_priority;
	//No need to check the best_match_priority because the rule uses a unique rule priority
	if(!ldp->backoff)
		return PA_RULE_BACKOFF; //Start or continue backoff timer.

	//Look at the subprefix if any
	if(!rule_r->subprefix_cb) { //Use the dp by default
		subprefix = &ldp->dp->prefix;
		subplen = ldp->dp->plen;
	} else if (rule_r->subprefix_cb(&rule_r->rule, ldp, &sp, &subplen)) {
		//cb returned error
		return PA_RULE_NO_MATCH;
	} else {
		//Use the returned subprefix
		subprefix = &sp;
		PA_DEBUG("Non-default assignment prefix pool will be used: %s", pa_prefix_repr(subprefix, subplen));
	}

	uint16_t prefix_count[PA_RAND_MAX_PLEN + 1];
	pa_rule_prefix_count(ldp->core, subprefix, subplen, prefix_count, PA_RAND_MAX_PLEN);

	pa_plen desired_plen = rule_r->desired_plen_cb(&rule_r->rule, ldp, prefix_count);
	uint32_t found;
	pa_plen min_plen;
	uint32_t overflow_n;
	found = pa_rule_candidate_subset(prefix_count, desired_plen, rule_r->random_set_size, &min_plen, &overflow_n);

	if(!found) { //No more available prefixes
		PA_INFO("No prefix candidates of length %d could be found in %s",
				(int)desired_plen, pa_prefix_repr(subprefix, subplen));
		return pa_rule_random_override_match(rule, ldp, subprefix, subplen, best_match_priority,
				pa_arg, desired_plen);
	}

	PA_DEBUG("Found %"PRIu32" prefix candidates of length %d in %s", found, (int)desired_plen, pa_prefix_repr(subprefix, subplen));
	PA_DEBUG("Minimum available prefix length is %d", min_plen);

	if(rule_r->pseudo_random_tentatives) {
		pa_prefix overflow_prefix;
		if(overflow_n) {
			pa_rule_candidate_pick(ldp->core, subprefix, subplen,
					overflow_n, &overflow_prefix, desired_plen, min_plen, min_plen);
			PA_DEBUG("Last (#%"PRIu32") candidate in available prefix of length %d is %s", overflow_n, min_plen, pa_prefix_repr(&overflow_prefix, desired_plen));
		}

		/* Make pseudo-random tentatives. */
		struct btrie *n0, *n;
		btrie_plen_t l0;
		pa_prefix iter_p;
		pa_plen iter_plen;
		for(i=0; i<rule_r->pseudo_random_tentatives; i++) {
			pa_rule_prefix_prandom(rule_r->pseudo_random_seed, rule_r->pseudo_random_seedlen, i, subprefix, subplen, &tentative, desired_plen);
			PA_DEBUG("Trying pseudo-random %s", pa_prefix_repr(&tentative, desired_plen));
			btrie_for_each_available_loop_stop(&ldp->core->prefixes, n, n0, l0, (btrie_key_t *)&iter_p, &iter_plen, \
					(btrie_key_t *)&tentative, subplen, desired_plen)
			{
				if(iter_plen > desired_plen || //First available prefix is too small
						!pa_prefix_contains(&iter_p, iter_plen, &tentative) || //First available prefix does not contain the tentative prefix
						iter_plen < min_plen || //Not in the candidate prefix set
						(overflow_n && iter_plen == min_plen && //Minimal length and greater than the overflow prefix
								(bmemcmp(&tentative, &overflow_prefix, desired_plen) >= 0))) {
					//Prefix is not in the candidate prefix set
					PA_DEBUG("Prefix is not in the candidate prefixes set");
					break;
				}
				if(!rule_r->accept_proposed_cb ||
						rule_r->accept_proposed_cb(&rule_r->rule, ldp, &tentative, desired_plen)) {
					goto choose;
				} else {
					PA_DEBUG("Prefix got rejected by user");
					break;
				}
			}
		}
	}

	/* Select a random prefix */
	for(i=0; i<100; i++) { //No more than 100 tentatives if they are all rejected
		uint32_t id = pa_rand() % found;
		pa_rule_candidate_pick(ldp->core, subprefix, subplen, id,
				&tentative, desired_plen, min_plen, desired_plen);
		if(!rule_r->accept_proposed_cb || rule_r->accept_proposed_cb(&rule_r->rule, ldp, &tentative, desired_plen)) {
			goto choose;
		} else {
			PA_DEBUG("Random prefix %s was rejected by user", pa_prefix_repr(&tentative, desired_plen));
		}
	}
	PA_DEBUG("All random prefixes were rejected by user");
	return PA_RULE_NO_MATCH;

choose:
	pa_prefix_cpy(&tentative, desired_plen, &pa_arg->prefix, pa_arg->plen);
	return PA_RULE_PUBLISH;
}

void pa_rule_random_init(struct pa_rule_random *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority,
		pa_rule_desired_plen_cb desired_plen_cb,
		uint16_t random_set_size)
{
	pa_rule_init(&r->rule, pa_rule_random_get_max_priority,
			0, pa_rule_random_match, name);
	r->rule_priority = rule_priority;
	r->priority = priority;
	r->subprefix_cb = NULL;
	r->desired_plen_cb = desired_plen_cb;
	r->random_set_size = random_set_size;
	r->override_priority = 0;
	r->override_rule_priority = 0;
	r->safety = 0;
	r->pseudo_random_seed = NULL;
	r->pseudo_random_seedlen = 0;
	r->accept_proposed_cb = NULL;
}

void pa_rule_random_prandconf(struct pa_rule_random *r,
		uint16_t tentatives,
		uint8_t *seed, uint16_t seedlen)
{
	r->pseudo_random_seed = seed;
	r->pseudo_random_seedlen = seedlen;
	r->pseudo_random_tentatives = tentatives;
}

enum pa_rule_target pa_rule_hamming_match(struct pa_rule *rule, struct pa_ldp *ldp,
			__unused pa_rule_priority best_match_priority, struct pa_rule_arg *pa_arg)
{
	struct pa_rule_hamming *rule_r = container_of(rule, struct pa_rule_hamming, rule);
	pa_prefix sp, *subprefix;
	pa_plen subplen;

	pa_arg->rule_priority = rule_r->rule_priority;
	if(!ldp->backoff)
		return PA_RULE_BACKOFF; //Start or continue backoff timer.

	//Look at the subprefix if any
	if(!rule_r->subprefix_cb) { //Use the dp by default
		PA_DEBUG("Default subprefix");
		subprefix = &ldp->dp->prefix;
		subplen = ldp->dp->plen;
	} else if (rule_r->subprefix_cb(&rule_r->rule, ldp, &sp, &subplen)) {
		return PA_RULE_NO_MATCH; //cb returned error
	} else {
		//Use the returned subprefix
		subprefix = &sp;
		PA_DEBUG("Non-default assignment prefix pool will be used: %s", pa_prefix_repr(subprefix, subplen));
	}

	uint16_t prefix_count[PA_RAND_MAX_PLEN + 1];
	pa_rule_prefix_count(ldp->core, subprefix, subplen, prefix_count, PA_RAND_MAX_PLEN);

	pa_plen desired_plen = rule_r->desired_plen_cb(&rule_r->rule, ldp, prefix_count);
	uint32_t found, overflow_n;
	pa_plen min_plen;
	found = pa_rule_candidate_subset(prefix_count, desired_plen, rule_r->random_set_size, &min_plen, &overflow_n);
	PA_DEBUG("Candidate subset is: min_plen=%d overflow_n=%d", min_plen, overflow_n);
	if(!found) { //No more available prefixes
		PA_INFO("No prefix candidates of length %d could be found in %s",
				(int)desired_plen, pa_prefix_repr(subprefix, subplen));
		return pa_rule_random_override_match(rule, ldp, subprefix, subplen, best_match_priority,
				pa_arg, desired_plen);
	}

	PA_DEBUG("Found %"PRIu32" prefix candidates of length %d in %s", found, (int)desired_plen, pa_prefix_repr(subprefix, subplen));
	PA_DEBUG("Minimum available prefix length is %d", min_plen);

	//Get a pseudo random prefix used for hamming distances
	pa_prefix hammer;
	pa_rule_prefix_prandom(rule_r->pseudo_random_seed, rule_r->pseudo_random_seedlen, 0, subprefix, subplen, &hammer, desired_plen);
	PA_DEBUG("Pseudo Random Prefix is %s", pa_prefix_repr(&hammer, desired_plen));

	struct btrie *n;
	size_t best_distance = 200;
	pa_prefix best_prefix, iter_prefix, overflow_prefix;
	pa_plen iter_plen;
	btrie_for_each_available(&ldp->core->prefixes, n, (btrie_key_t *)&iter_prefix, &iter_plen, (btrie_key_t *)subprefix, subplen) {
		if(iter_plen > desired_plen || iter_plen < min_plen)
			continue;

		size_t hd;
		if(overflow_n && iter_plen == min_plen) {
			uint32_t count;
			if(desired_plen - iter_plen >= 32) {
				count = 1 << 31;
			} else {
				count = 1 << (desired_plen - iter_plen);
			}

			if(count >= overflow_n) {
				//Have to use the complex min finder
				pa_rule_prefix_nth(&overflow_prefix, &iter_prefix, iter_plen, overflow_n - 1, desired_plen);
				hd = hamming_distance_64((uint64_t *)&iter_prefix, (uint64_t *)&hammer, iter_plen);
				hd += hamming_minimize((uint8_t *)&overflow_prefix, (uint8_t *)&hammer, (uint8_t *)&iter_prefix, iter_plen, desired_plen - iter_plen);
				PA_DEBUG("Distance of %d with %s (Up to %s only)",
						(int)hd, pa_prefix_repr(&iter_prefix, iter_plen), pa_prefix_repr(&overflow_prefix, desired_plen));
				if(hd < best_distance) {
					best_distance = hd;
					bmemcpy(&best_prefix, &iter_prefix, 0, desired_plen);
				}
				overflow_n = 0;
				continue;
			} else {
				overflow_n -= count;
			}
		}
		hd = hamming_distance_64((uint64_t *)&iter_prefix, (uint64_t *)&hammer, iter_plen);
		PA_DEBUG("Distance of %d with %s", (int)hd, pa_prefix_repr(&iter_prefix, iter_plen));
		if(hd < best_distance) {
			best_distance = hd;
			bmemcpy(&best_prefix, &iter_prefix, 0, iter_plen);
			bmemcpy(&best_prefix, &hammer, iter_plen, desired_plen - iter_plen);
		}
		//todo: Deal with ties (Keep smaller is the easy but imperfect solution, better would be a secondary hammer).
	}
	PA_DEBUG("Best found with distance %d is %s", (int)best_distance, pa_prefix_repr(&best_prefix, desired_plen));
	pa_prefix_cpy(&best_prefix, desired_plen, &pa_arg->prefix, pa_arg->plen);
	pa_arg->priority = rule_r->priority;
	return PA_RULE_PUBLISH;
}

pa_rule_priority pa_rule_hamming_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	struct pa_rule_hamming *rule_h = container_of(rule, struct pa_rule_hamming, rule);
	if(ldp->best_assignment || ldp->published) //No override
			return 0;

	return rule_h->rule_priority;
}

void pa_rule_hamming_init(struct pa_rule_hamming *r, const char *name,
		pa_rule_priority rule_priority, pa_priority priority,
		pa_rule_desired_plen_cb desired_plen_cb,
		uint16_t random_set_size,
		uint8_t *seed, size_t seedlen)
{
	pa_rule_init(&r->rule, pa_rule_hamming_get_max_priority,
				0, pa_rule_hamming_match, name);
		r->rule_priority = rule_priority;
		r->priority = priority;
		r->subprefix_cb = NULL;
		r->desired_plen_cb = desired_plen_cb;
		r->pseudo_random_seed = seed;
		r->pseudo_random_seedlen = seedlen;
		r->random_set_size = random_set_size;
}

/**** Static rule ****/

pa_rule_priority pa_rule_static_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	struct pa_rule_static *srule = container_of(rule, struct pa_rule_static, rule);
	if(!srule->get_prefix || srule->get_prefix(srule, ldp, &srule->_prefix, &srule->_plen) ||
			(ldp->dp->plen > srule->_plen) ||
			!pa_prefix_contains(&ldp->dp->prefix, ldp->dp->plen, &srule->_prefix) ||
			!pa_rule_valid_assignment(ldp, &srule->_prefix, srule->_plen,
					srule->override_rule_priority, srule->override_priority, srule->safety))
		return 0;

	return srule->rule_priority;
}

enum pa_rule_target pa_rule_static_match(struct pa_rule *rule, struct pa_ldp *ldp,
			__unused pa_rule_priority best_match_priority, struct pa_rule_arg *pa_arg)
{
	struct pa_rule_static *srule = container_of(rule, struct pa_rule_static, rule);
	if(!ldp->backoff && !ldp->best_assignment) //Do not return backoff when there is a best_assignment
		return PA_RULE_BACKOFF;

	pa_arg->rule_priority = srule->rule_priority;
	pa_arg->priority = srule->priority;
	pa_prefix_cpy(&srule->_prefix, srule->_plen, &pa_arg->prefix, pa_arg->plen);
	return PA_RULE_PUBLISH;
}

void pa_rule_static_init(struct pa_rule_static *r, const char *name,
		pa_rule_get_prefix_cb get_prefix,
		pa_rule_priority rule_priority, pa_priority priority)
{
	pa_rule_init(&(r)->rule, pa_rule_static_get_max_priority,
			0, pa_rule_static_match, name);
	r->get_prefix = get_prefix;
	r->rule_priority = rule_priority;
	r->priority = priority;
}
