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

void pa_rule_prefix_count(struct pa_ldp *ldp, uint16_t *count, pa_plen max_plen) {
	pa_prefix p;
	pa_plen plen;
	struct btrie *n;

	for(plen = 0; plen <= max_plen; plen++)
		count[plen] = 0;

	btrie_for_each_available(&ldp->core->prefixes, n, (btrie_key_t *)&p, (btrie_plen_t *)&plen, (btrie_key_t *)&ldp->dp->prefix, ldp->dp->plen) {
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
		}
	} while(plen--); //plen-- returns plen value before decrement

	return (uint32_t)c;
}

/* Returns the nth (starting from 0) candidate prefix of given length,
 * included in an available prefix of length > min_plen and < max_plen */
int pa_rule_candidate_pick(struct pa_ldp *ldp, uint32_t n, pa_prefix *p, pa_plen plen, pa_plen min_plen, pa_plen max_plen)
{
	struct btrie *node;
	pa_plen i;
	pa_prefix iter;
	int pass = 0;
	do{
		btrie_for_each_available(&ldp->core->prefixes, node, (btrie_key_t *)&iter, (btrie_plen_t *)&i,
				(btrie_key_t *)&ldp->dp->prefix, ldp->dp->plen) {
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


/**** Random rule ****/

pa_rule_priority pa_rule_random_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	struct pa_rule_random *rule_r = container_of(rule, struct pa_rule_random, rule);
	if(ldp->best_assignment || ldp->published) //No override
			return 0;

	return rule_r->rule_priority;
}

enum pa_rule_target pa_rule_random_match(struct pa_rule *rule, struct pa_ldp *ldp,
			__unused pa_rule_priority best_match_priority, struct pa_rule_arg *pa_arg)
{
	struct pa_rule_random *rule_r = container_of(rule, struct pa_rule_random, rule);
	pa_prefix tentative;
	uint16_t i;

	pa_arg->priority = rule_r->priority;
	pa_arg->rule_priority = rule_r->rule_priority;
	//No need to check the best_match_priority because the rule uses a unique rule priority
	if(!ldp->backoff)
		return PA_RULE_BACKOFF; //Start or continue backoff timer.

	uint16_t prefix_count[PA_RAND_MAX_PLEN + 1];
	pa_rule_prefix_count(ldp, prefix_count, PA_RAND_MAX_PLEN);

	pa_plen desired_plen = (rule_r->desired_plen_cb)?
			rule_r->desired_plen_cb(rule_r, ldp, prefix_count):rule_r->desired_plen;

	uint32_t found;
	pa_plen min_plen;
	uint32_t overflow_n;
	found = pa_rule_candidate_subset(prefix_count, desired_plen, rule_r->random_set_size, &min_plen, &overflow_n);


	if(!found) { //No more available prefixes
		PA_INFO("No prefix candidates of length %d could be found in %s", (int)desired_plen, pa_prefix_repr(&ldp->dp->prefix, ldp->dp->plen));
		return PA_RULE_NO_MATCH;
	}

	PA_DEBUG("Found %"PRIu32" prefix candidates of length %d in %s", found, (int)desired_plen, pa_prefix_repr(&ldp->dp->prefix, ldp->dp->plen));
	PA_DEBUG("Minimum available prefix length is %d", min_plen);

	if(rule_r->pseudo_random_tentatives) {
		pa_prefix overflow_prefix;
		if(overflow_n) {
			pa_rule_candidate_pick(ldp, overflow_n, &overflow_prefix, desired_plen, min_plen, min_plen);
			PA_DEBUG("Last (#%"PRIu32") candidate in available prefix of length %d is %s", overflow_n, min_plen, pa_prefix_repr(&overflow_prefix, desired_plen));
		}

		/* Make pseudo-random tentatives. */
		struct btrie *n0, *n;
		btrie_plen_t l0;
		pa_prefix iter_p;
		pa_plen iter_plen;
		for(i=0; i<rule_r->pseudo_random_tentatives; i++) {
			pa_rule_prefix_prandom(rule_r->pseudo_random_seed, rule_r->pseudo_random_seedlen, i, &ldp->dp->prefix, ldp->dp->plen, &tentative, desired_plen);
			PA_DEBUG("Trying pseudo-random %s", pa_prefix_repr(&tentative, desired_plen));
			btrie_for_each_available_loop_stop(&ldp->core->prefixes, n, n0, l0, (btrie_key_t *)&iter_p, &iter_plen, \
					(btrie_key_t *)&tentative, ldp->dp->plen, desired_plen)
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
						rule_r->accept_proposed_cb(rule_r, ldp, &tentative, desired_plen)) {
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
		pa_rule_candidate_pick(ldp, id, &tentative, desired_plen, min_plen, desired_plen);
		if(!rule_r->accept_proposed_cb || rule_r->accept_proposed_cb(rule_r, ldp, &tentative, desired_plen)) {
			goto choose;
		} else {
			PA_DEBUG("Random prefix %s was rejected by user", pa_prefix_repr(&tentative, desired_plen));
		}
	}

choose:
	pa_prefix_cpy(&tentative, desired_plen, &pa_arg->prefix, pa_arg->plen);
	return PA_RULE_PUBLISH;
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
