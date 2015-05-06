/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Distributed Prefix Assignment Algorithm configuration header.
 *
 * The Prefix Assignment Algorithm is generic. It can run on different flooding
 * mechanisms, using different Node IDs, prefix space, and configuration
 * variables.
 *
 * This file lists all parameters, mandatory or optional, specifying the
 * behavior of the algorithm. You can modify it, or use a different one.
 *
 */

#ifndef PA_CONF_H_
#define PA_CONF_H_

/**********************************
 *    Node ID Space Definition    *
 **********************************/

/**
 * The Node ID array type.
 *   (Mandatory)
 */
#include <stdint.h>
#define PA_NODE_ID_TYPE uint32_t

/**
 * The Node ID array length. Set it to 1 in order to use a single structure
 * instead of an array.
 *   (Mandatory) */
#define PA_NODE_ID_LEN  1

/**
 * Node ID comparison function.
 *   (Mandatory)
 */
#define PA_NODE_ID_CMP(node_id1, node_id2) \
	(*(node_id1) > *(node_id2))

/**
 * Node ID print format and arguments.
 *   (Optional - Default to hexadecimal dump)
 */
#include <inttypes.h>
#define PA_NODE_ID_P   "0x%08"PRIx32
#define PA_NODE_ID_PA(node_id) *(node_id)

/**********************************
 *     Prefix Space Specific      *
 **********************************/

/**
 * Prefix storage type and prefix length type.
 *    (Mandatory)
 */
#include <netinet/in.h>
#define PA_PREFIX_TYPE struct in6_addr
#define PA_PLEN_TYPE uint8_t

/**
 * Prefix printing function.
 *
 * It must return the buffer given as argument.
 *
 * Function prototype is:
 *    const char *pa_prefix_tostring(char *dst, const pa_prefix *prefix,
 *    		pa_plen plen)
 *
 * The provided buffer is at least of length PA_PREFIX_STRLEN.
 *    (Mandatory if logging is enabled)
 */
#include "prefix.h"
#define PA_PREFIX_STRLEN PREFIX_MAXBUFFLEN
#define pa_prefix_tostring(buff, p, plen) \
		prefix_ntopc(buff, PA_PREFIX_STRLEN, p, plen)

/**********************************
 *    Hierarchical Assignments    *
 **********************************/

/**
 * Hierarchical prefix assignment allows links to be associated in a tree
 * structure.
 *
 * Prefixes Assigned and Applied on a given link become Delegated Prefixes for
 * links that are below in the Link hierarchy. Each hierarchy level makes use
 * of a different PA instance. Lower-level instances are users of higher level
 * instances.
 */
#define PA_HIERARCHICAL

/**********************************
 *         Timing Values          *
 **********************************/

/**
 * Default value of the maximum time a node waits before adopting a prefix.
 *   (Mandatory)
 */
#define PA_ADOPT_DELAY_DEFAULT 2000

/**
 * Default value of the maximum time a node waits before creating a new
 * assignment.
 *   (Mandatory)
 */
#define PA_BACKOFF_DELAY_DEFAULT 20000

/**********************************
 *   Flooding Mechanism Specific  *
 **********************************/

/**
 * Advertised Prefix Priority type.
 *   (Mandatory)
 */
#define PA_PRIORITY_TYPE uint8_t

/**
 * Advertised Prefix Priority printing format.
 *
 *   (Mandatory)
 */
#include <inttypes.h>
#define PA_PRIO_P "%"PRIu8

/**
 * Default flooding delay in milliseconds.
 *
 * Set when pa_core is initialized.
 *    (Optional - Default to 10000)
 */
#define PA_FLOODING_DELAY_DEFAULT 10000

/**********************************
 *     Implementation specific    *
 **********************************/

/**
 * Logging functions.
 *    (Optional)
 */
#include "hnetd.h"
#define PA_WARNING(format, ...) L_WARN(format, ##__VA_ARGS__)
#define PA_INFO(format, ...)    L_INFO(format, ##__VA_ARGS__)
#define PA_DEBUG(format, ...)   L_DEBUG(format, ##__VA_ARGS__)

/**
 * Internal rule priority type.
 *
 * The value 0 (ZERO) is reserved.
 *
 * The higher the value, the higher the rule priority.
 * When a rule is removed, all Assigned Prefixes which were published by the
 * rule are unpublished and left for adoption to other rules.
 *
 *   (Mandatory)
 */
#define PA_RULE_PRIORITY_TYPE uint16_t
#include <inttypes.h>
#define PA_RULE_PRIO_P "%"PRIu16

/**
 * Delay, in milliseconds, between the events triggering the prefix assignment
 * routine and the actual time it is run.
 *
 * The routine is never run synchronously, even when the delay is set to 0.
 *
 *   (Optional - Default to 20)
 */
#define PA_RUN_DELAY 20

/**
 * The pa_ldp structure may contains PA_LDP_USERS void * pointers, to be used
 * by users for storing private data.
 *    (Optional)
 */
#define PA_LDP_USERS 3
#define PA_LDP_U_HNCP_TLV   0 //Contains the associated TLV
#define PA_LDP_U_HNCP_ADDR  1 //In an AP ldp, points to the assigned Address LDP
#define PA_LDP_U_HNCP_AP    2 //In an AP ldp, contains forbidden addresses advp structs

/**
 * Link type identifier option.
 *
 * When the link structure may be contained in different larger struct, it is
 * useful to identify the type of struct it is included in.
 *    (Optional)
 */
#define PA_LINK_TYPE

#ifdef PA_LINK_TYPE
/**
 * Reserved for links that have no associated type.
 */
#define PA_LINK_TYPE_NONE 0
#endif

/**
 * Delegated Prefix type identifier option.
 *
 * When the delegated prefix structure may be contained in different larger
 * struct, it is useful to identify the type of struct it is included in.
 *    (Optional)
 */
#define PA_DP_TYPE

#ifdef PA_DP_TYPE
/**
 * Reserved for delegated prefixes that have no associated type.
 */
#define PA_DP_TYPE_NONE 0
#endif

/**********************************
 *     Prefix Assignment Rules    *
 **********************************/

/**
 * pa_rule_random provides the available prefix count for
 * all available prefixes up to the maximum plen included.
 *   (Mandatory)
 */
#define PA_RAND_MAX_PLEN 128

/**
 * Random function used by pa_rule_random.
 *   int pa_rand(void)
 */
#include <stdlib.h>
#define pa_rand() random()

/**
 * Pseudo random function used by pa_rule_random.
 */
#ifdef PA_PRAND //Used by pa_rules.c
#include <libubox/md5.h>
static void pa_prand(uint8_t *buff, const uint8_t *seed, size_t seedlen,
		uint32_t ctr0, uint32_t ctr1)
{
	md5_ctx_t ctx;
	md5_begin(&ctx);
	md5_hash(seed, seedlen, &ctx);
	md5_hash(&ctr0, sizeof(ctr0), &ctx);
	md5_hash(&ctr1, sizeof(ctr0), &ctx);
	md5_end(buff, &ctx);
}
#define PA_PRAND_BUFFLEN 16
#endif

#endif
