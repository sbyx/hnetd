/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Implementation of the Distributed Prefix Assignment Algorithm.
 *
 * The algorithm is specified as an IETF Internet Draft:
 * https://tools.ietf.org/html/draft-ietf-homenet-prefix-assignment
 *
 */

#ifndef PA_CORE_H_
#define PA_CORE_H_

#include <libubox/list.h>

#include "hnetd_time.h"

#include "btrie.h"

/***************************
 *     Compatibility       *
 ***************************/

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

/***************************
 * Configuration defaults  *
 ***************************/

#include "pa_conf.h"

#ifndef PA_WARNING
#define PA_WARNING(format, ...) do{}while(0)
#endif
#ifndef PA_INFO
#define PA_INFO(format, ...) do{}while(0)
#endif
#ifndef PA_DEBUG
#define PA_DEBUG(format, ...) do{}while(0)
#endif

typedef PA_PREFIX_TYPE pa_prefix;
typedef PA_PLEN_TYPE pa_plen;
typedef PA_PRIORITY_TYPE pa_priority;
typedef PA_RULE_PRIORITY_TYPE pa_rule_priority;

#ifndef PA_NODE_ID_P
const char *pa_hex_dump(uint8_t *ptr, size_t len, char *s);
#define PA_HEX_DUMP

#define PA_NODE_ID_P   "[%s]"
#define PA_NODE_ID_PA(node_id) pa_hex_dump((uint8_t *)node_id, \
			sizeof(PA_NODE_ID_TYPE)*PA_NODE_ID_LEN, \
			alloca(sizeof(PA_NODE_ID_TYPE)*PA_NODE_ID_LEN*2+1))
#endif

#ifndef PA_DEFAULT_FLOODING_DELAY
#define PA_DEFAULT_FLOODING_DELAY 10000
#endif

#ifndef PA_RUN_DELAY
#define PA_RUN_DELAY 20
#endif

#include "bitops.h"
#define pa_prefix_cpy(sp, splen, dp, dplen) \
			do {bmemcpy(dp, sp, 0, splen); dplen = splen; } while(0)
#define pa_prefix_contains(p1, plen1, p2) (bmemcmp(p1, p2, plen1) == 0)
#define pa_prefix_cmp(p1, l1, p2, l2) \
			((l1==l2)?bmemcmp(p1, p2, l1):((l1>l2)?(bmemcmp(p1, p2, l2) | 1): \
			-(bmemcmp(p2, p1, l1) | 1)))
#define pa_prefix_equals(p1, l1, p2, l2) ((l1==l2)&&(bmemcmp(p1, p2, l1) == 0))
#define pa_prefix_overlap(p1, plen1, p2, plen2) ((plen1 > plen2)? \
			pa_prefix_contains(p2, plen2, p1):pa_prefix_contains(p1, plen1, p2))
#define pa_prefix_repr(p, plen) \
			pa_prefix_tostring(alloca(PA_PREFIX_STRLEN), p, plen)

struct pa_ldp;

/***************************
 *         User API        *
 ***************************/

/**
 * Users may subscribe to PA events using this structure.
 */
struct pa_user {
	struct list_head le; /* Linked in pa_core. */

	/**
	 * A prefix is assigned or unassigned.
	 *
	 * When unassigned, prefix and plen attributes are still valid.
	 */
	void (*assigned)(struct pa_user *, struct pa_ldp *);

	/**
	 * A prefix should be published or stop being published.
	 *
	 * When unpublished, the priority attribute is still valid.
	 * Always called with assigned == 1.
	 */
	void (*published)(struct pa_user *, struct pa_ldp *);

	/**
	 * A prefix can be used or should stop being used.
	 *
	 * Always called with assigned == 1.
	 */
	void (*applied)(struct pa_user *, struct pa_ldp *);
};

/**
 * Register a PA user.
 *
 * When added, the user *does not* receive callbacks for existing prefixes.
 * Use iterators (pa_for_each_ldp_in_link) if it is desired.
 */
#define pa_user_register(core, user) list_add(&(user)->le, &(core)->users)

/**
 * Unregister a user.
 */
#define pa_user_unregister(user) list_del(&(user)->le)


/***************************
 *       Generic API       *
 ***************************/

/**
 * Structure containing state specific to the overall algorithm.
 */
struct pa_core {

	/* btrie containing all Assigned and Advertised Prefixes. */
	struct btrie prefixes;

	/* The Node ID of the local node (default is 0). */
	PA_NODE_ID_TYPE node_id[PA_NODE_ID_LEN];

	/* The Flooding Delay (default PA_FLOODING_DELAY_DEFAULT). */
	uint32_t flooding_delay;

	/* Max wait time before adopting a prefix
	 * (default PA_ADOPT_DELAY_DEFAULT).*/
	uint32_t adopt_delay;

	/* Max wait time before creating a new assignment
	 * (default PA_BACKOFF_DELAY_DEFAULT) */
	uint32_t backoff_delay;

	/* List of all PA users. */
	struct list_head users;

	/*  List of all links. */
	struct list_head links;

	/* List of all delegated prefixes. */
	struct list_head dps;

	/* List of all PA rules. */
	struct list_head rules;

#ifdef PA_HIERARCHICAL

	/* When not-null, points to the parent pa_core structure. */
	struct pa_core *ha_parent;

	/* When a parent is associated, the child subscribes to parent's events.
	 * Prefixes that are assigned or applied by the parent are used as
	 * delegated prefixes by the child. */
	struct pa_user ha_user;

#endif
};

/**
 * Initializes a pa_core structure.
 *
 * Once initialized, it can be configured with rules, prefixes and links.
 *
 * @param core The PA core structure.
 * @return 0 upon success and -1 otherwise.
 */
void pa_core_init(struct pa_core *core);

/**
 * Sets the local node ID.
 *
 * @param core The PA core structure.
 * @param id The new node ID.
 */
void pa_core_set_node_id(struct pa_core *core,
		const PA_NODE_ID_TYPE id[PA_NODE_ID_LEN]);

/**
 * Sets the flooding delay to the specified value.
 *
 * When the delay is increased, all running timers are increased by
 * 'old_flooding_delay - new_flooding_delay'.
 *
 * When the delay is decreased, running apply timers are set to
 * 'min(remaining, new_flooding_delay)'.
 *
 * @param core The PA core structure.
 * @param flooding_delay The new flooding delay in milliseconds
 *        (must be smaller than 2 << 31).
 */
void pa_core_set_flooding_delay(struct pa_core *core, uint32_t flooding_delay);



/**
 * Structure used to identify a Shared or Private Link.
 */
struct pa_link {

	/* Linked in pa_core. */
	struct list_head le;

	/* List of Link/Delegated Prefix pairs associated with this Link. */
	struct list_head ldps;

	/* Link name. Only used for logging (NULL is ok). */
	const char *name;

#ifdef PA_LINK_TYPE
	/* Link type identifier provided by user.
	 * Set to PA_LINK_TYPE_NONE if it has no type.
	 */
	uint8_t type;
#endif
#ifdef PA_HIERARCHICAL
	/* NULL or the parent link.
	 * When a parent link is set, delegated prefix and link pairs (pa_ldp) are
	 * only created for delegated prefixes coming from a prefix assigned by the
	 * parent core structure. */
	struct pa_link *ha_parent;
#endif
};

/**
 * Link print format and arguments.
 */
#define PA_LINK_P "%s"
#define PA_LINK_PA(pa_link) (pa_link)?(pa_link)->name? \
		(pa_link)->name:"no-name":"no-link"

/**
 * Initializes the Link structure.
 *
 * @param link The initialized link.
 * @param name The link name. It is kept as a pointer.
 *             Therefore, it must not be freed while in use by PA.
 */
void pa_link_init(struct pa_link *link, const char *name);

/**
 * Adds a Link for prefix assignment.
 */
int pa_link_add(struct pa_core *, struct pa_link *);

/**
 * Removes a previously added Link.
 */
void pa_link_del(struct pa_link *);

/* Iterates over all links. */
#define pa_for_each_link(pa_core, pa_link) \
	list_for_each_entry(pa_link, &(pa_core)->links, le)
#define pa_for_each_link_safe(pa_core, pa_link, pa_link2) \
	list_for_each_entry_safe(pa_link, pa_link2, &(pa_core)->links, le)

/* Iterates over all delegated prefix/link pair associated with a given link */
#define pa_for_each_ldp_in_link(pa_link, pa_ldp) \
	list_for_each_entry(pa_ldp, &(pa_link)->ldps, in_link)
#define pa_for_each_ldp_in_link_safe(pa_link, pa_ldp, pa_ldp2) \
	list_for_each_entry_safe(pa_ldp, pa_ldp2, &(pa_link)->ldps, in_link)

/*
 * Structure used to identify a Delegated Prefix.
 */
struct pa_dp {

	/* Linked in pa_core. */
	struct list_head le;

	/* List of Link/Delegated Prefixes pairs associated with this
	 * Delegated Prefix. */
	struct list_head ldps;

	/* The delegated prefix value. */
	pa_prefix prefix;

	/* The prefix length of the delegated prefix. */
	pa_plen plen;

#ifdef PA_DP_TYPE
	/* Delegated Prefix type identifier provided by user. */
	uint8_t type;
#endif
#ifdef PA_HIERARCHICAL
	/* NULL, or the higher-level Link/Delegated Prefix this Delegated Prefix
	 * is associated with.
	 * DPs provided by users MUST have this set to NULL. */
	struct pa_ldp *ha_ldp;
#endif
};

/* Delegated Prefix print format and arguments */
#define PA_DP_P "%s"
#define PA_DP_PA(pa_dp) pa_prefix_repr(&(pa_dp)->prefix, (pa_dp)->plen)

/**
 * Initializes a delegated prefix.
 */
void pa_dp_init(struct pa_dp *dp, pa_prefix *prefix, pa_plen plen);

/**
 * Adds a Delegated Prefix for prefix assignment.
 */
int pa_dp_add(struct pa_core *, struct pa_dp *);

/**
 * Removes a previously added Delegated Prefix.
 */
void pa_dp_del(struct pa_dp *);

/* Iterates over all delegated prefixes. */
#define pa_for_each_dp(pa_core, pa_dp) \
	list_for_each_entry(pa_dp, &(pa_core)->dps, le)
#define pa_for_each_dp_safe(pa_core, pa_dp, pa_dp2) \
	list_for_each_entry_safe(pa_dp, pa_dp2, &(pa_core)->dps, le)

/* Iterates over all delegated prefix/link pairs,
 * with the given delegated prefix. */
#define pa_for_each_ldp_in_dp(pa_dp, pa_ldp) \
	list_for_each_entry(pa_ldp, &(pa_dp)->ldps, in_dp)
#define pa_for_each_ldp_in_dp_safe(pa_dp, pa_ldp, pa_ldp2) \
	list_for_each_entry_safe(pa_ldp, pa_ldp2, &(pa_dp)->ldps, in_dp)

/**
 * PA Prefix Entry.
 *
 * Used to link both assigned and advertised prefixes in the same btrie.
 */
struct pa_pentry {
	struct btrie_element be; /* The btrie element. */
	uint8_t type;            /* Prefix type. */
#define PAT_ASSIGNED   0x01  /* For assigned prefixes. */
#define PAT_ADVERTISED 0x02  /* For advertised prefixes. */
};

/**
 * Link/Delegated Prefix pair.
 */
struct pa_ldp {

	/* (if assigned) Linked in pa_core. */
	struct pa_pentry in_core;

	/* Linked in the Link structure. */
	struct list_head in_link;

	/* Linked in the Delegated Prefix structure. */
	struct list_head in_dp;

	/* The associated Link. */
	struct pa_link *link;

	/* The associated Delegated Prefix. */
	struct pa_dp *dp;

	/* Back-pointer to the associated pa_core struct */
	struct pa_core *core;

	/* There is an associated Assigned Prefix. */
	uint8_t assigned  : 1;

	/* The Assigned Prefix is published. */
	uint8_t published : 1;

	/* The Assigned Prefix is applied. */
	uint8_t applied   : 1;

	/* The Assigned Prefix is being adopted.
	 * Implies !published. */
	uint8_t adopting  : 1;

	/* (in routine) The routine is executed following backoff timeout. */
	uint8_t backoff   : 1;

#ifdef PA_HIERARCHICAL
	/* The prefix is ready to be applied, but it is waiting for higher-level
	 * prefix to be applied too. */
	uint8_t ha_apply_pending : 1;
#endif

	/* (if assigned or in user->assigned)
	 * The Assigned Prefix. */
	pa_prefix prefix;

	/* (if assigned or in user->assigned)
	 * The Assigned Prefix length. */
	pa_plen plen;

	/* (if published or in user->published)
	 * The Advertised Prefix Priority. */
	pa_priority priority;

	/* (if published or adopting)
	 * The internal rule priority. */
	pa_rule_priority rule_priority;

	/* (if published or adopting)
	 * The rule used to publish or adopt this prefix. */
	struct pa_rule *rule;

	/* Timer used to schedule the routine. */
	struct uloop_timeout routine_to;

	/* Timer used to backoff prefix generation, adoption or apply. */
	struct uloop_timeout backoff_to;

	/* (in routine) Best on-link assignment. */
	struct pa_advp *best_assignment;

#if PA_LDP_USERS != 0
	/* Generic pointers, initialized to NULL, for use by users. */
	void *userdata[PA_LDP_USERS];
#endif
};

/* Assigned Prefix print format and arguments */
#define PA_LDP_P "%s%%"PA_LINK_P" from "PA_DP_P" flags (%s %s %s)"
#define PA_LDP_PA(pa_ldp) ((pa_ldp)->assigned)? \
		pa_prefix_repr(&(pa_ldp)->prefix, (pa_ldp)->plen):"no-prefix", \
		PA_LINK_PA((pa_ldp)->link), PA_DP_PA((pa_ldp)->dp), \
		((pa_ldp)->published)?"Published":"-", \
		((pa_ldp)->applied)?"Applied":"-", ((pa_ldp)->adopting)?"Adopting":"-"

/*
 * A prefix Advertised Prefix by someone else.
 */
struct pa_advp {

	/* Linked in PA core prefix btrie. */
	struct pa_pentry in_core;

	/* The node ID of the node advertising the prefix. */
	PA_NODE_ID_TYPE node_id[PA_NODE_ID_LEN];

	/* The Advertised Prefix. */
	pa_prefix prefix;

	/* The Advertised Prefix length. */
	pa_plen plen;

	/* The Advertised Prefix Priority. */
	pa_priority priority;

	/* Advertised Prefix associated Shared Link (or null). */
	struct pa_link *link;
};

/* Advertised Prefix print format and arguments. */
#define PA_ADVP_P "%s%%"PA_LINK_P"@"PA_NODE_ID_P":(%d)"
#define PA_ADVP_PA(pa_advp) pa_prefix_repr(&(pa_advp)->prefix, \
		(pa_advp)->plen), PA_LINK_PA((pa_advp)->link), \
		PA_NODE_ID_PA((pa_advp)->node_id), (pa_advp)->priority

/**
 * Adds a new Advertised Prefix.
 */
int pa_advp_add(struct pa_core *, struct pa_advp *);

/**
 * Removes an Advertised Prefix which was previously added.
 */
void pa_advp_del(struct pa_core *, struct pa_advp *);

/**
 * Notify a change in the advertised prefix.
 *
 * Any attribute but the prefix and plen attributes may be updated this way.
 */
void pa_advp_update(struct pa_core *, struct pa_advp *);

/*
 * The provider of advertised prefix should not store advertised prefixes by
 * itself, as they are all stored in the pa_core structure.
 * The following iterators can be used to efficiently retrieve stored
 * advertised prefixes.
 */

/* Iterates over all advertised prefixes having the exact given prefix. */
#define pa_for_each_advp(pa_core, pa_adv, prefix, plen) \
	btrie_for_each_entry(pa_adv, &(pa_core)->prefixes, \
			(btrie_key_t *)prefix, plen, in_core.be) \
		if((pa_adv)->in_core.type == PAT_ADVERTISED)

/* Iterates safely over all advertised prefixes having the exact given prefix.*/
#define pa_for_each_advp_safe(pa_core, pa_adv, pa_adv2, prefix, plen) \
	btrie_for_each_entry_safe(pa_adv, pa_adv2, &(pa_core)->prefixes, \
			(btrie_key_t *)prefix, plen, in_core.be) \
		if((pa_adv)->in_core.type == PAT_ADVERTISED)

/* Compare the advertised prefix node id with a given node id
 * (useful with previous iterators for filtering based on node_id) */
#define pa_advp_nodeid_cmp(advp, node_id) \
	memcmp((advp)->node_id, node_id, PA_NODE_ID_LEN*sizeof(PA_NODE_ID_TYPE))


/***************************
 *   Configuration API     *
 ***************************/

/**
 * This API is an advanced rule-based configuration tool.
 *
 * Rules specify the way the prefix assignment advertise prefixes. Without
 * rules, the prefix assignment algorithm never make assignments but listens
 * to assignments made by others.
 *
 *  /!\ Warning /!\
 * Rules are supposed to behave in conformance with the prefix assignment
 * algorithm specifications. One should understand the algorithm behavior
 * before trying to implement a rule.
 * pa_core does not check for rules behavior correctness. An incorrect rule may
 * result in faults.
 *
 * User-friendly rules are defined in pa_rules.h.
 */

/* The rule target indicates the desired behavior of a rule on a given ldp. */
enum pa_rule_target {
	/* The rule does not match.
	 * Always valid. */
	PA_RULE_NO_MATCH = 0,

	 /* The rule desires to adopt the orphan prefix.
	  * Valid when: (assigned && !published && !best_assignment) */
	PA_RULE_ADOPT,

	/* The rule desires to make an assignment later.
	 * Valid when: (!assigned) */
	PA_RULE_BACKOFF,

	/* The rule desires to assign and publish a prefix immediately.
	 * Always valid (with a high enough rule_priority and priority) */
	PA_RULE_PUBLISH,

	/* The rule desires to unassign the prefix immediately.
	 * Valid when: (published || adopting) */
	PA_RULE_DESTROY,
};

/**
 * The argument given to rule's match function in order to get
 * more information about the desired behavior. */
struct pa_rule_arg {
	/* The rule priority indicates the internal priority of the desired action. */
	pa_rule_priority rule_priority;

	/* The prefix and prefix length to be published. Must be set when match
	 * function returns PA_RULE_PUBLISH. */
	pa_prefix prefix;
	pa_plen plen;

	/* The pa priority must be specified by the match function when it returns
	 * PA_RULE_PUBLISH or PA_RULE_ADOPT. It is the priority with which the prefix
	 * will be advertised.
	 */
	pa_priority priority;
};

/**
 * Prefix assignment low-level rule.
 */
struct pa_rule {

	/* Linked in pa_core. */
	struct list_head le;

	/* Rule name, displayed in logs (NULL is ok). */
	const char *name;

	/**
	 * Must return whether the rule can be used for the given ldp.
	 * If NULL, the rule is accepted.
	 */
	int (*filter_accept)(struct pa_rule *, struct pa_ldp *, void *p);
	void *filter_private; //Passed to filter function.

	/**
	 * Must return the maximal rule priority the rule may use when 'match' is
	 * called with the same pa_ldp.
	 *
	 * It is used to determine the order rules 'match' functions will be called
	 * later. If NULL, the max_priority value is used instead.
	 *
	 * 0 should be returned when the rule cannot match.
	 * In such case, or when the returned max_priority is smaller than another
	 * matching rule, 'match' will not be called.
	 *
	 * @param pa_rule The rule from which the function is called.
	 * @param pa_ldp The considered Link/Delegated Prefix pair.
	 * @return The maximum priority 'match' would pick given the same
	 *         parameters.
	 *
	 */
	pa_rule_priority (*get_max_priority)(struct pa_rule *, struct pa_ldp *);

	/* If get_max_priority is NULL, this value is used instead. */
	pa_rule_priority max_priority;

	/**
	 * Must return the target specified by the rule.
	 *
	 * @param pa_rule The rule from which the function is called.
	 * @param pa_ldp The considered Link/DP pair.
	 * @param best_match_priority The priority of the preferred matching rule.
	 *        There is no point doing heavy computations if the returned rule
	 *        priority is lower or equal to this value. As it would be ignored.
	 * @param pa_arg Arguments to be filled by the function
	 *               (see struct definition).
	 * @return The rule desired target.
	 */
	 enum pa_rule_target (*match)(struct pa_rule *, struct pa_ldp *,
			pa_rule_priority best_match_priority,
			struct pa_rule_arg *pa_arg);

	 /* PRIVATE - Used by pa_core. */
	 pa_rule_priority _max_priority;
	 struct list_head _le;
};

/* pa_rule print format and argument */
#define PA_RULE_P "'%s'@%p"
#define PA_RULE_PA(rule) (rule)->name?(rule)->name:"no-name", rule

/**
 * Add a rule to the given PA core structure.
 */
void pa_rule_add(struct pa_core *, struct pa_rule *);

/**
 * Remove a previously added rule to the PA core structure.
 */
void pa_rule_del(struct pa_core *, struct pa_rule *);


/***************************
 * Rules Utility Functions *
 ***************************/

/**
 * Checks if a candidate assignment would be a valid assignment for a given ldp.
 *
 * @param prefix The candidate prefix.
 * @param plen The candidate prefix length.
 * @param override_rule_priority
 *           Assignment is not valid if conflicting ldps have higher or equal
 *           rule priority.
 * @param override_priority
 *           Assignment is not valid if existing advertised prefix have
 *           higher or equal advertised prefix priority.
 * @param safety
 *           When set, assignment is not valid if a conflicting ldp have a
 *           strictly higher advertised prefix priority.
 *           This is to avoid assignment loops.
 *           If you don't understand why it is safer to set the safety, please
 *           set the safety. You'll be safer.
 * @return Whether the candidate assignment would be valid.
 */
int pa_rule_valid_assignment(struct pa_ldp *ldp, pa_prefix *prefix, pa_plen plen,
		pa_rule_priority override_rule_priority, pa_priority override_priority,
		uint8_t safety);


#ifdef PA_HIERARCHICAL
/***************************
 * Hierarchical Assignment *
 ***************************/

/**
 * Sets a pa_core structure as hierarchically lower than the parent.
 *
 * A PA structure can have a single parent. This function must not be called
 * if the child is already attached to some parent.
 *
 * @param child Initialized PA structure which will attach to the parent.
 * @param parent Initialized PA structure used as parent.
 * @param fast_assignment Whether sub-prefixes may be assigned (but not applied)
 *                        before higher level prefixes are applied.
 */
void pa_ha_attach(struct pa_core *child, struct pa_core *parent,
		uint8_t fast_assignment);

/**
 * Removes the parent of the PA structure.
 *
 * The child must have been previously attached.
 *
 * @param child The child PA structure.
 */
void pa_ha_detach(struct pa_core *child);
#endif


#endif
