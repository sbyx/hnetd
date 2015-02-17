/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 */


#include "pa_core.h"

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "prefix.h"

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifdef PA_HEX_DUMP
const char *pa_hex_dump(uint8_t *ptr, size_t len, char *s) {
	char n;
	s[2*len] = '\0';
	for(;len;len--) {
		n = (ptr[len] & 0xf0) >> 4;
		s[2*len - 2] = (n > 9)?('a'+(n-10)):('0'+n);
		n = (ptr[len] & 0x0f);
		s[2*len - 1] = (n > 9)?('a'+(n-10)):('0'+n);
	}
	return s;
}
#endif

/* Returns whether the Advertised Prefix takes precedence over the Assigned Prefix. */
#define pa_precedes(advp, ldp) \
	((!ldp->published) || ((advp)->priority > (ldp)->priority) || \
	(((advp)->priority == (ldp)->priority) && memcmp((advp)->node_id, (ldp)->core->node_id, PA_NODE_ID_LEN*sizeof(PA_NODE_ID_TYPE))))

#define pa_for_each_user(pa_core, pa_user) list_for_each_entry(pa_user, &(pa_core)->users, le)

#define pa_user_notify(pa_ldp, function) \
	do { \
		struct pa_user *_pa_user_notify_user; \
		pa_for_each_user((pa_ldp)->core, _pa_user_notify_user) { \
			if(_pa_user_notify_user->function) \
				_pa_user_notify_user->function(_pa_user_notify_user, ldp);\
		} \
	} while(0)

#define pa_routine_schedule(ldp) do { \
	if(!(ldp)->routine_to.pending) \
		uloop_timeout_set(&(ldp)->routine_to, PA_RUN_DELAY); }while(0)

#define PA_ADOPT_DELAY_r(ldp) (pa_rand() % (ldp)->core->adopt_delay)
#define PA_BACKOFF_DELAY_r(ldp) ((ldp)->core->adopt_delay + pa_rand() % ((ldp)->core->backoff_delay - (ldp)->core->adopt_delay))

static void pa_ldp_apply(struct pa_ldp *ldp)
{
	if(ldp->applied)
		return;

#ifdef PA_HIERARCHICAL
	if(ldp->dp->ha_ldp && !ldp->dp->ha_ldp->applied) {
		PA_DEBUG("Apply of "PA_LDP_P" must wait for "PA_LDP_P" being applied", PA_LDP_PA(ldp),  PA_LDP_PA(ldp->dp->ha_ldp));
		ldp->ha_apply_pending = 1;
		return;
	}
#endif

	PA_DEBUG("Applying "PA_LDP_P, PA_LDP_PA(ldp));

	ldp->applied = 1;
	ldp->ha_apply_pending = 0;
	pa_user_notify(ldp, applied);
}

static void pa_ldp_unpublish(struct pa_ldp *ldp, bool cancel_apply)
{
	if(!ldp->published)
		return;

	PA_DEBUG("Un-publishing "PA_LDP_P, PA_LDP_PA(ldp));
	ldp->rule = NULL;
	ldp->priority = 0;
	ldp->rule_priority = 0;

	if(cancel_apply && ldp->backoff_to.pending)
		uloop_timeout_cancel(&ldp->backoff_to);

	ldp->published = 0;

	pa_user_notify(ldp, published);
}

static void pa_ldp_unadopt(struct pa_ldp *ldp)
{
	if(!ldp->adopting)
		return;

	PA_DEBUG("Un-adopting "PA_LDP_P, PA_LDP_PA(ldp));
	ldp->rule = NULL;
	ldp->priority = 0;
	ldp->rule_priority = 0;

	ldp->adopting = 0;

	//Un-adopt means we are going to either publish, destroy, or someone else publishes
	if(!ldp->applied)
		uloop_timeout_set(&ldp->backoff_to, ldp->core->flooding_delay * 2);
}

static void pa_ldp_publish(struct pa_ldp *ldp, struct pa_rule *rule,
		pa_priority priority, pa_rule_priority rule_priority)
{
	if(ldp->published)
		return;

	//publish and adopt are incompatible states
	pa_ldp_unadopt(ldp);

	//Assignments are published by rules,
	//with associated rule and assignment priority
	ldp->rule = rule;
	ldp->priority = priority;
	ldp->rule_priority = rule_priority;

	ldp->published = 1;
	PA_DEBUG("Published "PA_LDP_P, PA_LDP_PA(ldp));

	pa_user_notify(ldp, published);
}

static void pa_ldp_adopt(struct pa_ldp *ldp, struct pa_rule *rule,
		pa_priority priority, pa_rule_priority rule_priority)
{
	if(ldp->adopting)
		return;

	//publish and adopt are incompatible states
	pa_ldp_unpublish(ldp, 1);

	//Assignments are adopted by rules,
	//with associated rule and assignment priority
	ldp->rule = rule;
	ldp->priority = priority;
	ldp->rule_priority = rule_priority;

	ldp->adopting = 1;
	uloop_timeout_set(&ldp->backoff_to, PA_ADOPT_DELAY_r(ldp));

	PA_DEBUG("Adopting "PA_LDP_P, PA_LDP_PA(ldp));
}

static void pa_ldp_unassign(struct pa_ldp *ldp)
{
	struct pa_ldp *ldp2;
	if(!ldp->assigned)
		return;

#ifdef PA_HIERARCHICAL
	ldp->ha_apply_pending = 0;
#endif
	if(ldp->applied) {
		ldp->applied = 0;
		pa_user_notify(ldp, applied);
	}

	pa_ldp_unpublish(ldp, 1);
	pa_ldp_unadopt(ldp);
	uloop_timeout_cancel(&ldp->backoff_to);
	PA_INFO("Un-assign prefix: "PA_LDP_P, PA_LDP_PA(ldp));

	btrie_remove(&ldp->in_core.be);
	ldp->assigned = 0;
	pa_user_notify(ldp, assigned); /* Tell users about that */

	/* Destroying the Assigned Prefix possibly freed space that other interfaces may use.
	 * Schedule links for the same dp, if there is no current prefix.
	 * This can be ignored when no prefix is ever created by the local node. */
	pa_for_each_ldp_in_dp(ldp->dp, ldp2) {
		if(!ldp2->assigned && (ldp2 != ldp))
			pa_routine_schedule(ldp2);
	}
}

static int pa_ldp_assign(struct pa_ldp *ldp, pa_prefix *prefix, pa_plen plen)
{
	if(ldp->assigned) {
		if(!pa_prefix_equals(prefix, plen, &ldp->prefix, ldp->plen))
			PA_WARNING("Could not assign %s to "PA_LDP_P, pa_prefix_repr(prefix, plen), PA_LDP_PA(ldp));
		return -2;
	}

	pa_prefix_cpy(prefix, plen, &ldp->prefix, ldp->plen);
	if(btrie_add(&ldp->core->prefixes, &ldp->in_core.be, (const btrie_key_t *)prefix, plen)) {
		PA_WARNING("Could not assign %s to "PA_LINK_P, pa_prefix_repr(prefix, plen), PA_LINK_PA(ldp->link));
		return -1;
	}

	//Cancel backoff timer and set apply timer
	PA_DEBUG("Set apply timer %d", 2 * ldp->core->flooding_delay);
	uloop_timeout_set(&ldp->backoff_to, 2 * ldp->core->flooding_delay);

	ldp->assigned = 1;
	PA_INFO("Assigned prefix: "PA_LDP_P, PA_LDP_PA(ldp));
	pa_user_notify(ldp, assigned); /* Tell users about that*/
	return 0;
}

static bool pa_ldp_global_valid(struct pa_ldp *ldp)
{
	/* There can't be any ldp except the one which is checked.
	 * If there are overlapping DPs, this assumption may be wrong and
	 * this code would bug. */
	struct pa_advp *advp;
	btrie_for_each_updown_entry(advp, &ldp->core->prefixes, (btrie_key_t *)&ldp->prefix, ldp->plen, in_core.be) {
		if(&advp->in_core != &ldp->in_core && pa_precedes(advp, ldp))
			return false;
	}
	return true;
}

/*
 * Prefix Assignment Routine.
 */
static void pa_routine(struct pa_ldp *ldp, bool backoff)
{
	PA_DEBUG("Executing PA %sRoutine for "PA_LDP_P, backoff?"backoff ":"", PA_LDP_PA(ldp));

	/*
	 * The algorithm is slightly modified in order to provide support for
	 * custom behavior.
	 * 1. The Best Assignment is fetched and checked.
	 * 2. The validity of the Current Assignment is checked.
	 * 3. Rules may be applied to create/adopt/delete assignments.
	 * 4. The prefix is removed if still invalid, and the routine
	 * is executed assuming existing assignment validity (That is, we assume
	 * rules provide valid assignments).
	 */

	/*********************************
	 * 1. Look for best Adv. Prefix  *
	 *********************************/
	struct pa_advp *advp;
	struct pa_pentry *pentry;
	ldp->best_assignment = NULL;
	btrie_for_each_updown_entry(pentry, &ldp->core->prefixes,
			(btrie_key_t *)&ldp->dp->prefix, ldp->dp->plen, be) {
		if(pentry->type == PAT_ADVERTISED) {
			advp = container_of(pentry, struct pa_advp, in_core);
			if(advp->link == ldp->link &&
					(!ldp->best_assignment ||
					advp->priority > ldp->best_assignment->priority ||
					((advp->priority == ldp->best_assignment->priority) &&
							(PA_NODE_ID_CMP(advp->node_id, ldp->best_assignment->node_id) > 0))))
				ldp->best_assignment = advp;
		}
	}

	/*********************************
	 * 2. Check Assignment Validity. *
	 *********************************/

	if(!ldp->best_assignment || !pa_precedes(ldp->best_assignment, ldp))
		ldp->best_assignment = NULL; //We don't really care about invalid best assignments.

	if(ldp->assigned) { //Check whether the algorithm would keep that prefix or destroy it.
		bool valid;
		if(!ldp->best_assignment) {
			valid = pa_ldp_global_valid(ldp); //Globally valid
		} else {
			valid = pa_prefix_equals(&ldp->prefix, ldp->plen, //Different from Best Assignment
					&ldp->best_assignment->prefix, ldp->best_assignment->plen);
		}
		if(!valid)
			pa_ldp_unassign(ldp);
	}

	/* If there is a best assignment, we can't adopt the prefix. */
	if(ldp->best_assignment)
		pa_ldp_unadopt(ldp);

	/*********************
	 * 3. Execute rules. *
	 *********************/

	struct pa_rule *rule, *r2;
	struct list_head rules, *insert;
	INIT_LIST_HEAD(&rules);
	ldp->backoff = backoff?1:0;

	/* First, sort the rules with their max priority. */
	list_for_each_entry(rule, &ldp->core->rules, le) {
		/* Apply rule filter */
		if(rule->filter_accept && !rule->filter_accept(rule, ldp, rule->filter_private))
			continue;

		/* Get priority */
		rule->_max_priority = rule->get_max_priority?
				rule->get_max_priority(rule, ldp):rule->max_priority;

		if(!rule->_max_priority)
			continue;

		/* Insert the rule in descending order. */
		insert = &rules;
		list_for_each_entry(r2, &rules, _le) {
			if(r2->_max_priority < rule->_max_priority)
				break;
			insert = &r2->_le;
		}
		list_add(&rule->_le, insert);
	}

	/* Now get the best rule result. */
	enum pa_rule_target target,
				best_target = PA_RULE_NO_MATCH;
	pa_rule_priority best_prio;
	struct pa_rule_arg arg, best_arg;
	struct pa_rule *best_rule = NULL;

	//Get existing rule priority
	best_prio = (ldp->published || ldp->adopting)?ldp->rule_priority:0;

	list_for_each_entry(rule, &rules, _le) {
		if(rule->_max_priority <= best_prio)
			break; //Stop here as it is a sorted list

		/* For now, we assume rules behave correctly.
		 * They only return a match when they have the best
		 * priority, and everything they say is valid.
		 */
		if(!rule->match || !(target = rule->match(rule, ldp, best_prio, &arg)))
				continue;

		best_arg = arg;
		best_target = target;
		best_prio = arg.rule_priority;
		best_rule = rule;
	}

	if(best_target == PA_RULE_NO_MATCH)
		PA_DEBUG("No matching rule was found.");
	else
		PA_DEBUG("Rule "PA_RULE_P" matched", PA_RULE_PA(best_rule));

	/* Now act upon the best rule */
	struct pa_ldp *ldp2;
	struct pa_pentry *pentry2;
	switch (best_target) {
		case PA_RULE_ADOPT:
			PA_DEBUG("Target: Adoption %s - priority="PA_PRIO_P" rule_priority="PA_RULE_PRIO_P, pa_prefix_repr(&ldp->prefix, ldp->plen),
					best_arg.priority, best_arg.rule_priority);
			pa_ldp_adopt(ldp, best_rule, best_arg.priority, best_arg.rule_priority);
			break;
		case PA_RULE_BACKOFF:
			PA_DEBUG("Target: Backoff");
			if(ldp->best_assignment) {
				PA_WARNING("Backoff is not a valid rule target, as there is a best assignment.");
				break;
			}
			//Unassign if assigned.
			//Backoff only makes sense for not assigned ldps
			pa_ldp_unassign(ldp);
			//If already pending, we can keep waiting.
			if(!ldp->backoff_to.pending)
				uloop_timeout_set(&ldp->backoff_to, PA_BACKOFF_DELAY_r(ldp));
			break;
		case PA_RULE_DESTROY:
			PA_DEBUG("Target: Destroy %s", pa_prefix_repr(&ldp->prefix, ldp->plen));
			pa_ldp_unassign(ldp);
			pa_routine_schedule(ldp); //We will have to start again
			break;
		case PA_RULE_PUBLISH:
			PA_DEBUG("Target: Publish %s - priority="PA_PRIO_P" rule_priority="PA_RULE_PRIO_P, pa_prefix_repr(&best_arg.prefix, best_arg.plen),
								best_arg.priority, best_arg.rule_priority);

			/* Unassign conflicting prefixes on other ldps */
			btrie_for_each_updown_entry_safe(pentry, pentry2, &ldp->core->prefixes, (btrie_key_t *)&best_arg.prefix, best_arg.plen, be) {
				if(pentry->type == PAT_ASSIGNED && (pentry != &ldp->in_core)) {
					ldp2 = container_of(pentry, struct pa_ldp, in_core);
					pa_ldp_unassign(ldp2);
					pa_routine_schedule(ldp2);
				}
			}

			if(ldp->assigned &&
					!pa_prefix_equals(&best_arg.prefix, best_arg.plen, &ldp->prefix, ldp->plen)) {
				pa_ldp_unassign(ldp);
			}

			if(ldp->assigned) {
				pa_ldp_unpublish(ldp, 0);
				pa_ldp_unadopt(ldp);
			} else {
				pa_ldp_assign(ldp, &best_arg.prefix, best_arg.plen);
			}
			pa_ldp_publish(ldp, best_rule, best_arg.priority, best_arg.rule_priority);

			//publish must return a valid advertisement
			ldp->best_assignment = NULL;

			//TODO: Send an update to FM instead of un-publish+publish
			break;
		case PA_RULE_NO_MATCH:
		default:
			break;
	}

	/*********************************
	 * 4. End the routine            *
	 *********************************/

	if(ldp->assigned) {
		//Assigned and valid

		if(ldp->best_assignment) {
			//Same prefix is advertised by someone else
			pa_ldp_unpublish(ldp, 0); //Give-up prefix
			pa_ldp_unadopt(ldp); //Cancel adoption
		} else if(!ldp->published && !ldp->adopting) {
			//Nobody advertises the prefix, and no rule tried to save the prefix
			//So it shall die.
			pa_ldp_unassign(ldp);
		}

	} else if (ldp->best_assignment) {
		//Should accept the best_assignment
		pa_ldp_unassign(ldp);
		pa_ldp_assign(ldp, &ldp->best_assignment->prefix, ldp->best_assignment->plen);
	}
}

static void pa_backoff_to(struct uloop_timeout *to)
{
	struct pa_ldp *ldp = container_of(to, struct pa_ldp, backoff_to);
	if(ldp->adopting) { //Adopt timeout
		pa_ldp_publish(ldp, ldp->rule, ldp->priority, ldp->rule_priority);
	} else if(ldp->assigned) { //Apply timeout
		pa_ldp_apply(ldp);
	} else { //Backoff delay
		pa_routine(ldp, true);
	}
}

static void pa_routine_to(struct uloop_timeout *to)
{
	struct pa_ldp *ldp = container_of(to, struct pa_ldp, routine_to);
	pa_routine(ldp, false);
}

/*
 * Create a new empty link/dp pairing.
 */
static int pa_ldp_create(struct pa_core *core, struct pa_link *link, struct pa_dp *dp)
{
	struct pa_ldp *ldp;
	if(!(ldp = calloc(1, sizeof(*ldp)))) {
		PA_WARNING("FAILED to create state for "PA_LINK_P"/"PA_DP_P, PA_LINK_PA(link), PA_DP_PA(dp));
		return -1;
	}

	ldp->backoff_to.cb = pa_backoff_to;
	ldp->routine_to.cb = pa_routine_to;
	ldp->in_core.type = PAT_ASSIGNED;
	ldp->core = core;
	ldp->link = link;
	list_add_tail(&ldp->in_link, &link->ldps);
	ldp->dp = dp;
	list_add_tail(&ldp->in_dp, &dp->ldps);
	PA_DEBUG("Creating Link/Delegated Prefix pair: "PA_LDP_P, PA_LDP_PA(ldp));
	pa_routine_schedule(ldp);
	return 0;
}

/*
 * Destroy an ldp. All states must be to 0.
 */
static void pa_ldp_destroy(struct pa_ldp *ldp)
{
	PA_DEBUG("Destroying Link/Delegated Prefix pair: "PA_LDP_P, PA_LDP_PA(ldp));
	list_del(&ldp->in_link);
	list_del(&ldp->in_dp);
	uloop_timeout_cancel(&ldp->backoff_to);
	uloop_timeout_cancel(&ldp->routine_to);
	free(ldp);
}

static void _pa_dp_del(struct pa_dp *dp)
{
	struct pa_ldp *ldp, *ldp2;
	//Public part
	pa_for_each_ldp_in_dp(dp, ldp)
		pa_ldp_unassign(ldp);

	//Private part (so the whole deletion is atomic for users)
	pa_for_each_ldp_in_dp_safe(dp, ldp, ldp2)
		pa_ldp_destroy(ldp);
	list_del(&dp->le);
}

void pa_dp_del(struct pa_dp *dp)
{
	PA_INFO("Removing Delegated Prefix "PA_DP_P, PA_DP_PA(dp));
	_pa_dp_del(dp);
}

int pa_dp_add(struct pa_core *core, struct pa_dp *dp)
{
	PA_INFO("Adding Delegated Prefix "PA_DP_P, PA_DP_PA(dp));
	INIT_LIST_HEAD(&dp->ldps);
	list_add_tail(&dp->le, &core->dps);
	struct pa_link *link;
	pa_for_each_link(core, link) {
#ifdef PA_HIERARCHICAL
		/* If dp is from higher level and the link is the child of a higher level link.
		 * Compare the two links.  */
		if(dp->ha_ldp && link->ha_parent && link->ha_parent != dp->ha_ldp->link) {
			PA_DEBUG("Hierarchical Assignment: No state for link %s", link->name);
			continue;
		}
#endif

		if(pa_ldp_create(core, link, dp)) {
			PA_WARNING("FAILED to add Delegated Prefix "PA_DP_P, PA_DP_PA(dp));
			_pa_dp_del(dp);
			return -1;
		}
	}
	return 0;
}

void pa_dp_init(struct pa_dp *dp, pa_prefix *prefix, pa_plen plen)
{
	pa_prefix_cpy(prefix, plen, &dp->prefix, dp->plen);
#ifdef PA_DP_TYPE
	dp->type = PA_DP_TYPE_NONE;
#endif
#ifdef PA_HIERARCHICAL
	dp->ha_ldp = NULL;
#endif
}

static void _pa_link_del(struct pa_link *link)
{
	struct pa_ldp *ldp, *ldp2;
	//Public part
	pa_for_each_ldp_in_link(link, ldp)
		pa_ldp_unassign(ldp);

	//Private part (so the whole deletion is atomic for users)
	pa_for_each_ldp_in_link_safe(link, ldp, ldp2)
	pa_ldp_destroy(ldp);

	list_del(&link->le);
}

void pa_link_del(struct pa_link *link)
{
	PA_INFO("Removing Link "PA_LINK_P, PA_LINK_PA(link));
	_pa_link_del(link);
}

int pa_link_add(struct pa_core *core, struct pa_link *link)
{
	PA_INFO("Adding Link "PA_LINK_P, PA_LINK_PA(link));
	INIT_LIST_HEAD(&link->ldps);
	list_add_tail(&link->le, &core->links);
	struct pa_dp *dp;
	pa_for_each_dp(core, dp) {
#ifdef PA_HIERARCHICAL
		/* If dp is from higher level and the link is the child of a higher level link.
		 * Compare the two links.  */
		if(dp->ha_ldp && link->ha_parent && link->ha_parent != dp->ha_ldp->link)
			continue;
#endif
		if(pa_ldp_create(core, link, dp)) {
			PA_WARNING("FAILED to add Link "PA_LINK_P, PA_LINK_PA(link));
			_pa_link_del(link);
			return -1;
		}
	}
	return 0;
}

void pa_link_init(struct pa_link *link, const char *name)
{
	link->name = name;
#ifdef PA_LINK_TYPE
	link->type = PA_LINK_TYPE_NONE;
#endif
#ifdef PA_HIERARCHICAL
	link->ha_parent = NULL;
#endif
}

static void _pa_advp_update(struct pa_core *core, struct pa_advp *advp)
{
	struct pa_dp *dp;
	struct pa_ldp *ldp;
	pa_for_each_dp(core, dp) {
		/* Schedule all for dps overlapping with the advp. */
		//TODO: Maybe not necessary to schedule if we have Current and advp is not overlapping with it.
		if(pa_prefix_overlap(&dp->prefix, dp->plen, &advp->prefix, advp->plen)) {
			pa_for_each_ldp_in_dp(dp, ldp)
					pa_routine_schedule(ldp);
		}
	}
}

/* Tell the content of the Advertised Prefix was changes. */
void pa_advp_update(struct pa_core *core, struct pa_advp *advp)
{
	PA_DEBUG("Updating Advertised Prefix "PA_ADVP_P, PA_ADVP_PA(advp));
	_pa_advp_update(core, advp);
}

/* Adds a new Advertised Prefix. */
int pa_advp_add(struct pa_core *core, struct pa_advp *advp)
{
	PA_DEBUG("Adding Advertised Prefix "PA_ADVP_P, PA_ADVP_PA(advp));
	advp->in_core.type = PAT_ADVERTISED;
	if(btrie_add(&core->prefixes, &advp->in_core.be, (btrie_key_t *)&advp->prefix, advp->plen)) {
		PA_WARNING("Could not add Advertised Prefix "PA_ADVP_P, PA_ADVP_PA(advp));
		return -1;
	}

	_pa_advp_update(core, advp);
	return 0;
}

/* Removes an added Advertised Prefix. */
void pa_advp_del(struct pa_core *core, struct pa_advp *advp)
{
	PA_DEBUG("Deleting Advertised Prefix "PA_ADVP_P, PA_ADVP_PA(advp));
	btrie_remove(&advp->in_core.be);
	_pa_advp_update(core, advp);
}

void pa_rule_add(struct pa_core *core, struct pa_rule *rule)
{
	PA_DEBUG("Adding rule "PA_RULE_P, PA_RULE_PA(rule));
	list_add_tail(&rule->le, &core->rules);
	/* Schedule all routines */
	struct pa_link *link;
	struct pa_ldp *ldp;
	pa_for_each_link(core, link)
		pa_for_each_ldp_in_link(link, ldp)
			pa_routine_schedule(ldp);
}

void pa_rule_del(struct pa_core *core, struct pa_rule *rule)
{
	PA_DEBUG("Deleting rule "PA_RULE_P, PA_RULE_PA(rule));
	list_del(&rule->le);
	struct pa_link *link;
	struct pa_ldp *ldp;
	pa_for_each_link(core, link)
		pa_for_each_ldp_in_link(link, ldp) {
			pa_routine_schedule(ldp);
			if(ldp->rule == rule) {
				pa_ldp_unpublish(ldp, 1);
				pa_ldp_unadopt(ldp);
			}
		}
}

void pa_core_set_flooding_delay(struct pa_core *core, uint32_t flooding_delay)
{
	PA_INFO("Set Flooding Delay to %"PRIu32, flooding_delay);
	struct pa_link *link;
	struct pa_ldp *ldp;
	if(flooding_delay > core->flooding_delay) {
		pa_for_each_link(core, link)
			pa_for_each_ldp_in_link(link, ldp)
				if(ldp->assigned && !ldp->adopting && ldp->backoff_to.pending)
					uloop_timeout_set(&ldp->backoff_to, uloop_timeout_remaining(&ldp->backoff_to) + 2*(flooding_delay - core->flooding_delay));
	} else if (flooding_delay < core->flooding_delay) {
		pa_for_each_link(core, link)
			pa_for_each_ldp_in_link(link, ldp)
				if(ldp->assigned && !ldp->adopting && ldp->backoff_to.pending && ((uint32_t)uloop_timeout_remaining(&ldp->backoff_to) > 2*flooding_delay))
					uloop_timeout_set(&ldp->backoff_to, 2*flooding_delay);
	}
	core->flooding_delay = flooding_delay;
}

void pa_core_set_node_id(struct pa_core *core, const PA_NODE_ID_TYPE node_id[])
{
	PA_INFO("Set Node ID to "PA_NODE_ID_P, PA_NODE_ID_PA(node_id));
	struct pa_link *link;
	struct pa_ldp *ldp;
	if(memcmp(node_id, core->node_id, PA_NODE_ID_LEN*sizeof(PA_NODE_ID_TYPE))) {
		memcpy(core->node_id, node_id, PA_NODE_ID_LEN*sizeof(PA_NODE_ID_TYPE));
		/* Schedule routine for all pairs */
		pa_for_each_link(core, link)
			pa_for_each_ldp_in_link(link, ldp)
				pa_routine_schedule(ldp);
	}
}

void pa_core_init(struct pa_core *core)
{
	PA_INFO("Initialize Prefix Assignment Algorithm Core");
	INIT_LIST_HEAD(&core->dps);
	INIT_LIST_HEAD(&core->links);
	INIT_LIST_HEAD(&core->users);
	INIT_LIST_HEAD(&core->rules);
	btrie_init(&core->prefixes);
	memset(core->node_id, 0, PA_NODE_ID_LEN *sizeof(PA_NODE_ID_TYPE));
	core->flooding_delay = PA_DEFAULT_FLOODING_DELAY;
	core->adopt_delay = PA_ADOPT_DELAY_DEFAULT;
	core->backoff_delay = PA_BACKOFF_DELAY_DEFAULT;
#ifdef PA_HIERARCHICAL
	core->ha_parent = NULL;
#endif
}


int pa_rule_valid_assignment(struct pa_ldp *ldp, pa_prefix *prefix, pa_plen plen,
		pa_rule_priority override_rule_priority, pa_priority override_priority,
		uint8_t safety)
{
	struct pa_pentry *p;
	struct pa_advp *advp;
	struct pa_ldp *ldp2;

	if(ldp->best_assignment) {
		if(ldp->best_assignment->priority >= override_priority)
			return 0;
	} else if(ldp->assigned) {
		if((ldp->published || ldp->adopting) && (ldp->rule_priority >= override_rule_priority))
			return 0;
		else if(safety && ldp->published && (ldp->priority >= override_priority))
			return 0;
	}

	btrie_for_each_updown_entry(p, &ldp->core->prefixes, (btrie_key_t *)prefix, plen, be) {
		if(p->type == PAT_ASSIGNED) {
			ldp2 = container_of(p, struct pa_ldp, in_core);
			if((ldp2->published || ldp2->adopting) && (ldp2->rule_priority >= override_rule_priority))
				return 0;
			if(safety && ldp2->published && (ldp2->priority > override_priority))
				return 0;
		} else if (p->type == PAT_ADVERTISED) {
			advp = container_of(p, struct pa_advp, in_core);
			if(advp->priority >= override_priority)
				return 0;
		}
	}
	return 1;
}

#ifdef PA_HIERARCHICAL
/***************************
 * Hierarchical Assignment *
 ***************************/

static struct pa_dp *pa_ha_dp_get(struct pa_core *core, struct pa_ldp *ldp)
{
	struct pa_dp *dp = NULL;
	pa_for_each_dp(core, dp) {
		if(dp->ha_ldp == ldp) {
			return dp;
		}
	}
	return NULL;
}

static void pa_ha_dp_del(struct pa_core *core, struct pa_ldp *ldp)
{
	struct pa_dp *dp = pa_ha_dp_get(core, ldp);
	if(!dp) {
		PA_WARNING("The higher-level prefix is not associated with a lower-level dp.");
	} else {
		pa_dp_del(dp);
		free(dp);
	}
}

static void pa_ha_dp_add(struct pa_core *core, struct pa_ldp *ldp)
{
	struct pa_dp *dp = pa_ha_dp_get(core, ldp);
	if(dp) {
		PA_WARNING("The higher-level ldp is already associated with a lower-level dp.");
		return;
	}
	if(!(dp = malloc(sizeof(struct pa_dp)))) {
		PA_WARNING("Cannot create lower-level dp for "PA_LDP_P, PA_LDP_PA(ldp));
		return;
	}

	/* init dp */
	pa_prefix_cpy(&ldp->prefix, ldp->plen, &dp->prefix, dp->plen);
	dp->ha_ldp = ldp;
#ifdef PA_DP_TYPE
	dp->type = PA_DP_TYPE_NONE;
#endif

	/* Add the dp to the child PA structure */
	pa_dp_add(core, dp);
}

static void pa_ha_assigned_cb(struct pa_user *user, struct pa_ldp *ldp)
{
	struct pa_core *core = container_of(user, struct pa_core, ha_user);
	if(ldp->assigned) {
		pa_ha_dp_add(core, ldp);
	} else {
		pa_ha_dp_del(core, ldp);
	}
}

static void pa_ha_applied_cb(struct pa_user *user, struct pa_ldp *ldp)
{
	struct pa_core *core = container_of(user, struct pa_core, ha_user);
	if(core->ha_user.assigned) {
		//Fast mode
		struct pa_dp *dp = pa_ha_dp_get(core, ldp);
		if(!dp)
			return;

		if(ldp->applied) {
			pa_for_each_ldp_in_dp(dp, ldp) {
				if(!ldp->applied && ldp->ha_apply_pending)
					pa_ldp_apply(ldp);
			}
		}
		//A prefix is only unapplied when unassigned
	} else {
		PA_DEBUG("Hierarchical Assignment - Apply callback in safe mode");
		//Safe mode
		if(ldp->applied) {
			pa_ha_dp_add(core, ldp);
		} else {
			pa_ha_dp_del(core, ldp);
		}
	}
}

void pa_ha_attach(struct pa_core *child, struct pa_core *parent, uint8_t fast_assignment)
{
	child->ha_user.applied = pa_ha_applied_cb;
	child->ha_user.assigned = fast_assignment?pa_ha_assigned_cb:NULL;
	child->ha_user.published = NULL;
	child->ha_parent = parent;

	/* Attach to parent */
	pa_user_register(parent, &child->ha_user);

	/* Update dps from parent's applied ldps */
	struct pa_dp *dp;
	struct pa_ldp *ldp;
	pa_for_each_dp(parent, dp)
		pa_for_each_ldp_in_dp(dp, ldp) {
			if(fast_assignment && ldp->assigned)
				pa_ha_assigned_cb(&child->ha_user, ldp);
			if(ldp->applied)
				pa_ha_applied_cb(&child->ha_user, ldp);
	}
}

void pa_ha_detach(struct pa_core *child)
{
	/* Remove all dps that are from the parent. */
	struct pa_dp *dp, *dp2;
	pa_for_each_dp_safe(child, dp, dp2) {
		if(dp->ha_ldp) {
			pa_dp_del(dp);
			free(dp);
		}
	}

	/* Detach from parent */
	child->ha_parent = NULL;
	pa_user_unregister(&child->ha_user);
}

#endif
