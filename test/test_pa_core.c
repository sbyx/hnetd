/* Basic tests. */

#include <stdio.h>
#include <stdlib.h>

#include "fake_uloop.h"

#define FR_MASK_RANDOM
#include "fake_random.h"

/* Make calloc fail */
static bool calloc_fail = false;
static void *f_calloc (size_t __nmemb, size_t __size) {
	if(calloc_fail)
		return NULL;
	return calloc(__nmemb, __size);
}

#define calloc f_calloc

/* Make btrie_add fail */
#include "btrie.h"
static bool btrie_fail = false;
static int f_btrie_add(struct btrie *root, struct btrie_element *new, const btrie_key_t *key, btrie_plen_t len) {
	if(btrie_fail)
		return -1;
	return btrie_add(root, new, key, len);
}

#define btrie_add f_btrie_add



#include <stdio.h>
#define TEST_DEBUG(format, ...) printf("TEST Debug   : "format"\n", ##__VA_ARGS__)

int log_level = 8;

#include "pa_rules.h"
#include "pa_filters.h"

#include "pa_core.c"

#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

static struct pa_dp
	d1 = {.plen = 56, .prefix = {{{0x20, 0x01, 0, 0, 0, 0, 0x01}}}},
	d2 = {.plen = 56, .prefix = {{{0x20, 0x01, 0, 0, 0, 0, 0x02}}}};

static struct pa_link
		l1 = {.name = "L1"},
		l2 = {.name = "L2"};

static uint32_t id0 = 0,
		id1 = 0x111111,
		id2 = 0x222222,
		id3 = 0x333333;

static struct pa_advp
		advp1_01 = {.plen = 64, .prefix = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x01}}}},
		advp1_02 = {.plen = 64, .prefix = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x11}}}},
		advp2_01 = {.plen = 64, .prefix = {{{0x20, 0x01, 0, 0, 0, 0, 0x02, 0x01}}}};

struct test_user {
	struct pa_user user;
	struct pa_ldp *assigned_ldp, *published_ldp, *applied_ldp;
};

#define check_user(tuser, assigned, published, applied) \
	sput_fail_unless((tuser)->assigned_ldp == assigned, "Correct user assigned"); \
	sput_fail_unless((tuser)->published_ldp == published, "Correct user published"); \
	sput_fail_unless((tuser)->applied_ldp == applied, "Correct user applied"); \
	(tuser)->assigned_ldp = (tuser)->published_ldp = (tuser)->applied_ldp = NULL;

#define check_ldp_flags(ldp, ass, pub, app, adopt) \
		sput_fail_unless((ldp)->assigned == ass, "Correct ldp assigned"); \
		sput_fail_unless((ldp)->published == pub, "Correct ldp published"); \
		sput_fail_unless((ldp)->applied == app, "Correct ldp applied"); \
		sput_fail_unless((ldp)->adopting == adopt, "Correct ldp adopting");

#define check_ldp_prefix(ldp, p, pl) \
		sput_fail_unless(pa_prefix_equals(&(ldp)->prefix, (ldp)->plen, p, pl), "Correct prefix");

#define check_ldp_publish(ldp, rul, rule_prio, prio) \
		sput_fail_unless((ldp)->rule == rul, "Correct ldp rule"); \
		sput_fail_unless((ldp)->rule_priority == rule_prio, "Correct ldp rule_priority"); \
		sput_fail_unless((ldp)->priority == prio, "Correct ldp priority");

#define check_ldp_routine(ldp, b, best) \
		sput_fail_unless((ldp)->backoff == b, "Correct ldp backoff flag"); \
		sput_fail_unless((ldp)->best_assignment == best, "Correct ldp best_assignment");

/* Custom user */

static void user_assigned(struct pa_user *user, struct pa_ldp *ldp) {
	TEST_DEBUG("Called user_assigned");
	struct test_user *tuser = container_of(user, struct test_user, user);
	tuser->assigned_ldp = ldp;
}

static void user_published(struct pa_user *user, struct pa_ldp *ldp) {
	TEST_DEBUG("Called user_published");
	struct test_user *tuser = container_of(user, struct test_user, user);
	tuser->published_ldp = ldp;
}

static void user_applied(struct pa_user *user, struct pa_ldp *ldp) {
	TEST_DEBUG("Called user_applied");
	struct test_user *tuser = container_of(user, struct test_user, user);
	tuser->applied_ldp = ldp;
}

static struct test_user tuser = {
		.user = {.assigned = user_assigned,
		.published = user_published,
		.applied = user_applied }
};

/* Custom rules */

struct test_rule {
	struct pa_rule rule;
	struct pa_ldp ldp;
	int filter_ctr;
	int prio_ctr;
	int match_ctr;
	void *filter_p;
	int filter_accept;
	pa_rule_priority best_match_priority;
	pa_rule_priority priority; //Returned by get_prio
	enum pa_rule_target target;
	struct pa_rule_arg arg;    //arg returned by match
};

static int test_rule_filter_accept(struct pa_rule *rule,
		__attribute__ ((unused)) struct pa_ldp *ldp, void *p)
{
	struct test_rule *t = container_of(rule, struct test_rule, rule);
	t->filter_p = p;
	t->filter_ctr++;
	TEST_DEBUG("Called filter_accept %d", t->filter_accept);
	return t->filter_accept;
}

static pa_rule_priority test_rule_prio(struct pa_rule *rule, struct pa_ldp *ldp)
{
	struct test_rule *t = container_of(rule, struct test_rule, rule);
	t->ldp = *ldp;
	t->prio_ctr++;
	TEST_DEBUG("Called get_max_prio %d", t->priority);
	return t->priority;
}

static enum pa_rule_target test_rule_match(struct pa_rule *rule, struct pa_ldp *ldp,
		pa_rule_priority best_match_priority,
		struct pa_rule_arg *pa_arg)
{
	struct test_rule *t = container_of(rule, struct test_rule, rule);
	t->ldp = *ldp;
	t->best_match_priority = best_match_priority;
	*pa_arg = t->arg;
	t->match_ctr++;
	TEST_DEBUG("Called match %d", pa_arg->rule_priority);
	return t->target;
}

#define CUSTOM_RULE_INIT {.filter_accept = test_rule_filter_accept, .get_max_priority = test_rule_prio, .match = test_rule_match}

#define cr_check_ctr(cr, filter, prio, match) do{\
		sput_fail_unless((cr)->filter_ctr == filter, "Correct filter number of calls"); \
		(cr)->filter_ctr = 0; \
		sput_fail_unless((cr)->prio_ctr == prio, "Correct get_max_priority number of calls"); \
		(cr)->prio_ctr = 0;\
		sput_fail_unless((cr)->match_ctr == match, "Correct match number of calls"); \
		(cr)->match_ctr = 0; } while(0)


static pa_prefix sr_prefix;
static pa_plen sr_plen;
static int static_rule_get_prefix(__unused struct pa_rule_static *srule,
		__unused struct pa_ldp *ldp, pa_prefix *prefix, pa_plen *plen)
{
	pa_prefix_cpy(&sr_prefix, sr_plen, prefix, *plen);
	return 0;
}

static pa_prefix sr_prefix2;
static pa_plen sr_plen2;
static int static_rule_get_prefix2(__unused struct pa_rule_static *srule,
		__unused struct pa_ldp *ldp, pa_prefix *prefix, pa_plen *plen)
{
	pa_prefix_cpy(&sr_prefix2, sr_plen2, prefix, *plen);
	return 0;
}

void pa_core_override() {
	fu_init();
	fr_mask_random = 0;
	struct pa_core core;
	struct pa_rule_static s1, s2;
	struct pa_ldp *ldp;
	struct pa_filter_ldp f1, f2;

	pa_rule_static_init(&s1);
	s1.rule.name = "static rule 1";
	s1.override_priority = 0;
	s1.override_rule_priority = 0;
	s1.priority = 3;
	s1.rule_priority = 3;
	s1.get_prefix = static_rule_get_prefix;
	pa_prefix_cpy(&advp1_01.prefix, 80, &sr_prefix, sr_plen);
	pa_filter_ldp_init(&f1, &l1, NULL);
	pa_rule_set_filter(&s1.rule, &f1.filter);

	core.node_id[0] = id1;
	pa_core_init(&core);
	pa_rule_add(&core, &s1.rule);

	pa_link_add(&core, &l1);
	pa_dp_add(&core, &d1);
	ldp = list_entry(d1.ldps.next, struct pa_ldp, in_dp);

	fu_loop(3); //Routine, Backoff and Apply
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);


	advp1_01.priority = 3;
	advp1_01.link = NULL;
	advp1_01.node_id[0] = id2; //id is higher
	pa_advp_add(&core, &advp1_01);

	fu_loop(1); //Unassign ldp
	check_ldp_flags(ldp, 0, 0, 0, 0);

	pa_rule_del(&core, &s1.rule);
	s1.override_priority = 3;
	pa_rule_add(&core, &s1.rule);
	fu_loop(1); //Stille nothing assigned
	check_ldp_flags(ldp, 0, 0, 0, 0);

	pa_rule_del(&core, &s1.rule);
	s1.override_priority = 4;
	s1.priority = 7;
	pa_rule_add(&core, &s1.rule);
	fu_loop(3); //Override prefix
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);

	advp1_01.priority = 6; //Lower prio
	pa_advp_update(&core, &advp1_01);
	fu_loop(1); //No change
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);

	pa_advp_del(&core, &advp1_01);

	//Different prefix assigned on the interface
	advp1_02.priority = 6;
	advp1_02.link = &l1;
	advp1_02.node_id[0] = id2; //id is higher
	pa_advp_add(&core, &advp1_02);

	fu_loop(1); //No change
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);

	advp1_02.priority = 7;
	pa_advp_update(&core, &advp1_02);
	fu_loop(2); //Overriden prefix
	check_ldp_flags(ldp, 1, 0, 1, 0);
	check_ldp_prefix(ldp, &advp1_02.prefix, 64);

	pa_rule_del(&core, &s1.rule);
	s1.override_priority = 7; //Not big enough
	s1.priority = 8;
	pa_rule_add(&core, &s1.rule);
	fu_loop(1); //Nothing happens
	check_ldp_flags(ldp, 1, 0, 1, 0);
	check_ldp_prefix(ldp, &advp1_02.prefix, 64);

	pa_rule_del(&core, &s1.rule);
	s1.override_priority = 8;
	s1.priority = 8;
	pa_rule_add(&core, &s1.rule);
	fu_loop(2); //Override onlink prefix
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);

	pa_rule_del(&core, &s1.rule);
	pa_advp_del(&core, &advp1_02);
	fu_loop(1); //Eraze everything
	check_ldp_flags(ldp, 0, 0, 0, 0);

	s1.safety = 1; //Safety on to start with
	s1.priority = 6;
	s1.override_priority = 3;
	s1.rule_priority = 2;
	s1.override_rule_priority = 2;

	pa_rule_static_init(&s2);
	s2.rule.name = "static rule 1";
	s2.override_priority = 0;
	s2.override_rule_priority = 0;
	s2.priority = 2;
	s2.rule_priority = 5;
	s2.get_prefix = static_rule_get_prefix2;
	pa_prefix_cpy(&advp1_01.prefix, 75, &sr_prefix2, sr_plen2); //Colliding prefix
	pa_filter_ldp_init(&f2, &l2, NULL);
	pa_rule_set_filter(&s2.rule, &f2.filter);

	pa_link_add(&core, &l2);
	struct pa_ldp *ldp2;
	ldp2 = list_entry(l2.ldps.next, struct pa_ldp, in_link);

	pa_rule_add(&core, &s1.rule);
	pa_rule_add(&core, &s2.rule);

	fu_loop(5); //s2 wins
	check_ldp_flags(ldp2, 1, 1, 1, 0);
	check_ldp_prefix(ldp2, &advp1_01.prefix, 75);
	check_ldp_flags(ldp, 0, 0, 0, 0);

	pa_rule_del(&core, &s1.rule);
	s1.rule_priority = 8;
	s1.override_rule_priority = 8;
	s1.safety = 1; //Safety on, s1 should not win
	pa_rule_add(&core, &s1.rule);

	fu_loop(1); //s1 can't win because of safety
	check_ldp_flags(ldp2, 1, 1, 1, 0);
	check_ldp_prefix(ldp2, &advp1_01.prefix, 75);
	check_ldp_flags(ldp, 0, 0, 0, 0);

	pa_rule_del(&core, &s1.rule);
	s1.safety = 0; //Safety's off, s1 should win
	pa_rule_add(&core, &s1.rule);

	fu_loop(6); //s1 wins
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, 80);
	check_ldp_flags(ldp2, 0, 0, 0, 0);

	pa_rule_del(&core, &s1.rule);
	pa_rule_del(&core, &s2.rule);

	fu_loop(2);

	check_ldp_flags(ldp2, 0, 0, 0, 0);
	check_ldp_flags(ldp, 0, 0, 0, 0);


	pa_dp_del(&d1);
	pa_link_del(&l1);
	pa_link_del(&l2);
}

void pa_core_hierarchical() {
	fu_init();

	struct pa_core core, low_core;
	struct pa_ldp *ldp, *low_ldp;
	struct pa_link link, low_link;

	struct test_rule rule = {.rule = CUSTOM_RULE_INIT, .filter_accept = 1},
				low_rule = {.rule = CUSTOM_RULE_INIT, .filter_accept = 1};

	pa_prefix_cpy(&advp1_01.prefix, 64, &rule.arg.prefix, rule.arg.plen);
	rule.arg.priority = 1;
	rule.arg.rule_priority = 1;
	rule.priority = 1;
	rule.target = PA_RULE_PUBLISH;

	pa_prefix_cpy(&advp1_01.prefix, 128, &low_rule.arg.prefix, low_rule.arg.plen);
	low_rule.arg.priority = 1;
	low_rule.arg.rule_priority = 1;
	low_rule.priority = 1;
	low_rule.target = PA_RULE_PUBLISH;

	pa_core_init(&core);
	pa_core_init(&low_core);

	sput_fail_unless(list_empty(&core.users), "No user");
	pa_ha_attach(&low_core, &core, 0);
	sput_fail_if(list_empty(&core.users), "User subscribed");
	sput_fail_unless(core.users.next == &low_core.ha_user.le, "Correct user");

	pa_rule_add(&core, &rule.rule);
	pa_rule_add(&low_core, &low_rule.rule);

	link.name = "parent";
	link.ha_parent = NULL;
	low_link.name = "child";
	low_link.ha_parent = &link;

	pa_link_add(&core, &link);
	pa_link_add(&low_core, &low_link);

	//Adding to low first. It should assign the prefix from low_rule.
	pa_dp_add(&low_core, &d1);

	fu_loop(3); //Publish and apply
	low_ldp = list_entry(d1.ldps.next, struct pa_ldp, in_dp);
	check_ldp_flags(low_ldp, 1, 1, 1, 0);
	sput_fail_if(low_ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	//Remove from low
	pa_dp_del(&d1);
	fu_loop(1);

	//Add to high
	pa_dp_add(&core, &d1);
	fu_loop(1); //Publish prefix but no apply
	ldp = list_entry(d1.ldps.next, struct pa_ldp, in_dp);
	check_ldp_flags(low_ldp, 1, 1, 0, 0);
	sput_fail_if(ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 64);
	sput_fail_unless(list_empty(&low_core.dps), "No DP on low core");

	fu_loop(1); //Apply prefix
	struct pa_dp *low_dp;
	sput_fail_if(list_empty(&low_core.dps), "One dp");
	low_dp = container_of(low_core.dps.next, struct pa_dp, le);
	sput_fail_if(pa_prefix_cmp(&advp1_01.prefix, 64, &low_dp->prefix, low_dp->plen), "Correct prefix");
	sput_fail_unless(low_dp->ha_ldp == ldp, "Parent ldp is set");

	fu_loop(2); //Publish and apply in low core
	low_ldp = list_entry(low_link.ldps.next, struct pa_ldp, in_link);
	check_ldp_flags(low_ldp, 1, 1, 1, 0);
	sput_fail_if(low_ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	pa_dp_del(&d1); //Remove parent dp
	sput_fail_unless(list_empty(&core.dps), "No parent dp");
	sput_fail_unless(list_empty(&low_core.dps), "No lower dp");

	pa_ha_detach(&low_core);
	low_core.flooding_delay = 1000; //Fast flooding delay compare to core
	sput_fail_unless(list_empty(&core.users), "No user");
	pa_ha_attach(&low_core, &core, 1); //Fast mode this time
	sput_fail_if(list_empty(&core.users), "User subscribed");
	sput_fail_unless(core.users.next == &low_core.ha_user.le, "Correct user");

	pa_dp_add(&core, &d1); //Add dp back
	fu_loop(1); //Publish prefix but no apply
	ldp = list_entry(d1.ldps.next, struct pa_ldp, in_dp);

	sput_fail_if(list_empty(&low_core.dps), "One dp");
	low_dp = container_of(low_core.dps.next, struct pa_dp, le);
	sput_fail_if(pa_prefix_cmp(&advp1_01.prefix, 64, &low_dp->prefix, low_dp->plen), "Correct prefix");
	sput_fail_unless(low_dp->ha_ldp == ldp, "Parent ldp is set");

	fu_loop(1); //Publish
	low_ldp = list_entry(low_link.ldps.next, struct pa_ldp, in_link);
	check_ldp_flags(low_ldp, 1, 1, 0, 0);
	sput_fail_if(low_ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	fu_loop(1); //Apply. But it should block, waiting for higher core to apply.
	check_ldp_flags(low_ldp, 1, 1, 0, 0);
	sput_fail_unless(low_ldp->ha_apply_pending, "Pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	fu_loop(1); //Apply higher level
	check_ldp_flags(ldp, 1, 1, 1, 0);
	check_ldp_flags(low_ldp, 1, 1, 1, 0);
	sput_fail_if(low_ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	pa_ha_detach(&low_core);
	sput_fail_unless(list_empty(&core.users), "No user");
	sput_fail_unless(list_empty(&low_core.dps), "No dp");

	pa_ha_attach(&low_core, &core, 1); //Fast mode
	fu_loop(2);
	low_ldp = list_entry(low_link.ldps.next, struct pa_ldp, in_link);
	check_ldp_flags(low_ldp, 1, 1, 1, 0);
	sput_fail_if(low_ldp->ha_apply_pending, "Not pending for HA");
	check_ldp_prefix(low_ldp, &advp1_01.prefix, 128);

	pa_dp_del(&d1);
	pa_link_del(&link);
	pa_link_del(&low_link);
}

void pa_core_rule() {
	struct pa_core core;
	struct pa_ldp *ldp, *ldp2;
	struct test_rule rule1 = {.rule = CUSTOM_RULE_INIT}
	, rule2  = {.rule = CUSTOM_RULE_INIT};

	sput_fail_if(fu_next(), "No pending timeout");

	pa_core_init(&core);
	pa_link_add(&core, &l1);
	pa_dp_add(&core, &d1);

	ldp = NULL;
	pa_for_each_ldp_in_dp(&d1, ldp2){
		ldp = ldp2; //Get the unique ldp
	}

	fu_loop(1);
	pa_user_register(&core, &tuser.user);
	sput_fail_if(fu_next(), "No scheduled timer.");

	pa_rule_add(&core, &rule1.rule);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY, "Correct delay");

	set_time(get_time() + 1);
	pa_rule_add(&core, &rule2.rule);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY - 1, "Correct delay");

	rule1.filter_accept = 0;
	rule2.filter_accept = 0;
	rule1.rule.filter_private = &rule1;
	rule2.rule.filter_private = &rule2;

	fu_loop(1);

	//One call to each filter
	cr_check_ctr(&rule1, 1, 0, 0);
	cr_check_ctr(&rule2, 1, 0, 0);
	sput_fail_unless(rule1.filter_p == &rule1, "Correct private pointer");
	sput_fail_unless(rule2.filter_p == &rule2, "Correct private pointer");
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);

	pa_rule_del(&core, &rule1.rule);
	rule1.filter_accept = 1;
	rule1.priority = 0;
	pa_rule_add(&core, &rule1.rule);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 0); //prio called once
	cr_check_ctr(&rule2, 1, 0, 0);
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);

	pa_rule_del(&core, &rule2.rule);
	rule2.filter_accept = 1;
	rule2.priority = 2;
	rule2.target = PA_RULE_NO_MATCH;
	pa_rule_add(&core, &rule2.rule);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 0);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);

	pa_rule_del(&core, &rule1.rule);
	rule1.priority = 3; //Higher priority than rule2
	rule1.target = PA_RULE_BACKOFF; //Will trigger backoff timer
	rule1.arg.rule_priority = 1; //Smaller than promissed, match2 will be called
	pa_rule_add(&core, &rule1.rule);
	fr_random_push(1000); //Will wait PA_ADOPT_DELAY + pa_rand() % (PA_BACKOFF_DELAY - PA_ADOPT_DELAY)
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 1); //Rule1 matches and has a higher priority, match2 is not called
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);
	sput_fail_unless(ldp->backoff_to.pending, "Backoff timer pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (PA_ADOPT_DELAY_DEFAULT + 1000 % (PA_BACKOFF_DELAY_DEFAULT - PA_ADOPT_DELAY_DEFAULT)), "Correct delay");
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);

	rule1.target = PA_RULE_PUBLISH; //This time, we publish
	rule1.arg.plen = 63;
	rule1.arg.prefix = advp1_01.prefix;
	rule1.arg.rule_priority = 3; //Big enough so that rule2 is not called
	rule1.arg.priority = 5;
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 0);
	check_ldp_flags(ldp, true, true, false, false);
	check_ldp_publish(ldp, &rule1.rule, 3, 5);
	check_ldp_prefix(ldp, &rule1.arg.prefix, rule1.arg.plen);
	check_ldp_routine(&rule1.ldp, 1, NULL);
	check_ldp_routine(&rule2.ldp, 1, NULL);
	check_user(&tuser, ldp, ldp, NULL);


	//Apply
	fu_loop(1);
	check_ldp_flags(ldp, true, true, true, false);
	check_user(&tuser, NULL, NULL, ldp);

	//rule2 will override the assignment with a different one
	pa_rule_del(&core, &rule2.rule);
	rule2.priority = 4;
	rule2.target = PA_RULE_PUBLISH; //This time, we publish
	rule2.arg.plen = 63;
	rule2.arg.prefix = advp1_02.prefix;
	rule2.arg.rule_priority = 4; //Bigger than rule 1
	rule2.arg.priority = 3;
	pa_rule_add(&core, &rule2.rule);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 0);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_user(&tuser, ldp, ldp, ldp); //Apply is called for unapply
	check_ldp_flags(ldp, true, true, false, false);
	check_ldp_publish(ldp, &rule2.rule, 4, 3);
	check_ldp_prefix(ldp, &rule2.arg.prefix, rule2.arg.plen);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);

	//Apply
	fu_loop(1);
	check_user(&tuser, NULL, NULL, ldp);

	//Add a colliding assignment, with a smaller priority
	advp1_02.link = NULL;
	advp1_02.priority = 2;
	pa_advp_add(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	cr_check_ctr(&rule1, 1, 1, 0);
	cr_check_ctr(&rule2, 1, 1, 0); //rule2 not called because existing assignment has equaling priority
	check_ldp_flags(ldp, true, true, true, false);
	check_ldp_publish(ldp, &rule2.rule, 4, 3);
	check_ldp_prefix(ldp, &rule2.arg.prefix, rule2.arg.plen);

	//The prefix is now on-link -- Same thing
	advp1_02.link = &l1;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	cr_check_ctr(&rule1, 1, 1, 0);
	cr_check_ctr(&rule2, 1, 1, 0); //rule2 not called because existing assignment has equaling priority
	check_ldp_flags(ldp, true, true, true, false);
	check_ldp_publish(ldp, &rule2.rule, 4, 3);
	check_ldp_prefix(ldp, &rule2.arg.prefix, rule2.arg.plen);

	//The prefix will have an higher priority, on a different link
	advp1_02.link = NULL;
	advp1_02.priority = 4;
	rule2.target = PA_RULE_NO_MATCH;
	rule1.target = PA_RULE_NO_MATCH;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, ldp, ldp, ldp);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_routine(&rule2.ldp, 0, NULL);
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);

	//The prefix moves on-link and is accepted
	advp1_02.link = &l1;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_flags(ldp, true, false, false, false);
	check_ldp_prefix(ldp, &advp1_02.prefix, advp1_02.plen);

	//Testing adoption
	pa_advp_del(&core, &advp1_02);
	rule1.target = PA_RULE_ADOPT;
	rule1.priority = 3;
	rule1.arg.plen = 120; //should not be used
	rule1.arg.priority = 10;
	rule1.arg.rule_priority = 3;
	rule2.priority = 2;
	fr_random_push(10);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 0);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_ldp_flags(ldp, true, false, false, true);
	check_ldp_publish(ldp, &rule1.rule, 3, 10);
	check_ldp_prefix(ldp, &advp1_02.prefix, advp1_02.plen);
	sput_fail_unless(ldp->backoff_to.pending, "Backoff timer pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == 10 % PA_ADOPT_DELAY_DEFAULT, "Correct delay");

	//Adopt
	fu_loop(1);
	check_user(&tuser, NULL, ldp, NULL);
	check_ldp_flags(ldp, true, true, false, false);
	check_ldp_prefix(ldp, &advp1_02.prefix, advp1_02.plen);
	check_ldp_publish(ldp, &rule1.rule, 3, 10);
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay), "Correct apply delay");
	sput_fail_unless(fu_next() == &ldp->backoff_to, "Correct timeout");

	//Apply
	fu_loop(1);

	//Testing destruction !
	pa_rule_del(&core, &rule2.rule);
	rule2.target = PA_RULE_DESTROY;
	rule2.priority = 4; //Must be higher than 3 to be accepted
	pa_rule_add(&core, &rule2.rule);
	fu_loop(1);
	check_user(&tuser, ldp, ldp, ldp);
	cr_check_ctr(&rule1, 1, 1, 0);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_routine(&rule2.ldp, 0, NULL);
	check_ldp_flags(ldp, false, false, false, false);
	check_ldp_publish(ldp, NULL, 0, 0);

	//Test adopt case when already applied
	rule2.target = PA_RULE_NO_MATCH;
	rule1.target = PA_RULE_NO_MATCH;
	pa_advp_add(&core, &advp1_01);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_routine(&rule2.ldp, 0, &advp1_01);
	check_ldp_routine(&rule1.ldp, 0, &advp1_01);
	check_ldp_flags(ldp, true, false, false, false);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);


	//Now playing with flooding delays
	set_time(get_time()+10); //Waiting 10ms
	pa_core_set_flooding_delay(&core, 100);
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay), "Correct apply delay");

	set_time(get_time()+10); //Waiting 10 more ms
	pa_core_set_flooding_delay(&core, PA_DEFAULT_FLOODING_DELAY);
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay) - 10, "Correct apply delay");

	//Apply
	fu_loop(1);
	check_user(&tuser, NULL, NULL, ldp);
	check_ldp_flags(ldp, true, false, true, false);

	//Adopt
	rule1.target = PA_RULE_ADOPT;
	rule1.priority = 3;
	rule1.arg.priority = 4;
	rule1.arg.rule_priority = 3;
	pa_advp_del(&core, &advp1_01);
	fr_random_push(10);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_routine(&rule2.ldp, 0, NULL);
	check_ldp_routine(&rule1.ldp, 0, NULL);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, true, false, true, true);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);
	check_ldp_publish(ldp, &rule1.rule, 3, 4);
	sput_fail_unless(ldp->backoff_to.pending, "Backoff timer pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == 10 % PA_ADOPT_DELAY_DEFAULT, "Correct delay");
	sput_fail_unless(fu_next() == &ldp->backoff_to, "Correct timeout");

	//Adopt
	fu_loop(1);
	check_user(&tuser, NULL, ldp, NULL);
	check_ldp_flags(ldp, true, true, true, false);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);
	check_ldp_publish(ldp, &rule1.rule, 3, 4);
	sput_fail_if(fu_next(), "No Apply timer.");

	//Override with the same prefix
	pa_rule_del(&core, &rule2.rule);
	rule2.target = PA_RULE_PUBLISH;
	rule2.priority = 4;
	rule2.arg.priority = 2;
	rule2.arg.rule_priority = 4;
	rule2.arg.prefix = advp1_01.prefix;
	rule2.arg.plen = advp1_01.plen;
	pa_rule_add(&core, &rule2.rule);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 0); //Too small priority to be called
	cr_check_ctr(&rule2, 1, 1, 1);
	check_ldp_routine(&rule2.ldp, 0, NULL);
	check_user(&tuser, NULL, ldp, NULL);
	check_ldp_flags(ldp, true, true, true, false);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);
	check_ldp_publish(ldp, &rule2.rule, 4, 2);

	//Destroy the rule that published the prefix
	rule1.target = PA_RULE_NO_MATCH;
	pa_rule_del(&core, &rule2.rule);
	fu_loop(1);
	cr_check_ctr(&rule1, 1, 1, 1);
	cr_check_ctr(&rule2, 0, 0, 0);
	check_ldp_routine(&rule2.ldp, 0, NULL);
	check_user(&tuser, ldp, ldp, ldp);
	check_ldp_flags(ldp, false, false, false, false);

	//Finish
	pa_link_del(&l1);
	pa_dp_del(&d1);
	sput_fail_if(fu_next(), "No scheduled timer.");
}

void pa_core_norule() {
	struct pa_core core;
	struct pa_ldp *ldp, *ldp2;
	struct pa_advp *ai1, *ai2;

	//Nothing pending
	sput_fail_if(fu_next(), "No pending timeout");

	pa_core_init(&core);

	pa_link_add(&core, &l1);
	pa_dp_add(&core, &d1);

	pa_for_each_ldp_in_dp(&d1, ldp2){
		ldp = ldp2; //Get the unique ldp
	}

	//Test scheduling
	sput_fail_unless(ldp, "ldp present");
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY, "Correct delay");
	sput_fail_unless(fu_next() == &ldp->routine_to, "Correct timeout");

	set_time(get_time() + 1);
	pa_core_set_node_id(&core, &id1); //Reschedule
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY - 1, "Correct delay");

	//Adding user
	pa_user_register(&core, &tuser.user);

	//Execute routine with nothing
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, false, false, false, false);

	//No advp for now
	ai2 = NULL;
	pa_for_each_advp(&core, ai1, &advp2_01.prefix, advp2_01.plen)
		ai2 = ai1;
	sput_fail_if(ai2, "No advp for now");

	//Add an adv prefix outside the dp on a null link
	//Scheduling only happens when overlap with a dp
	advp2_01.link = NULL;
	advp2_01.priority = 2;
	pa_advp_add(&core, &advp2_01);
	pa_advp_update(&core, &advp2_01);
	sput_fail_if(ldp->routine_to.pending, "Not routine pending");
	sput_fail_if(fu_next(), "No pending timeout");

	//advp added
	ai2 = NULL;
	pa_for_each_advp(&core, ai1, &advp2_01.prefix, advp2_01.plen)
		ai2 = ai1;
	sput_fail_unless(ai2 == &advp2_01, "No advp for now");

	ai2 = NULL;
	pa_for_each_advp(&core, ai1, &advp1_01.prefix, advp1_01.plen)
		ai2 = ai1;
	sput_fail_if(ai2, "No advp with that prefix");

	//Add an adv prefix inside the dp on a null link
	advp1_01.link = NULL;
	advp1_01.priority = 2;
	pa_advp_add(&core, &advp1_01);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY, "Correct delay");
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, false, false, false, false);

	ai2 = NULL;
	pa_for_each_advp(&core, ai1, &advp1_01.prefix, advp1_01.plen)
		ai2 = ai1;
	sput_fail_unless(ai2 == &advp1_01, "No advp for now");

	//Set the adv prefix as onlink
	//Accept a prefix
	advp1_01.link = &l1;
	pa_advp_update(&core, &advp1_01);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY, "Correct delay");
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);

	//Apply running
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay), "Correct apply delay");
	sput_fail_unless(fu_next() == &ldp->backoff_to, "Correct timeout");

	//Remove adv2_01
	pa_advp_del(&core, &advp2_01);
	sput_fail_if(ldp->routine_to.pending, "Not routine pending");

	//Remove and add adv1_01 again
	pa_advp_del(&core, &advp1_01);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);

	set_time(get_time() + 1);
	pa_advp_add(&core, &advp1_01);
	sput_fail_unless(ldp->routine_to.pending, "Routine pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->routine_to) == PA_RUN_DELAY - 1, "Correct delay");
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);

	//Apply running
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay) - PA_RUN_DELAY, "Correct apply delay");
	sput_fail_unless(fu_next() == &ldp->backoff_to, "Correct timeout");

	//Remove and execute routine
	pa_advp_del(&core, &advp1_01);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 0, 0, 0, 0);

	//Apply canceled
	sput_fail_if(ldp->backoff_to.pending, "Apply to not pending");
	sput_fail_if(fu_next(), "Not timeout");

	//Add and execute routine
	pa_advp_add(&core, &advp1_01);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);

	//Now let's apply the prefix
	fu_loop(1);
	check_user(&tuser, NULL, NULL, ldp);
	check_ldp_flags(ldp, 1, 0, 1, 0);

	//Add another prefix on a different link
	advp1_02.link = NULL;
	advp1_02.priority = 10;
	pa_advp_add(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 1, 0);

	//Lower priority
	advp1_02.priority = 0;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 1, 0);

	//On the link
	advp1_02.link = &l1;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 1, 0);

	//With a higher priority
	advp1_02.priority = 3;
	pa_advp_update(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, ldp);
	check_ldp_flags(ldp, 1, 0, 0, 0);
	check_ldp_prefix(ldp, &advp1_02.prefix, advp1_02.plen);

	//Check apply timer
	sput_fail_unless(ldp->backoff_to.pending, "Apply timeout pending");
	sput_fail_unless(uloop_timeout_remaining(&ldp->backoff_to) == (int)(2 * core.flooding_delay), "Correct apply delay");

	//First one use a lower rid
	advp1_02.node_id[0] = id3;
	advp1_01.node_id[0] = id2; //Lower router id
	advp1_01.priority = 3; //Same prio
	pa_advp_update(&core, &advp1_01);
	fu_loop(1);
	check_user(&tuser, NULL, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);
	check_ldp_prefix(ldp, &advp1_02.prefix, advp1_02.plen);

	//Now use an higher router ID
	advp1_02.node_id[0] = id2;
	advp1_01.node_id[0] = id3; //Higher router id
	pa_advp_update(&core, &advp1_01);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);

	//Remove the link from core
	pa_link_del(&l1);
	sput_fail_if(ldp->routine_to.pending, "Not routine pending");
	sput_fail_if(fu_next(), "No pending timeout");
	check_user(&tuser, ldp, NULL, NULL);

	//Add link again
	pa_link_add(&core, &l1);
	pa_for_each_ldp_in_dp(&d1, ldp2){
		ldp = ldp2; //Get the unique ldp
	}
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 1, 0, 0, 0);
	check_ldp_prefix(ldp, &advp1_01.prefix, advp1_01.plen);

	//Remove both advertised prefixes
	pa_advp_del(&core, &advp1_01);
	pa_advp_del(&core, &advp1_02);
	fu_loop(1);
	check_user(&tuser, ldp, NULL, NULL);
	check_ldp_flags(ldp, 0, 0, 0, 0);

	pa_link_del(&l1);
	pa_dp_del(&d1);

	sput_fail_if(fu_next(), "No scheduled timer.");
}

void pa_core_data() {
	struct pa_core core;
	sput_fail_if(fu_next(), "No pending timeout");

	pa_core_init(&core);
	sput_fail_unless(core.flooding_delay == PA_DEFAULT_FLOODING_DELAY, "Default flooding delay");
	sput_fail_if(memcmp(core.node_id, &id0, PA_NODE_ID_LEN), "Default Node ID");

	pa_core_set_node_id(&core, &id1);
	pa_core_set_flooding_delay(&core, 20000);
	pa_core_set_flooding_delay(&core, 5000);
	pa_link_init(&l1, l1.name);
	pa_link_init(&l2, l2.name);
	pa_dp_init(&d1, &d1.prefix, d1.plen);
	pa_dp_init(&d2, &d2.prefix, d2.plen);
	sput_fail_if(pa_link_add(&core, &l1), "Add L1");
	sput_fail_if(pa_dp_add(&core, &d1), "Add DP1");
	sput_fail_if(pa_link_add(&core, &l2), "Add L2");
	sput_fail_if(pa_dp_add(&core, &d2), "Add DP2");
	pa_core_set_node_id(&core, &id2);
	pa_core_set_flooding_delay(&core, 10000);
	pa_core_set_flooding_delay(&core, 5000);

	pa_link_del(&l1);
	pa_dp_del(&d1);

	sput_fail_if(pa_link_add(&core, &l1), "Add L1");
	sput_fail_if(pa_dp_add(&core, &d1), "Add DP1");

	/* Test adding PPs */
	advp1_01.link = &l1;
	memcpy(advp1_01.node_id, &id1, PA_NODE_ID_LEN);

	advp2_01.link = &l2;
	memcpy(advp2_01.node_id, &id3, PA_NODE_ID_LEN);
	btrie_fail = true;
	sput_fail_unless(pa_advp_add(&core, &advp1_01), "Can't add advp1_01");
	btrie_fail = false;
	sput_fail_if(pa_advp_add(&core, &advp1_01), "Add advp1_01");
	btrie_fail = true;
	sput_fail_unless(pa_advp_add(&core, &advp2_01), "Can't add advp2_01");
	btrie_fail = false;
	sput_fail_if(pa_advp_add(&core, &advp2_01), "Add advp2_01");

	pa_advp_update(&core, &advp1_01);
	pa_advp_update(&core, &advp2_01);
	pa_advp_del(&core, &advp1_01);
	pa_advp_del(&core, &advp2_01);

	/* Adding rules */
	struct pa_rule r1,r2;
	r1.name = "Rule 1";
	r2.name = "Rule 2";
	pa_rule_add(&core, &r1);
	pa_rule_add(&core, &r2);
	pa_rule_del(&core, &r1);
	pa_rule_del(&core, &r2);

	/* Remove all */
	pa_dp_del(&d1);
	pa_link_del(&l1);
	pa_dp_del(&d2);
	pa_link_del(&l2);

	/* Test when calloc fails */
	calloc_fail = true;
	sput_fail_if(pa_link_add(&core, &l1), "Add L1");
	sput_fail_unless(pa_dp_add(&core, &d1), "Fail adding DP1");
	pa_link_del(&l1);

	sput_fail_if(pa_dp_add(&core, &d1), "Add DP1");
	sput_fail_unless(pa_link_add(&core, &l1), "Fail adding L1");
	pa_dp_del(&d1);
	calloc_fail = false;

	/* There should be nothing scheduled here */
	sput_fail_if(fu_next(), "No scheduled timer.");
}

int main() {
	fu_init();
	sput_start_testing();
	sput_enter_suite("Prefix assignment tests"); /* optional */
	sput_run_test(pa_core_data);
	sput_run_test(pa_core_norule);
	sput_run_test(pa_core_rule);
	sput_run_test(pa_core_hierarchical);
	sput_run_test(pa_core_override);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
