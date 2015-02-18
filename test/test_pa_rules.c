#include "sput.h"


#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#include <stdio.h>
#define TEST_DEBUG(format, ...) printf("TEST Debug   : "format"\n", ##__VA_ARGS__)

#include "pa_core.h"
int log_level = 8;

void test_core_init(struct pa_core *core, uint32_t node_id)
{
	btrie_init(&core->prefixes);
	core->node_id[0] = node_id;
}

void test_advp_add(struct pa_core *core, struct pa_advp *advp)
{
	advp->in_core.type = PAT_ADVERTISED;
	sput_fail_if(btrie_add(&core->prefixes, &advp->in_core.be, (btrie_key_t *)&advp->prefix, advp->plen), "Adding Advertised Prefix");
}

void test_advp_del(__unused struct pa_core *core, struct pa_advp *advp)
{
	btrie_remove(&advp->in_core.be);
}

struct in6_addr
	p1   = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x00}}},
	p101 = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x01}}},
	p102 = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x02}}},
	p10f = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x0f}}},
	p11  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x10}}},
	p111 = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x11}}},
	p12  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x20}}},
	p14  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x40}}},
	p15  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x50}}},
	p16  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x60}}},
	p17  = {{{0x20, 0x01, 0, 0, 0, 0, 0x01, 0x70}}};

#include "fake_random.h"

#include "pa_rules.c"

#define test_rule_get_max_prio(rule, ldp, value)\
		sput_fail_unless((rule)->get_max_priority(rule, ldp)== value , "Correct get_max_prio value")

#define test_rule_match(rule, ldp, best, arg, target)\
		sput_fail_unless((rule)->match(rule, ldp, best, arg) == target, "Correct target")

#define test_rule_prio(arg, prio)\
	sput_fail_unless((arg)->rule_priority == prio, "Correct rule_priority in arg")

#define test_rule_prefix(arg, p, pl, prio)\
	sput_fail_if(pa_prefix_cmp(p, pl, &(arg)->prefix, (arg)->plen), "Correct prefix");
	//sput_fail_unless(prio == (arg)->priority, "Correct advertise priority");


void pa_rules_random()
{
	struct pa_core core;
	struct pa_dp dp = {.prefix = p1, .plen = 4};
	struct pa_link link = {.name = "L1"};
	struct pa_advp advp = {.link = &link, .prefix = p1, .plen = 56};
	struct pa_ldp ldp = {.core = &core, .dp = &dp, .link = &link, .prefix = p1, .plen = 2};
	struct pa_rule_arg arg;

	test_core_init(&core, 5);

	struct pa_rule_random random;
	pa_rule_random_init(&random);
	random.desired_plen_cb = NULL;
	random.desired_plen = 12;
	random.accept_proposed_cb = NULL;
	random.rule_priority = 3;
	random.priority = 4;
	random.pseudo_random_seed = (uint8_t *)"SEED";
	random.pseudo_random_seedlen = 4;
	random.pseudo_random_tentatives = 2;
	random.random_set_size = 4;

	ldp.best_assignment = &advp;
	ldp.assigned = 1;
	ldp.applied = 1;
	test_rule_get_max_prio(&random.rule, &ldp, 0);

	ldp.best_assignment = NULL;
	ldp.published = 1;
	test_rule_get_max_prio(&random.rule, &ldp, 0);

	ldp.published = 0;
	test_rule_get_max_prio(&random.rule, &ldp, 3);

	ldp.backoff = 0;
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_BACKOFF);
	test_rule_prio(&arg, 3);

	//Test pseudo-random
	ldp.backoff = 1;
	fr_mask_md5 = true;
	fr_mask_random = true;

	random.pseudo_random_tentatives = 2;
	random.random_set_size = 2; //two best only

	dp.prefix = p1;
	dp.plen = 56;
	random.desired_plen = 60;

	fr_md5_push(&p1);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p1, 60, 4);

	fr_md5_push(&p12); //Outside the set
	fr_md5_push(&p11); //In the set
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p11, 60, 4);

	//Different plen
	random.desired_plen = 64;
	fr_md5_push(&p102);
	fr_md5_push(&p101);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p101, 64, 4);

	random.desired_plen = 60;
	advp.prefix = p1;
	advp.plen = 56;
	test_advp_add(&core, &advp);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_NO_MATCH);

	test_advp_del(&core, &advp);
	advp.prefix = p14;
	advp.plen = 60;
	test_advp_add(&core, &advp);
	random.pseudo_random_tentatives = 6;
	fr_md5_push(&p1);
	fr_md5_push(&p11);
	fr_md5_push(&p12);
	fr_md5_push(&p14);
	fr_md5_push(&p17);
	fr_md5_push(&p15);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p15, 60, 4);

	test_advp_del(&core, &advp);

	//Test random
	random.desired_plen = 60;
	random.pseudo_random_tentatives = 0;
	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p1, 60, 4);

	fr_random_push(1);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p11, 60, 4);

	fr_random_push(2);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p1, 60, 4);

	random.random_set_size = 4;
	advp.prefix = p14;
	advp.plen = 60;
	test_advp_add(&core, &advp);

	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p15, 60, 4);

	fr_random_push(1);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p16, 60, 4);

	fr_random_push(2);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p17, 60, 4);

	fr_random_push(3);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &p1, 60, 4);

	test_advp_del(&core, &advp);
}

void pa_rules_adopt()
{
	struct pa_core core;
	struct pa_dp dp = {.prefix = p1, .plen = 4};
	struct pa_link link = {.name = "L1"};
	struct pa_ldp ldp = {.dp = &dp, .link = &link, .prefix = p101, .plen = 64};
	struct pa_rule_arg arg;
	test_core_init(&core, 5);

	struct pa_rule_adopt adopt;
	pa_rule_adopt_init(&adopt);
	adopt.priority = 5;
	adopt.rule_priority = 3;
	ldp.assigned = 0;
	test_rule_get_max_prio(&adopt.rule, &ldp, 0);

	ldp.assigned = 1;
	test_rule_get_max_prio(&adopt.rule, &ldp, 3);

	test_rule_match(&adopt.rule, &ldp, 1, &arg, PA_RULE_ADOPT);
	test_rule_prio(&arg, 3);
}

int main() {
	sput_start_testing();
	sput_enter_suite("Prefix Assignment Rules tests"); /* optional */
	sput_run_test(pa_rules_adopt);
	sput_run_test(pa_rules_random);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
