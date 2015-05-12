#include "sput.h"


#ifndef __unused
#define __unused __attribute__ ((unused))
#endif

#include <stdio.h>
#define TEST_DEBUG(format, ...) printf("TEST Debug   : "format"\n", ##__VA_ARGS__)

int log_level = 8;
void (*hnetd_log)(int priority, const char *format, ...) = NULL;
#include "hnetd.h"

#include "pa_core.h"

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

void test_ldp_add(struct pa_core *core, struct pa_ldp *ldp)
{
	ldp->in_core.type = PAT_ASSIGNED;
	sput_fail_if(btrie_add(&core->prefixes, &ldp->in_core.be, (btrie_key_t *)&ldp->prefix, ldp->plen), "Adding Advertised Prefix");
}

void test_ldp_del(__unused struct pa_core *core, struct pa_ldp *ldp)
{
	btrie_remove(&ldp->in_core.be);
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

pa_plen test_desired_plen = 0;
pa_plen test_desired_plen_cb(__unused struct pa_rule *r,
		__unused struct pa_ldp *ldp,
		__unused uint16_t prefix_count[PA_RAND_MAX_PLEN + 1])
{
	return test_desired_plen;
}

void pa_rules_hamming()
{
#define _(u) x0##u = {{{0x20, 0x01, 0, 0, 0, 0, 0x00, 0x0##u}}}
	struct in6_addr
	_(0), _(1), _(2), _(3), _(4), _(5), _(6), _(7), _(8),
	_(9), _(a), _(b), _(c), _(d), _(e), _(f);
#undef _
	struct pa_core core;
	struct pa_dp dp = {.prefix = x00, .plen = 48};
	struct pa_link link1 = {.name = "L1"};
	struct pa_ldp ldp = {.core = &core, .dp = &dp, .link = &link1};
	struct pa_advp advp1, advp2;
	struct pa_rule_arg arg;

	test_core_init(&core, 5);
	struct pa_rule_hamming hamming;
	pa_rule_hamming_init(&hamming, NULL, 3, 4, test_desired_plen_cb, 4, (uint8_t *)"SEED", 4);
	test_desired_plen = 64;

	ldp.backoff = 1;
	fr_mask_md5 = true;

	fr_md5_push(&x00);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x00, 64, 4);

	advp1.link = NULL;
	advp1.node_id[0] = 4;
	advp1.plen = 64;
	advp1.prefix = x00;
	advp1.priority = 2;

	test_advp_add(&core, &advp1);
	fr_md5_push(&x00);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x01, 64, 4);

	fr_md5_push(&x01);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &x01, 64, 4);

	fr_md5_push(&x04);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &x04, 64, 4);

	test_advp_del(&core, &advp1);

	advp1.plen = 62;
	test_advp_add(&core, &advp1);

	fr_md5_push(&x00);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x04, 64, 4);

	fr_md5_push(&x01);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &x05, 64, 4);

	fr_md5_push(&x0c);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &x04, 64, 4);

	fr_md5_push(&x0f);
	test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prefix(&arg, &x07, 64, 4);

	advp2.link = NULL;
	advp2.node_id[0] = 4;
	advp2.plen = 63;
	advp2.prefix = x04;
	advp2.priority = 2;
	test_advp_add(&core, &advp2);


#define test(seedp, res) \
		fr_md5_push(&seedp); \
		test_rule_match(&hamming.rule, &ldp, 1, &arg, PA_RULE_PUBLISH); \
		test_rule_prefix(&arg, &res, 64, 4) \

	test(x00, x08);
	test(x01, x09);
	test(x02, x06);
	test(x03, x07);
	test(x04, x06);
	test(x05, x07);
	test(x06, x06);
	test(x07, x07);
	test(x08, x08);
	test(x09, x09);
	test(x0a, x08);
	test(x0b, x09);
	test(x0c, x08);
	test(x0d, x09);
	test(x0e, x06);
	test(x0f, x07);
#undef test

	test_advp_del(&core, &advp2);
	test_advp_del(&core, &advp1);

	fr_mask_md5 = false;
}

void pa_rules_random_override()
{
	struct in6_addr
		x00 = {{{0x20, 0x01, 0, 0, 0, 0, 0x00, 0x00}}},
		x01 = {{{0x20, 0x01, 0, 0, 0, 0, 0x00, 0x04}}},
		x10 = {{{0x20, 0x01, 0, 0, 0, 0, 0x00, 0x08}}},
		x11 = {{{0x20, 0x01, 0, 0, 0, 0, 0x00, 0x0c}}};
	struct pa_core core;
	struct pa_dp dp = {.prefix = x00, .plen = 60};
	struct pa_link link1 = {.name = "L1"};
	struct pa_link link2 = {.name = "L2"};
	struct pa_ldp existing_ldp = {.core = &core, .dp = &dp,
			.link = &link2, .prefix = x10, .plen = 62,
			.rule_priority = 3, .rule = (void *)1, .assigned = 1, .published = 1};
	struct pa_ldp ldp = {.core = &core, .dp = &dp, .link = &link1};
	struct pa_advp advp1, advp2;
	struct pa_rule_arg arg;

	test_core_init(&core, 5);
	struct pa_rule_random random;
	pa_rule_random_init(&random, NULL, 3, 4, test_desired_plen_cb, 4);
	random.pseudo_random_seed = (uint8_t *)"SEED";
	random.pseudo_random_seedlen = 4;
	random.pseudo_random_tentatives = 0;

	test_ldp_add(&core, &existing_ldp);
	advp1.priority = 4;
	advp1.prefix = x00;
	advp1.plen = 61;
	test_advp_add(&core, &advp1);

	test_desired_plen = 62;

	fr_random_push(0);
	ldp.backoff = 1;
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x11, 62, 4);

	advp2.priority = 4;
	advp2.prefix = x11;
	advp2.plen = 62;
	test_advp_add(&core, &advp2);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_NO_MATCH);

	//Now let's authorize override
	advp1.priority = 3;
	random.override_priority = 4;
	random.priority = 5;
	fr_random_push(1);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x01, 62, 5);

	advp2.priority = 3;
	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x00, 62, 5);

	advp1.priority = 4;
	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x11, 62, 5);

	existing_ldp.rule_priority = 2;
	existing_ldp.priority = 5;
	random.override_rule_priority = 3;
	random.safety = 1;
	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x11, 62, 5);

	random.safety = 0;
	fr_random_push(0);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &x10, 62, 5);
}


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
	pa_rule_random_init(&random, NULL, 3, 4, test_desired_plen_cb, 4);
	test_desired_plen = 12;
	random.accept_proposed_cb = NULL;
	random.pseudo_random_seed = (uint8_t *)"SEED";
	random.pseudo_random_seedlen = 4;
	random.pseudo_random_tentatives = 2;

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
	test_desired_plen = 60;

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
	test_desired_plen = 64;
	fr_md5_push(&p102);
	fr_md5_push(&p101);
	test_rule_match(&random.rule, &ldp, 1, &arg, PA_RULE_PUBLISH);
	test_rule_prio(&arg, 3);
	test_rule_prefix(&arg, &p101, 64, 4);

	test_desired_plen = 60;
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
	test_desired_plen = 60;
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
	pa_rule_adopt_init(&adopt, NULL, 3, 5);
	ldp.assigned = 0;
	test_rule_get_max_prio(&adopt.rule, &ldp, 0);

	ldp.assigned = 1;
	test_rule_get_max_prio(&adopt.rule, &ldp, 3);

	test_rule_match(&adopt.rule, &ldp, 1, &arg, PA_RULE_ADOPT);
	test_rule_prio(&arg, 3);
}

int main() {
	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	sput_start_testing();
	sput_enter_suite("Prefix Assignment Rules tests"); /* optional */
	sput_run_test(pa_rules_adopt);
	sput_run_test(pa_rules_random);
	sput_run_test(pa_rules_random_override);
	sput_run_test(pa_rules_hamming);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
