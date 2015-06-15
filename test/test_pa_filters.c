/*
 * Copyright (c) 2015 Cisco Systems, Inc.
 */
#include "sput.h"

#include "pa_filters.c"

struct filter_test {
	struct pa_filter filter;
	int ret;
};

int filter_test(__unused struct pa_rule *rule, __unused struct pa_ldp *ldp, struct pa_filter *filter)
{
	struct filter_test *ft = container_of(filter, struct filter_test, filter);
	return ft->ret;
}

#define filter_check(f, rule, ldp, value) \
	sput_fail_unless((f)->accept(rule, ldp, f) == value, "Correct filter value")


void pa_filters_type()
{
	struct pa_filter_type t;
	struct pa_link l;
	struct pa_dp d;
	struct pa_ldp ldp;
	ldp.link = &l;
	ldp.dp = &d;

	pa_filter_type_dp_init(&t, 1);
	l.type = 1;
	d.type = 1;
	filter_check(&t.filter, NULL, &ldp, 1);
	l.type = 0;
	d.type = 1;
	filter_check(&t.filter, NULL, &ldp, 1);
	l.type = 0;
	d.type = 0;
	filter_check(&t.filter, NULL, &ldp, 0);
	l.type = 1;
	d.type = 0;
	filter_check(&t.filter, NULL, &ldp, 0);

	pa_filter_type_link_init(&t, 1);
	l.type = 1;
	d.type = 1;
	filter_check(&t.filter, NULL, &ldp, 1);
	l.type = 0;
	d.type = 1;
	filter_check(&t.filter, NULL, &ldp, 0);
	l.type = 0;
	d.type = 0;
	filter_check(&t.filter, NULL, &ldp, 0);
	l.type = 1;
	d.type = 0;
	filter_check(&t.filter, NULL, &ldp, 1);
}

void pa_filters_ldp()
{
	struct pa_filter_ldp f;
	struct pa_link l, l2;
	struct pa_dp d, d2;
	struct pa_ldp ldp, ldp2;
	ldp.link = &l;
	ldp.dp = &d;
	ldp2.link = &l2;
	ldp2.dp = &d2;
	pa_filter_ldp_init(&f, NULL, NULL);
	filter_check(&f.filter, NULL, &ldp, 1);
	filter_check(&f.filter, NULL, &ldp2, 1);
	f.dp = &d;
	filter_check(&f.filter, NULL, &ldp, 1);
	filter_check(&f.filter, NULL, &ldp2, 0);
	f.link = &l;
	filter_check(&f.filter, NULL, &ldp, 1);
	filter_check(&f.filter, NULL, &ldp2, 0);
	f.dp = NULL;
	filter_check(&f.filter, NULL, &ldp, 1);
	filter_check(&f.filter, NULL, &ldp2, 0);
}

void pa_filters_logic()
{
	struct filter_test fts[2] = {{.filter = {.accept = filter_test}}, {.filter = {.accept = filter_test}}};
	struct pa_filters fs;

	/* OR */
	pa_filters_or_init(&fs, false);
	filter_check(&fs.filter, NULL, NULL, 0);
	fs.negate = 1;
	filter_check(&fs.filter, NULL, NULL, 1);

	pa_filters_add(&fs, &fts[0].filter);
	pa_filters_add(&fs, &fts[1].filter);

	fs.negate = 0;
	fts[0].ret = 0;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 1;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 0;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 1;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 1);

	fs.negate = 1;
	fts[0].ret = 0;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 1;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 0;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 1;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 0);

	/* AND */
	pa_filters_and_init(&fs, false);
	filter_check(&fs.filter, NULL, NULL, 1);
	fs.negate = 1;
	filter_check(&fs.filter, NULL, NULL, 0);

	pa_filters_add(&fs, &fts[0].filter);
	pa_filters_add(&fs, &fts[1].filter);

	fs.negate = 0;
	fts[0].ret = 0;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 1;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 0;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 0);
	fts[0].ret = 1;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 1);

	fs.negate = 1;
	fts[0].ret = 0;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 1;
	fts[1].ret = 0;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 0;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 1);
	fts[0].ret = 1;
	fts[1].ret = 1;
	filter_check(&fs.filter, NULL, NULL, 0);
}

int main() {
	sput_start_testing();
	sput_enter_suite("Prefix Assignment Filters tests"); /* optional */
	sput_run_test(pa_filters_logic);
	sput_run_test(pa_filters_ldp);
	sput_run_test(pa_filters_type);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
