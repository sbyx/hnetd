/*
 * Author: Pierre Pfister
 *
 * Prefix assignment stable storage API tester.
 *
 */

#include "pa.h"
#include "pa_store.h"
#include "sput.h"

static struct pa pa;
#define store (&pa.store)

static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };
static struct prefix p2 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x02, 0xff, 0xff, 0xff}},
		.plen = 56 };
static struct prefix p1_20 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x20}},
		.plen = 64 };
static struct prefix p1_21 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x21}},
		.plen = 64 };
static struct prefix p2_20 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x02, 0xff, 0xff, 0xff, 0x20}},
		.plen = 56 };

static struct prefix p_ula = {
		.prefix = { .s6_addr = {
				0xfd, 0x00, 0xde, 0xad}},
		.plen = 56 };
static struct prefix p_ula2 = {
		.prefix = { .s6_addr = {
				0xfd, 0x00, 0xde, 0xae}},
		.plen = 56 };
static struct prefix p_global = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0xde, 0xad}},
		.plen = 56 };

static struct pa_rid rid = { .id = {0x20} };

struct pa_iface *if1, *if2;
#define IFNAME_1 "iface0"
#define IFNAME_2 "iface1"
#define TEST_PAS_FILE "/tmp/hnetd_pa.db"

static void test_pa_file_reset() {
	FILE *f;
		sput_fail_unless(f = fopen(TEST_PAS_FILE, "w"), "Erase test db file");
		if(f)
			fclose(f);
}

static void test_pa_store_init() {
	pa_data_init(&pa.data, NULL);
	pa_store_init(store);
	pa_store_start(store);

	if1 = pa_iface_get(&pa.data, IFNAME_1, true);
	if2 = pa_iface_get(&pa.data, IFNAME_2, true);
	pa_iface_notify(&pa.data, if1);
	pa_iface_notify(&pa.data, if2);
}

static void test_pa_store_term() {
	pa_iface_todelete(if1);
	pa_iface_todelete(if2);
	pa_iface_notify(&pa.data, if1);
	pa_iface_notify(&pa.data, if2);

	pa_store_stop(store);
	pa_store_term(store);
	pa_data_term(&pa.data);
}

static void test_pa_store_sps() {
	struct pa_cp *cp1_20, *cp2_20, *cp1_21, *cp1, *cp2;
	struct pa_sp *sp;
	struct pa_laa *la1_20, *la2_20, *la1_21;
	struct pa_sa *sa;

	test_pa_file_reset();
	test_pa_store_init();
	pa.data.conf.max_sp = 3;
	pa.data.conf.max_sp_per_if = 2;
	pa.data.conf.max_sa = 2;
	pa_store_setfile(store, TEST_PAS_FILE);

	cp1_20 = pa_cp_get(&pa.data, &p1_20, PA_CPT_L, true);
	pa_cpl_set_iface(_pa_cpl(cp1_20), if1);
	pa_cp_notify(cp1_20);

	la1_20 = pa_laa_create(&p1_20.prefix, _pa_cpl(cp1_20));
	pa_aa_notify(&pa.data, &la1_20->aa);

	sput_fail_unless(list_empty(&pa.data.sps), "No sp");
	sput_fail_unless(!pa.data.sp_count, "sp_count equals zero");
	sput_fail_unless(list_empty(&pa.data.sas), "No sa");
	sput_fail_unless(!pa.data.sa_count, "sa_count equals zero");

	pa_cp_set_applied(cp1_20, true);
	pa_cp_notify(cp1_20);

	sput_fail_unless(!list_empty(&pa.data.sps), "One sp");
	sput_fail_unless(pa.data.sp_count == 1, "sp_count equals 1");
	sput_fail_unless(if1->sp_count == 1, "One sp for if1");
	sput_fail_unless(if2->sp_count == 0, "Zero sp for if2");
	sput_fail_unless(pa.data.sa_count == 0, "No sa yet");

	pa_laa_set_applied(la1_20, true);
	pa_aa_notify(&pa.data, &la1_20->aa);
	sput_fail_unless(pa.data.sa_count == 1, "One sa");
	sa = list_first_entry(&pa.data.sas, struct pa_sa, le);
	sput_fail_unless(!memcmp(&sa->addr, &la1_20->aa.address, sizeof(struct in6_addr)), "Address value");

	cp2_20 = pa_cp_get(&pa.data, &p2_20, PA_CPT_L, true);
	pa_cpl_set_iface(_pa_cpl(cp2_20), if1);
	pa_cp_set_applied(cp2_20, true);
	pa_cp_notify(cp2_20);

	la2_20 = pa_laa_create(&p2_20.prefix, _pa_cpl(cp2_20));
	pa_laa_set_applied(la2_20, true);
	pa_aa_notify(&pa.data, &la2_20->aa);

	bool first = true;
	pa_for_each_sp_in_iface(sp, if1) {
		if(first) {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p2_20), "Correct prefix");
			sput_fail_unless(sp->iface == if1, "Correct iface");
			first = false;
		} else {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p1_20), "Correct prefix");
			sput_fail_unless(sp->iface == if1, "Correct iface");
		}
	}
	first = true;
	pa_for_each_sa(sa, &pa.data) {
		if(first) {
			sput_fail_unless(!memcmp(&sa->addr, &la2_20->aa.address, sizeof(struct in6_addr)), "Address value");
			first = false;
		} else {
			sput_fail_unless(!memcmp(&sa->addr, &la1_20->aa.address, sizeof(struct in6_addr)), "Address value");
		}
	}
	sput_fail_unless(pa.data.sp_count == 2, "sp_count equals 2");
	sput_fail_unless(pa.data.sa_count == 2, "sa_count equals 2");
	sput_fail_unless(if1->sp_count == 2, "One sp for if1");
	sput_fail_unless(if2->sp_count == 0, "Zero sp for if2");

	cp1_21 = pa_cp_get(&pa.data, &p1_21, PA_CPT_L, true);
	pa_cpl_set_iface(_pa_cpl(cp1_21), if1);
	pa_cp_set_applied(cp1_21, true);
	pa_cp_notify(cp1_21);

	la1_21 = pa_laa_create(&p1_21.prefix, _pa_cpl(cp1_21));
	pa_laa_set_applied(la1_21, true);
	pa_aa_notify(&pa.data, &la1_21->aa);

	first = true;
	pa_for_each_sp_in_iface(sp, if1) {
		if(first) {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p1_21), "Correct prefix");
			sput_fail_unless(sp->iface == if1, "Correct iface");
			first = false;
		} else {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p2_20), "Correct prefix");
			sput_fail_unless(sp->iface == if1, "Correct iface");
		}
	}

	first = true;
	pa_for_each_sa(sa, &pa.data) {
		if(first) {
			sput_fail_unless(!memcmp(&sa->addr, &la1_21->aa.address, sizeof(struct in6_addr)), "Address value");
			first = false;
		} else {
			sput_fail_unless(!memcmp(&sa->addr, &la2_20->aa.address, sizeof(struct in6_addr)), "Address value");
		}
	}
	sput_fail_unless(pa.data.sp_count == 2, "sp_count equals 2");
	sput_fail_unless(pa.data.sa_count == 2, "sa_count equals 2");
	sput_fail_unless(if1->sp_count == 2, "2 sp for if1");
	sput_fail_unless(if2->sp_count == 0, "0 sp for if2");

	cp1 = pa_cp_get(&pa.data, &p1, PA_CPT_L, true);
	pa_cpl_set_iface(_pa_cpl(cp1), if2);
	pa_cp_set_applied(cp1, true);
	pa_cp_notify(cp1);

	sput_fail_unless(pa.data.sp_count == 3, "sp_count equals 3");
	sput_fail_unless(if1->sp_count == 2, "Two sp for if1");
	sput_fail_unless(if2->sp_count == 1, "1 sp for if2");

	cp2 = pa_cp_get(&pa.data, &p2, PA_CPT_L, true);
	pa_cpl_set_iface(_pa_cpl(cp2), if2);
	pa_cp_set_applied(cp2, true);
	pa_cp_notify(cp2);


	first = true;
	pa_for_each_sp_in_iface(sp, if2) {
		if(first) {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p2), "Correct prefix");
			sput_fail_unless(sp->iface == if2, "Correct iface");
			first = false;
		} else {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p1), "Correct prefix");
			sput_fail_unless(sp->iface == if2, "Correct iface");
		}
	}
	pa_for_each_sp_in_iface(sp, if1)
		sput_fail_unless(!prefix_cmp(&sp->prefix, &p1_21), "Correct prefix");
	sput_fail_unless(pa.data.sp_count == 3, "sp_count equals 3");
	sput_fail_unless(if1->sp_count == 1, "One sp for if1");
	sput_fail_unless(if2->sp_count == 2, "Two sp for if2");

	sput_fail_unless(store->save_timeout.pending, "Timeout pending");
	sput_fail_unless(store->save_delay == INT64_C(10*60)*HNETD_TIME_PER_SECOND, "5 min delay");
	store->save_timeout.cb(&store->save_timeout);
	test_pa_store_term();

	/* reloading */
	test_pa_store_init();
	pa_store_setfile(store, TEST_PAS_FILE);
	sput_fail_unless(store->save_delay == INT64_C(20*60)*HNETD_TIME_PER_SECOND, "10 min delay now");

	first = true;
	pa_for_each_sp_in_iface(sp, if2) {
		if(first) {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p2), "Correct prefix");
			sput_fail_unless(sp->iface == if2, "Correct iface");
			first = false;
		} else {
			sput_fail_unless(!prefix_cmp(&sp->prefix, &p1), "Correct prefix");
			sput_fail_unless(sp->iface == if2, "Correct iface");
		}
	}
	pa_for_each_sp_in_iface(sp, if1)
		sput_fail_unless(!prefix_cmp(&sp->prefix, &p1_21), "Correct prefix");

	first = true;
	pa_for_each_sa(sa, &pa.data) {
		if(first) {
			sput_fail_unless(!memcmp(&sa->addr, &p1_21.prefix, sizeof(struct in6_addr)), "Address value");
			first = false;
		} else {
			sput_fail_unless(!memcmp(&sa->addr, &p2_20.prefix, sizeof(struct in6_addr)), "Address value");
		}
	}
	sput_fail_unless(pa.data.sa_count == 2, "sa_count equals 2");
	sput_fail_unless(pa.data.sp_count == 3, "sp_count equals 3");
	sput_fail_unless(if1->sp_count == 1, "One sp for if1");
	sput_fail_unless(if2->sp_count == 2, "Zero sp for if2");

	test_pa_store_term();
}

void test_pa_store_ulas()
{
	struct pa_ldp *ldp_global, *ldp_ula, *ldp_ula2;
	struct pa_edp *edp;

	test_pa_file_reset();
	test_pa_store_init();
	pa_store_setfile(store, TEST_PAS_FILE);

	sput_fail_if(pa_store_ula_get(store), "No ula for now");

	ldp_global = pa_ldp_get(&pa.data, &p_global, true);
	pa_dp_notify(&pa.data, &ldp_global->dp);
	sput_fail_if(pa_store_ula_get(store), "Global is not valid");

	edp = pa_edp_get(&pa.data, &p_global, &rid, true);
	pa_dp_notify(&pa.data, &edp->dp);
	sput_fail_if(pa_store_ula_get(store), "External is not valid");

	ldp_ula = pa_ldp_get(&pa.data, &p_ula, true);
	pa_dp_notify(&pa.data, &ldp_ula->dp);
	sput_fail_unless(!prefix_cmp(pa_store_ula_get(store), &p_ula), "Set a ula address");

	ldp_ula2 = pa_ldp_get(&pa.data, &p_ula2, true);
	pa_dp_notify(&pa.data, &ldp_ula2->dp);
	sput_fail_unless(!prefix_cmp(pa_store_ula_get(store), &p_ula2), "Set a ula address");

	pa_dp_todelete(&ldp_global->dp);
	pa_dp_notify(&pa.data, &ldp_global->dp);
	pa_dp_todelete(&ldp_ula->dp);
	pa_dp_notify(&pa.data, &ldp_ula->dp);
	pa_dp_todelete(&ldp_ula2->dp);
	pa_dp_notify(&pa.data, &ldp_ula2->dp);
	pa_dp_todelete(&edp->dp);
	pa_dp_notify(&pa.data, &edp->dp);

	test_pa_store_term();
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();
	sput_start_testing();
	sput_enter_suite("Prefix assignment stable storage (pa_store.c)"); /* optional */
	sput_run_test(test_pa_store_sps);
	sput_run_test(test_pa_store_ulas);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}

