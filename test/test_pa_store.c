/*
 * Author: Pierre Pfister
 *
 * Prefix assignment stable storage API tester.
 *
 */

#include "pa_store.c"

#include <stdio.h>

#include "sput.h"

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

#define TEST_IFNAME_1 "iface0"
#define TEST_IFNAME_2 "iface1"
#define TEST_PAS_FILE "/tmp/hnetd_pa.db"

static void test_pa_store_init() {
	FILE *f;
	sput_fail_unless(f = fopen(TEST_PAS_FILE, "w"), "Erase test db file");
	if(f)
		fclose(f);
}

static void test_pa_store_multiple() {
	struct pa_store *store;
	const struct prefix *res;
	int i;

	struct pa_store_conf conf;
	conf.max_px = 2;
	conf.max_px_per_if = 1;

	store = pa_store_create(&conf, TEST_PAS_FILE);
	sput_fail_unless(store, "Pa storage initialized");
	if(!store)
		return;

	for(i=0; i<4; i++)
		sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_1, &p1_20), "Adding p1_20 prefix");
	sput_fail_unless(store->ap_count == 1, "Correct store ap_count");

	sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_1, &p1_21), "Adding p1_21 prefix");
	sput_fail_unless(store->ap_count == 1, "One single ap per iface");
	res = pa_store_prefix_get(store, NULL, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_21), "Correct res for prefix");
	res = pa_store_prefix_get(store, TEST_IFNAME_1, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_21), "Correct res for prefix");
	sput_fail_if(pa_store_prefix_get(store, TEST_IFNAME_2, &p1), "No prefix for iface 2");

	/* Adding the same prefix for another interface */
	sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_2, &p1_21), "Adding p1_21 prefix for another interface");
	sput_fail_unless(store->ap_count == 1, "One single ap in memory");

	/* Adding a prefix for the first interface */
	sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_1, &p1_20), "Adding p1_20 for first iface");
	sput_fail_unless(store->ap_count == 2, "Two pas in memory");
	res = pa_store_prefix_get(store, TEST_IFNAME_1, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_20), "Correct res for prefix");
	res = pa_store_prefix_get(store, TEST_IFNAME_2, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_21), "Correct res for prefix");

	pa_store_destroy(store);
}

static void test_pa_store_basic_check_state1(struct pa_store *store) {
	const struct prefix *res;
	res = pa_store_prefix_get(store, NULL, NULL);
	sput_fail_unless(res, "One available");
	sput_fail_unless(!prefix_cmp(res, &p1_20) || !prefix_cmp(res, &p2_20), "Compatible value");
	res = pa_store_prefix_get(store, TEST_IFNAME_1, NULL);
	sput_fail_if(!res || prefix_cmp(res, &p1_20), "Correct res for "TEST_IFNAME_1);
	res = pa_store_prefix_get(store, TEST_IFNAME_2, NULL);
	sput_fail_if(!res || prefix_cmp(res, &p2_20), "Correct res for "TEST_IFNAME_2);
	res = pa_store_prefix_get(store, NULL, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_20), "Correct res for prefix 1");
	res = pa_store_prefix_get(store, NULL, &p2);
	sput_fail_if(!res || prefix_cmp(res, &p2_20), "Correct res for prefix 2");
	res = pa_store_prefix_get(store, TEST_IFNAME_1, &p1);
	sput_fail_if(!res || prefix_cmp(res, &p1_20), "Correct res for prefix 1");
	res = pa_store_prefix_get(store, TEST_IFNAME_2, &p2);
	sput_fail_if(!res || prefix_cmp(res, &p2_20), "Correct res for prefix 2");
	sput_fail_if(pa_store_prefix_get(store, TEST_IFNAME_1, &p2), "No such prefix in state");
	sput_fail_if(pa_store_prefix_get(store, TEST_IFNAME_2, &p1), "No such prefix in state");

	res = pa_store_ula_get(store);
	sput_fail_if(!res || prefix_cmp(res, &p_ula), "Correct res for prefix 2");
}

static void test_pa_store_basic() {
	struct pa_store *store;
	const struct prefix *res;

	/* Creating a first state */
	store = pa_store_create(NULL, TEST_PAS_FILE);
	sput_fail_unless(store, "Pa storage initialized");
	if(!store)
		return;

	sput_fail_if(pa_store_prefix_get(store, NULL, NULL), "No prefix by now");
	sput_fail_if(pa_store_ula_get(store), "No ula for now");

	sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_1, &p1_20), "Adding p1_20 prefix");
	sput_fail_if(pa_store_prefix_add(store, TEST_IFNAME_2, &p2_20), "Adding p2_20 prefix");
	sput_fail_if(pa_store_ula_set(store, &p_ula), "Setting ula");

	test_pa_store_basic_check_state1(store);

	pa_store_destroy(store);

	/* Loading from file */
	store = pa_store_create(NULL, TEST_PAS_FILE);
	sput_fail_unless(store, "Pa storage initialized");
	if(!store)
		return;

	sput_fail_if(pas_load(store), "Load from file");

	test_pa_store_basic_check_state1(store);

	sput_fail_if(pa_store_empty(store), "Emptying store structure");
	pa_store_destroy(store);
}



int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	sput_start_testing();
	sput_enter_suite("Prefix assignment stable storage (pa_store.c)"); /* optional */

	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);

	sput_run_test(test_pa_store_init);
	sput_run_test(test_pa_store_basic);
	sput_run_test(test_pa_store_multiple);

	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}

