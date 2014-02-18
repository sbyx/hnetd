#include "hnetd.h"
#include "sput.h"
#include "smock.h"

#include "iface.h"
#include "pa.h"

/**************************************************** Tested structures */
struct pa pa;

hnetd_time_t pa_aaa_to = 0;
hnetd_time_t pa_paa_to = 0;
hnetd_time_t pa_local_to = 0;
#define pa_other_to "timeout_queue"
#define pa_other_to_time "timeout_queue_time"

/***************************************************** Test behaviour */
static bool mask_random = false;

#define SMOCK_RANDOM_QUEUE "random queue"

#define TEST_PA_DEBUG
#ifdef TEST_PA_DEBUG
#define test_pa_printf(...) printf(__VA_ARGS__)
#else
#define test_pa_printf(...)
#endif


/***************************************************** Mask for pa.c */

static struct pa_test_iface {
	struct iface_user *user;
	struct iface iface;
} iface = { .user = NULL,
		.iface = { .eui64_addr = {
				.s6_addr = { 0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
						0x01,0x01, 0x02,0x02,  0x03,0x03, 0x04,0x04 }
		} } };


#define iface_register_user   pa_test_iface_register_user
#define iface_unregister_user pa_test_iface_unregister_user
#define iface_get             pa_test_iface_get

static void pa_test_iface_register_user(struct iface_user *user)
{
	test_pa_printf("Iface registered\n");
	iface.user = user;
}

static void pa_test_iface_unregister_user(__attribute__((unused))struct iface_user *user)
{
	test_pa_printf("Iface unregistered\n");
	iface.user = NULL;
}

static struct iface* pa_test_iface_get(__attribute__((unused))const char *ifname)
{
	return &iface.iface;
}

#define hnetd_time test_pa_time
static hnetd_time_t now_time = 1000;
static hnetd_time_t test_pa_time(void) {
	return now_time;
}

#define uloop_timeout_set		test_pa_timeout_set
#define uloop_timeout_cancel	test_pa_timeout_cancel

static int test_pa_timeout_set(struct uloop_timeout *timeout, int ms)
{
	test_pa_printf("Setting a timeout with delay %d\n", ms);

	if(timeout->pending)
		sput_fail_if(1, "Timeout already set");

	if(timeout == &pa.local.timeout) {
		test_pa_printf("Local timeout\n");
		pa_local_to = now_time + ms;
	} else if(timeout == &pa.core.aaa.to) {
		test_pa_printf("aaa timeout\n");
		pa_aaa_to = now_time + ms;
	} else if(timeout == &pa.core.paa.to) {
		test_pa_printf("paa timeout\n");
		pa_paa_to = now_time + ms;
	} else {
		test_pa_printf("other timeout\n");
		smock_push(pa_other_to, timeout);
		smock_push_int(pa_other_to_time, now_time + ms);
	}
	return 0;
}

static int test_pa_timeout_cancel(__attribute__((unused))struct uloop_timeout *timeout)
{
	test_pa_printf("Canceling a timeout\n");
	return 0;
}

static int test_pa_random() {
	int res;
	if(mask_random) {
		res = smock_pull_int(SMOCK_RANDOM_QUEUE);
	} else {
		res = random();
	}
	test_pa_printf("Called random (0x%2x)\n", res);
	return res;
}

#define random test_pa_random

/* Masked sources */
#include "prefix_utils.c"
#include "pa.c"
#include "pa_core.c"
#include "pa_local.c"

/***************************************************** Utilities */

static void test_pa_random_push(const int *int_array, size_t array_len)
{
	int i;
	for(i=0; i< (int) array_len; i++) {
		smock_push_int(SMOCK_RANDOM_QUEUE, int_array[i]);
	}
}

static void test_pa_random_push_prefix(const struct prefix *p)
{
	struct prefix pc;
	prefix_canonical(&pc, p);
	int array[16];
	int i;
	for(i=0; i<16; i++) {
		array[i] = (int) pc.prefix.s6_addr[i];
	}
	test_pa_random_push(array, 16);
}

static void test_pa_call(struct uloop_timeout *to, hnetd_time_t *when)
{
	sput_fail_unless(to, "Timeout is set");
	sput_fail_unless(now_time <= *when, "Timeout after now");
	now_time = *when;
	*when = 0;
	to->cb(to);
}

static void test_pa_call_aaa()
{
	test_pa_call(&pa.core.aaa.to, &pa_aaa_to);
}

static void test_pa_call_paa()
{
	test_pa_call(&pa.core.paa.to, &pa_paa_to);
}

static void test_pa_call_local()
{
	test_pa_call(&pa.local.timeout, &pa_local_to);
}

/***************************************************** Data */

static struct pa_rid rid = { .id = {0x20} };
//static struct pa_rid rid_higher = { .id = {0x30} };
//static struct pa_rid rid_lower = { .id = {0x10} };

static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };

static struct prefix p1_1 = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x01}},
		.plen = 64 };

static struct prefix pv4_1 = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff,  0x0a,0x00, 0x01,0x01 }},
		.plen = 120 };

static struct prefix pv4_1_1 = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff,  0x0a,0x00, 0x01,0x01 }},
		.plen = 128 };

#define PA_TEST_FLOOD 1000
#define PA_TEST_FLOOD_LL 100

#define IFNAME1 "ifname.1"
#define IFNAME2 "ifname.2"

#define DHCP_DATA "dhcpdata"
#define DHCP_LEN 9


/***************************************************** Tests */

void test_pa_initial()
{
	struct pa_cp *cp;
	struct pa_laa *laa;
	struct uloop_timeout *cp_to, *laa_to;
	hnetd_time_t cp_when, laa_when;

	mask_random = true;

	pa_init(&pa, NULL);
	pa.conf.use_ipv4 = false;
	pa.conf.use_ula = false;
	sput_fail_unless(iface.user == NULL, "No iface registered");

	/* Setting flood info */
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);

	/* Starting pa */
	pa_start(&pa);
	sput_fail_unless(iface.user == &pa.ifu, "Iface registered");

	/* Testing initial schedules */
	sput_fail_unless(pa_paa_to == now_time + PA_TEST_FLOOD, "Correct paa timeout");
	sput_fail_unless(pa_aaa_to == now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR, "Correct aaa timeout");
	sput_fail_unless(pa_local_to == now_time + PA_TEST_FLOOD, "Correct local timeout");

	test_pa_call_aaa();
	test_pa_call_paa();
	test_pa_call_local();

	/* No more timeout */
	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_aaa_to, "Correct aaa timeout");
	sput_fail_if(pa_local_to, "Correct local timeout");

	now_time += 10000;

	/* Create a new internal interface */
	iface.user->cb_intiface(iface.user, IFNAME1, true);
	sput_fail_unless(pa_paa_to == now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR, "Correct paa timeout");
	test_pa_call_paa();
	sput_fail_if(pa_paa_to, "Correct paa timeout");

	/* Create a new ldp */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, now_time + 100000, now_time + 50000, NULL, 0);
	sput_fail_unless(pa_local_to == now_time + PA_LOCAL_MIN_DELAY, "Correct local timeout");
	sput_fail_unless(pa_paa_to == now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR, "Correct paa timeout");
	test_pa_call_local();

	test_pa_random_push_prefix(&p1_1);
	test_pa_call_paa();
	cp_when = smock_pull_int(pa_other_to_time);
	cp_to = (struct uloop_timeout *)smock_pull_int(pa_other_to);
	sput_fail_unless(cp_when == now_time + 2*PA_TEST_FLOOD, "Correct apply to");

	sput_fail_if(list_empty(&pa.data.cps), "At least one cp");
	cp = container_of(cp_to, struct pa_cp, apply_to);
	sput_fail_unless(!prefix_cmp(&p1_1, &cp->prefix), "Correct cp prefix");


	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_local_to, "Correct local timeout");
	sput_fail_unless(pa_aaa_to == now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR, "Correct aaa timeout");

	test_pa_call_aaa(); /* Should create a slaac address for this address */
	laa_when = smock_pull_int(pa_other_to_time);
	laa_to = (struct uloop_timeout *)smock_pull_int(pa_other_to);
	sput_fail_unless(laa_when == now_time, "Correct apply to"); /* Immediate because slaac */

	laa = container_of(laa_to, struct pa_laa, apply_to);
	test_pa_call(laa_to, &laa_when);

	sput_fail_unless(laa->applied, "Laa is set now");

	/* Applying the cp */
	test_pa_call(cp_to, &cp_when);
	sput_fail_unless(cp->applied, "CP is set now");

	/* Removing dp */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, 0, 0, NULL, 0);
	sput_fail_unless(pa_paa_to == now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR, "Correct paa timeout");
	sput_fail_unless(pa_local_to == now_time + PA_LOCAL_MIN_DELAY, "Correct local timeout");
	sput_fail_if(pa_aaa_to, "No aaa timeout");
	test_pa_call_local();
	test_pa_call_paa();

	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_aaa_to, "Correct aaa timeout");
	sput_fail_if(pa_local_to, "Correct local timeout");

	iface.user->cb_intiface(iface.user, IFNAME1, false);

	test_pa_call_paa();

	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_aaa_to, "Correct aaa timeout");
	sput_fail_if(pa_local_to, "Correct local timeout");

	pa_stop(&pa);
	sput_fail_unless(iface.user == NULL, "Iface unregistered");
	pa_term(&pa);
}

void test_pa_ipv4()
{
	struct pa_ldp *ldp;
	struct pa_cp *cp;
	struct pa_laa *laa;
	struct uloop_timeout *cp_to, *laa_to;
	hnetd_time_t cp_when, laa_when;

	mask_random = true;

	pa_init(&pa, NULL);
	pa.conf.use_ipv4 = true;
	pa.conf.use_ula = false;

	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);
	iface.user->cb_intiface(iface.user, IFNAME1, true);
	iface.user->ipv4_update(iface.user, IFNAME2, DHCP_DATA, DHCP_LEN);

	sput_fail_unless(pa_paa_to == now_time + PA_TEST_FLOOD, "Correct paa timeout");
	sput_fail_unless(pa_aaa_to == now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR, "Correct aaa timeout");
	sput_fail_unless(pa_local_to == now_time + PA_TEST_FLOOD, "Correct local timeout");

	test_pa_call_aaa();
	test_pa_call_paa();
	test_pa_call_local();

	sput_fail_unless(pa_local_to == now_time + 2*PA_TEST_FLOOD, "Correct local timeout");
	test_pa_call_local();

	ldp = pa.local.ipv4.ldp;
	sput_fail_unless(ldp, "Generated ipv4 prefix");
	sput_fail_unless(!prefix_cmp(&ldp->dp.prefix, &pa.conf.v4_prefix), "Correct v4 prefix");

	test_pa_random_push_prefix(&pv4_1);
	test_pa_call_paa();
	cp_when = smock_pull_int(pa_other_to_time);
	cp_to = (struct uloop_timeout *)smock_pull_int(pa_other_to);
	cp = container_of(cp_to, struct pa_cp, apply_to);
	sput_fail_unless(!prefix_cmp(&cp->prefix, &pv4_1), "Correct ipv4 cp");

	test_pa_random_push_prefix(&pv4_1_1);
	test_pa_call_aaa();

	laa_when = smock_pull_int(pa_other_to_time);
	laa_to = (struct uloop_timeout *)smock_pull_int(pa_other_to);
	laa = container_of(laa_to, struct pa_laa, apply_to);
	sput_fail_unless(!memcmp(&laa->aa.address, &pv4_1_1.prefix, sizeof(struct in6_addr)), "Correct ipv4 laa");

	test_pa_call(laa_to, &laa_when);
	test_pa_call(cp_to, &cp_when);

	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_aaa_to, "Correct aaa timeout");

	/* Renew ipv4 dp validity */
	test_pa_call_local();

	sput_fail_if(pa_paa_to, "Correct paa timeout");
	sput_fail_if(pa_aaa_to, "Correct aaa timeout");

	iface.user->ipv4_update(iface.user, NULL, NULL, 0);
	test_pa_call_local();
	test_pa_call_paa();

	pa_stop(&pa);
	pa_term(&pa);
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);

	sput_start_testing();

	sput_enter_suite("Prefix assignment tests"); /* optional */
	sput_run_test(test_pa_initial);
	sput_run_test(test_pa_ipv4);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
