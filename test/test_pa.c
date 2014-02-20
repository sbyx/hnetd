#define L_LEVEL 7

#include "hnetd.h"
#include "sput.h"
#include "smock.h"

#include "iface.h"
#include "pa.h"

/**************************************************** Tested structures */
struct pa pa;


/***************************************************** Test behaviour */
static bool mask_random = false;

#define SMOCK_RANDOM_QUEUE "random queue"

#define TEST_PA_DEBUG
#ifdef TEST_PA_DEBUG
#define test_pa_printf(...) printf(__VA_ARGS__)
#else
#define test_pa_printf(...)
#endif


/***************************************************** Masking time */

#define hnetd_time 				test_pa_time
#define uloop_timeout_set		test_pa_timeout_set
#define uloop_timeout_cancel	test_pa_timeout_cancel

LIST_HEAD(timeouts);
static hnetd_time_t now_time = 1000;

static hnetd_time_t test_pa_time(void) {
	return now_time;
}

static int test_pa_timeout_set(struct uloop_timeout *timeout, int ms)
{
	sput_fail_if(ms < 0, "Timeout delay is positive");
	if(ms < 0)
		ms = 0;

	if(timeout->pending)
		list_remove(&timeout->list);
	else
		timeout->pending = true;

	timeout->time.tv_sec = now_time + ms;

	struct uloop_timeout *tp;
	list_for_each_entry(tp, &timeouts, list) {
		if(timeout->time.tv_sec < tp->time.tv_sec) {
			list_add_before(&tp->list, &timeout->list);
			return 0;
		}
	}
	list_add_tail(&timeout->list, &timeouts);
	return 0;
}

static int test_pa_timeout_cancel(struct uloop_timeout *timeout)
{
	sput_fail_unless(timeout->pending, "Timeout is pending");
	if(timeout->pending) {
		list_remove(&timeout->list);
		timeout->pending = 0;
	}
	return 0;
}

static hnetd_time_t to_time(struct uloop_timeout *t)
{
	return (hnetd_time_t) t->time.tv_sec;
}

#define to_check(to, when) ((to)->pending && (to_time(to) == (when)))

static void to_run_one(struct uloop_timeout *t)
{
	hnetd_time_t when = to_time(t);
	if(when >= now_time) {
		test_pa_printf("Time going forward of %d ms\n", (int) (when - now_time));
		now_time = when;
	}

	list_remove(&t->list);
	t->pending = false;
	if(t->cb)
		t->cb(t);
}

static struct uloop_timeout *to_getfirst()
{
	if(list_is_empty(&timeouts))
		return NULL;
	return list_first_entry(&timeouts, struct uloop_timeout, list);
}

static int to_run(int rounds)
{
	struct uloop_timeout *to;
	while(rounds > 0 && (to = to_getfirst())) {
		to_run_one(to);
		rounds--;
	}
	return rounds;
}


/***************************************************** Mask for pa.c */

static struct pa_test_iface {
	struct iface_user *user;
	struct iface iface;
} iface = { .user = NULL,
		.iface = { .eui64_addr = {
				.s6_addr = { 0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
						0x00,0x00, 0x00,0x00,  0xff,0xff, 0xff,0xff }
		} } };


#define iface_register_user   pa_test_iface_register_user
#define iface_unregister_user pa_test_iface_unregister_user
#define iface_get             pa_test_iface_get

static void pa_test_iface_register_user(struct iface_user *user)
{
	iface.user = user;
}

static void pa_test_iface_unregister_user(__attribute__((unused))struct iface_user *user)
{
	iface.user = NULL;
}

static struct iface* pa_test_iface_get(__attribute__((unused))const char *ifname)
{
	return &iface.iface;
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

/***************************************************** Data */

static struct pa_rid rid = { .id = {0x20} };
static struct pa_rid rid_higher = { .id = {0x30} };
static struct pa_rid rid_lower = { .id = {0x10} };

static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };

static struct prefix p1_1 = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x01}},
		.plen = 64 };
static struct prefix p1_2 = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x02}},
		.plen = 64 };

static struct prefix p2 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x02, 0xff, 0xff, 0xff}},
		.plen = 56 };

static struct prefix p2_1 = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x02,  0xff,0xff, 0xff,0x01}},
		.plen = 64 };


static struct prefix p1_excluded = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x00}},
		.plen = 60 };
static struct prefix p1_excluded_incr = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x20}},
		.plen = 64 };

static struct prefix p1_1_addr = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x01,
				0x00,0x00, 0x00,0x00,  0xff,0xff, 0xff,0xff}},
		.plen = 128 };
static struct prefix p1_2_addr = {
		.prefix = { .s6_addr = {
				0x20,0x01, 0x20,0x01,  0xff,0xff, 0xff,0x02,
				0x00,0x00, 0x00,0x00,  0xff,0xff, 0xff,0xff}},
		.plen = 128 };

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
	hnetd_time_t when;

	mask_random = true;

	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = false;
	pa.local.conf.use_ula = false;
	sput_fail_unless(iface.user == NULL, "No iface registered");

	/* Setting flood info */
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);

	/* Starting pa */
	pa_start(&pa);
	sput_fail_unless(iface.user == &pa.ifu, "Iface registered");

	/* Testing initial schedules */
	sput_fail_unless(to_check(&pa.core.paa.to, now_time + PA_TEST_FLOOD), "Correct paa timeout");
	sput_fail_unless(to_check(&pa.core.aaa.to, now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR), "Correct aaa timeout");
	sput_fail_unless(to_check(&pa.local.timeout, now_time + PA_TEST_FLOOD), "Correct local timeout");

	sput_fail_unless(!to_run(3) && !to_getfirst(), "Run three timeouts");

	now_time += 10000;

	/* Create a new internal interface */
	iface.user->cb_intiface(iface.user, IFNAME1, true);
	sput_fail_unless(to_check(&pa.core.paa.to, now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR), "Correct paa timeout");
	sput_fail_unless(!to_run(1) && !to_getfirst(), "Run one timeouts");

	/* Create a new ldp */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, now_time + 100000, now_time + 50000, NULL, 0);
	sput_fail_unless(to_check(&pa.core.paa.to, now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR), "Correct paa timeout");
	sput_fail_unless(to_check(&pa.local.timeout, now_time + PA_LOCAL_MIN_DELAY), "Correct paa timeout");
	when = now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR + 2*PA_TEST_FLOOD;

	test_pa_random_push_prefix(&p1_1);
	sput_fail_unless(!to_run(2), "Run two timeouts (remains the new cp apply and aaa)");

	sput_fail_unless(to_check(&pa.core.aaa.to, now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR), "Correct aaa timeout");

	cp = list_first_entry(&pa.data.cps, struct pa_cp, le);
	sput_fail_unless(cp, "One cp");
	if(cp) {
		sput_fail_unless(to_check(&cp->apply_to, when), "Correct apply to");
		sput_fail_unless(!prefix_cmp(&p1_1, &cp->prefix), "Correct cp prefix");
	}
	sput_fail_unless(!to_run(1), "Run aaa");

	sput_fail_unless(cp->laa, "laa created");
	if(cp->laa) {
		sput_fail_unless(to_check(&cp->laa->apply_to, now_time + 0), "Correct laa timeout");
	}
	//sput_fail_unless(!to_run(2) && !to_getfirst(), "Apply cp and laa");
	to_run(100);

	/* Removing dp */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, 0, 0, NULL, 0);
	sput_fail_unless(!to_run(2) && !to_getfirst(), "Run paa and local");
	iface.user->cb_intiface(iface.user, IFNAME1, false);
	sput_fail_unless(!to_run(1) && !to_getfirst(), "Run paa");

	pa_stop(&pa);
	sput_fail_unless(iface.user == NULL, "Iface unregistered");
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

void test_pa_ipv4()
{
	struct pa_ldp *ldp;
	struct pa_cp *cp;
	hnetd_time_t when;
	int res;

	mask_random = true;

	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = true;
	pa.local.conf.use_ula = false;

	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.user->cb_intiface(iface.user, IFNAME1, true);
	iface.user->ipv4_update(iface.user, IFNAME2, DHCP_DATA, DHCP_LEN);

	sput_fail_unless(to_check(&pa.local.timeout, now_time + PA_TEST_FLOOD), "Correct local timeout");
	when = now_time + PA_TEST_FLOOD + 2*PA_TEST_FLOOD;
	sput_fail_unless(!to_run(3), "Run paa, aaa and local");
	sput_fail_unless(to_check(&pa.local.timeout, when), "Correct local timeout");
	sput_fail_unless(to_getfirst() == &pa.local.timeout, "Local to be run");
	res = to_run(1);
	sput_fail_if(res, "Correctly run");

	ldp = pa.local.ipv4.ldp;
	sput_fail_unless(ldp, "Generated ipv4 prefix");
	if(!ldp)
		return;

	sput_fail_unless(!prefix_cmp(&ldp->dp.prefix, &pa.local.conf.v4_prefix), "Correct v4 prefix");

	test_pa_random_push_prefix(&pv4_1);
	sput_fail_unless(to_getfirst() == &pa.core.paa.to && !to_run(1), "Run paa");

	cp = list_first_entry(&pa.data.cps, struct pa_cp, le);
	sput_fail_unless(cp, "One cp");
	if(cp) {
		sput_fail_unless(!prefix_cmp(&pv4_1, &cp->prefix), "Correct cp prefix");
	}

	test_pa_random_push_prefix(&pv4_1_1);
	sput_fail_unless(to_getfirst() == &pa.core.aaa.to && !to_run(1), "Run aaa");
	sput_fail_unless(cp->laa, "Created laa");
	if(cp->laa)
		sput_fail_unless(!memcmp(&cp->laa->aa.address, &pv4_1_1.prefix, sizeof(struct in6_addr)), "Correct ipv4 laa");

	sput_fail_unless(!to_run(2), "Run cp and laa apply");


	/* Renew ipv4 dp validity */
	sput_fail_unless(to_getfirst() == &pa.local.timeout && !to_run(1), "Renew");

	iface.user->ipv4_update(iface.user, NULL, NULL, 0);
	sput_fail_unless(!to_run(2) && !to_getfirst(), "Remove IPv4 connectivity");

	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

void test_pa_checkcp(struct pa_cp *cp, const struct prefix *p, const struct in6_addr *addr, const char *ifname)
{
	sput_fail_unless(!p || !prefix_cmp(&cp->prefix, p), "Correct prefix");
	sput_fail_unless(!ifname || (cp->iface && !strcmp(cp->iface->ifname, ifname)), "Correct ifname");

	sput_fail_unless(cp->laa, "Assigned address");
	if(cp->laa)
		sput_fail_unless(!addr || !memcmp(addr, &cp->laa->aa.address, sizeof(struct in6_addr)), "Correct address");
}

void test_pa_network()
{
	struct pa_cp *cp, *cp2;
	struct pa_edp *edp;
	struct pa_eaa *eaa;
	struct pa_ap *ap;
	hnetd_time_t valid, preferred;
	int res;

	/* This test looks for collisions */
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = false;
	pa.local.conf.use_ula = false;
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.user->cb_intiface(iface.user, IFNAME1, true);
	valid = now_time + 100000;
	preferred = now_time + 50000;
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, valid , preferred, NULL, 0);

	test_pa_random_push_prefix(&p1_1);
	res = to_run(6);
	sput_fail_unless(!res && !to_getfirst(), "Run and apply everything");

	cp = list_first_entry(&pa.data.cps, struct pa_cp, le);
	test_pa_checkcp(cp, &p1_1, &p1_1_addr.prefix, IFNAME1);

	/* Lower ID, Lower priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_notify(&pa.data, ap);
	sput_fail_unless(!to_run(1) && !to_getfirst(), "Run paa");
	sput_fail_if(list_empty(&pa.data.cps), "The cp remains");
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	/* Higher ID, Lower priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_notify(&pa.data, ap);
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run paa");
	sput_fail_if(list_empty(&pa.data.cps), "The cp remains");
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	/* Lower ID, higher priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MAX);
	pa_ap_notify(&pa.data, ap);
	test_pa_random_push_prefix(&p1_1); /* This one should be ignored and the second one should be chosen */
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");
	sput_fail_if(list_empty(&pa.data.cps), "The cp remains");
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa and apply");
	cp = list_first_entry(&pa.data.cps, struct pa_cp, le);
	test_pa_checkcp(cp, &p1_2, &p1_2_addr.prefix, IFNAME1);
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	/* Now let's delete the address */
	eaa = pa_eaa_get(&pa.data, &p1_2_addr.prefix, &rid_higher, true);
	pa_eaa_set_iface(eaa, pa_iface_get(&pa.data, IFNAME1, true));
	pa_aa_notify(&pa.data, &eaa->aa);
	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa and apply");

	pa_aa_todelete(&eaa->aa);
	pa_aa_notify(&pa.data, &eaa->aa);
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa");

	/* Adding an excluded prefix, which should remove the current cp and address */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, &p1_excluded, valid, preferred, NULL, 0);
	/* That should trigger paa only */
	test_pa_random_push_prefix(&p1_2); // <-this one is in excluded
	sput_fail_unless(to_getfirst() == &pa.core.paa.to, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	sput_fail_unless(to_getfirst() == &pa.core.aaa.to, "Aaa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run aaa");

	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "No remaining timeout");

	/* Let's remove the excluded */
	iface.user->cb_prefix(iface.user, IFNAME1, &p1, NULL, valid, preferred, NULL, 0);
	/* paa is not run in this case */

	/* Now let's make paa accept a prefix (using authority bit) */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_authoritative(ap, true);
	pa_ap_notify(&pa.data, ap);

	//Running paa
	sput_fail_unless(to_getfirst() == &pa.core.paa.to, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	/* Now that ap suddenly come to our interface ! */
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	//Running paa
	sput_fail_unless(to_getfirst() == &pa.core.paa.to, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	//Running aaa, cp apply and aa apply
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run everything");

	cp = list_first_entry(&pa.data.cps, struct pa_cp, le);
	sput_fail_unless(!prefix_cmp(&cp->prefix, &p1_1), "Correct accepted prefix");
	sput_fail_unless(cp->authoritative == false, "Authoritative is false");
	sput_fail_unless(cp->advertised == true, "We advertises it");
	sput_fail_unless(cp->iface->do_dhcp, "We do dhcp");
	sput_fail_unless(cp->priority == PA_PRIORITY_AUTO_MIN, "We do dhcp");

	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);
	sput_fail_unless(to_getfirst() == &pa.core.paa.to, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");
	sput_fail_if(to_getfirst(), "No more schedule");

	/* Now let someone else start advertising another dp */
	edp = pa_edp_get(&pa.data, &p2, &rid_higher, true);
	pa_dp_set_lifetime(&edp->dp, preferred, valid);
	pa_dp_set_dhcp(&edp->dp, DHCP_DATA, DHCP_LEN);
	pa_dp_notify(&pa.data, &edp->dp);

	ap = pa_ap_get(&pa.data, &p2_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	res = to_run(2);
	sput_fail_unless(!res, "Run paa and aaa");

	cp2 = pa_cp_get(&pa.data, &p2_1, false);
	sput_fail_unless(cp2, "New cp created");
	if(cp2) {
		sput_fail_unless(!cp2->iface->designated, "Not designated on this iface");
		sput_fail_unless(!cp2->iface->do_dhcp, "Don't do dhcp anymore");
		sput_fail_unless(!cp2->advertised, "Do not advertise this one");
	}

	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	res = to_run(4);
	sput_fail_unless(!res && !to_getfirst(), "Run paa and aaa and apply");

	cp = pa_cp_get(&pa.data, &p1_1, false);
	cp2 = pa_cp_get(&pa.data, &p2_1, false);
	sput_fail_unless(cp && cp2, "Two cps");
	if(cp && cp2) {
		sput_fail_unless(cp2->iface->do_dhcp, "Doing dhcp now");
		sput_fail_unless(cp2->advertised, "Advertise cp2");
		sput_fail_unless(cp->advertised, "Advertise cp");
	}

	/* Now we are going to make the cp2 not advertised */
	ap = pa_ap_get(&pa.data, &p2_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	/* The router stops from beeing designated and stops advertising cp2 */
	sput_fail_unless(to_getfirst() == &pa.core.paa.to, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run paa");

	sput_fail_if(cp2->advertised, "cp2 not advertised");
	sput_fail_unless(cp->advertised, "cp advertised");
	sput_fail_unless(!cp2->iface->do_dhcp, "Not do dhcp anymore");

	/* Now we are going to change our rid */
	pa_flood_set_rid(&pa.data, &rid_lower);
	pa_flood_notify(&pa.data);
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run paa, aaa and local");

	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);

	sput_start_testing();

	sput_enter_suite("Prefix assignment tests"); /* optional */
	sput_run_test(test_pa_initial);
	sput_run_test(test_pa_ipv4);
	sput_run_test(test_pa_network);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
