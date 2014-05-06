#ifndef L_LEVEL
#define L_LEVEL 7
#endif /* !L_LEVEL */

#include "hnetd.h"
#include "sput.h"
#include "smock.h"

#include "iface.h"
#include "pa.h"

/**************************************************** Tested structures */
struct pa pa;

/***************************************************** Masking time */

/* Make sure timeout cancels are called only on scheduled timeouts */
#define FU_PARANOID_TIMEOUT_CANCEL

#include "fake_uloop.h"
#define now_time hnetd_time()
#define to_check(to, when) ((to)->pending && (_to_time(&(to)->time) == (when)))
#define to_run(n) fu_loop(n)
#define to_getfirst() fu_next()

#include "fake_random.h"

/***************************************************** Mask for pa.c */

#include "prefixes_library.h"

static struct pa_test_iface {
	struct iface_user *user;
	struct iface iface;
} iface = { .user = NULL,
		.iface = { .eui64_addr = {
				.s6_addr = { 0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00, PL_EUI64 }
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

/* Masked sources */
#include "prefix_utils.c"
#include "pa_timer.c"
#include "pa.c"
#include "pa_core.c"
#include "pa_local.c"
#include "pa_data.c"

/***************************************************** Data */

static struct pa_rid rid = { .id = {0x20} };
static struct pa_rid rid_higher = { .id = {0x30} };
static struct pa_rid rid_lower = { .id = {0x10} };

static struct prefix p1 = PL_P1;
static struct prefix p1_1 = PL_P1_01;
static struct prefix p1_2 = PL_P1_02;

static struct prefix p2 = PL_P2;
static struct prefix p2_1 = PL_P2_01;

static struct prefix p1_excluded = PL_P1_0;
static struct prefix p1_1_addr = PL_P1_01A;
static struct prefix p1_2_addr = PL_P1_02A;
static struct prefix pv4_1 = PL_PV4_1;
static struct prefix pv4_1_1 = PL_PV4_1_1;

#define PA_TEST_FLOOD 1000
#define PA_TEST_FLOOD_LL 100

/***************************************************** Tests */
void test_pa_initial()
{
	struct pa_cp *cp;
	hnetd_time_t when;

	fr_mask_md5 = true;

	uloop_init();
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
	sput_fail_unless(to_check(&pa.core.paa_to.t, now_time + PA_TEST_FLOOD), "Correct paa timeout");
	sput_fail_unless(to_check(&pa.core.aaa_to.t, now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR), "Correct aaa timeout");
	sput_fail_unless(to_check(&pa.local.t.t, now_time + PA_TEST_FLOOD), "Correct local timeout");

	sput_fail_unless(!to_run(3) && !to_getfirst(), "Run three timeouts");

        set_hnetd_time(hnetd_time() + 10000);

	/* Create a new internal interface */
	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	sput_fail_unless(to_check(&pa.core.paa_to.t, now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR), "Correct paa timeout");
	sput_fail_unless(!to_run(1) && !to_getfirst(), "Run one timeouts");

	/* Create a new ldp */
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, now_time + 100000, now_time + 50000, NULL, 0);
	sput_fail_unless(to_check(&pa.core.paa_to.t, now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR), "Correct paa timeout");
	sput_fail_unless(to_check(&pa.local.t.t, now_time + PA_LOCAL_MIN_DELAY), "Correct paa timeout");
	when = now_time + PA_TEST_FLOOD / PA_CORE_DELAY_FACTOR + 2*PA_TEST_FLOOD;

	fr_md5_push_prefix(&p1_1);
	sput_fail_unless(!to_run(2), "Run two timeouts (remains the new cp apply and aaa)");

	sput_fail_unless(to_check(&pa.core.aaa_to.t, now_time + PA_TEST_FLOOD_LL / PA_CORE_DELAY_FACTOR), "Correct aaa timeout");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "One cp");
	if(cp) {
		sput_fail_unless(cp->type == PA_CPT_L, "CP local");
		sput_fail_unless(to_check(&cp->apply_to, when), "Correct apply to");
		sput_fail_unless(!prefix_cmp(&p1_1, &cp->prefix), "Correct cp prefix");
	}
	sput_fail_unless(!to_run(1), "Run aaa");

	sput_fail_unless(_pa_cpl(cp)->laa, "laa created");
	if(_pa_cpl(cp)->laa) {
		sput_fail_unless(to_check(&_pa_cpl(cp)->laa->apply_to, now_time + 0), "Correct laa timeout");
	}
	//sput_fail_unless(!to_run(2) && !to_getfirst(), "Apply cp and laa");
	to_run(100);

	/* Removing dp */
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, 0, 0, NULL, 0);
	sput_fail_unless(!to_run(2) && !to_getfirst(), "Run paa and local");
	iface.user->cb_intiface(iface.user, PL_IFNAME1, false);
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

	fr_mask_md5 = true;

	uloop_init();
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = true;
	pa.local.conf.use_ula = false;

	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	iface.user->cb_ext4data(iface.user, PL_IFNAME2, PL_DHCP_DATA, PL_DHCP_LEN);

	sput_fail_unless(to_check(&pa.local.t.t, now_time + PA_TEST_FLOOD), "Correct local timeout");
	when = now_time + PA_TEST_FLOOD + 2*PA_TEST_FLOOD;
	sput_fail_unless(!to_run(3), "Run paa, aaa and local");
	sput_fail_unless(to_check(&pa.local.t.t, when), "Correct local timeout");
	sput_fail_unless(to_getfirst() == &pa.local.t.t, "Local to be run");
	res = to_run(1);
	sput_fail_if(res, "Correctly run");

	ldp = pa.local.ipv4.ldp;
	sput_fail_unless(ldp, "Generated ipv4 prefix");
	if(!ldp)
		return;

	sput_fail_unless(!prefix_cmp(&ldp->dp.prefix, &pa.local.conf.v4_prefix), "Correct v4 prefix");
	sput_fail_unless(ldp->iface != NULL, "IPv4 must have an interface");
	if(ldp->iface) {
		sput_fail_unless(!strcmp(PL_IFNAME2, ldp->iface->ifname), "Correct ipv4 interface");
	}

	fr_md5_push_prefix(&pv4_1);
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t && !to_run(1), "Run paa");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "One cp");
	if(cp) {
		sput_fail_unless(cp->type == PA_CPT_L, "Local cp");
		sput_fail_unless(!prefix_cmp(&pv4_1, &cp->prefix), "Correct cp prefix");
	}

	fr_md5_push_prefix(&pv4_1_1);
	sput_fail_unless(to_getfirst() == &pa.core.aaa_to.t && !to_run(1), "Run aaa");
	sput_fail_unless(_pa_cpl(cp)->laa, "Created laa");
	if(_pa_cpl(cp)->laa)
		sput_fail_unless(!memcmp(&_pa_cpl(cp)->laa->aa.address, &pv4_1_1.prefix, sizeof(struct in6_addr)), "Correct ipv4 laa");

	sput_fail_unless(!to_run(2), "Run cp and laa apply");


	/* Renew ipv4 dp validity */
	sput_fail_unless(to_getfirst() == &pa.local.t.t && !to_run(1), "Renew");

	/* Test if the same address is used again */
	iface.user->cb_intiface(iface.user, PL_IFNAME1, false);
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");
	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	res = to_run(2);
	sput_fail_unless(!res, "Run paa and laa");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "One cp");
	if(cp) {
		sput_fail_unless(cp->type == PA_CPT_L, "Local cp");
		sput_fail_unless(!prefix_cmp(&pv4_1, &cp->prefix), "Correct cp prefix");
	}
	sput_fail_unless(_pa_cpl(cp)->laa, "Created laa");
	if(_pa_cpl(cp)->laa)
		sput_fail_unless(!memcmp(&_pa_cpl(cp)->laa->aa.address, &pv4_1_1.prefix, sizeof(struct in6_addr)), "Correct ipv4 laa");

	res = to_run(2);
	sput_fail_unless(!res, "Apply cp and laa");

	iface.user->cb_ext4data(iface.user, PL_IFNAME2, NULL, 0);
	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "Remove IPv4 connectivity");

	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

void test_pa_checkcpl(struct pa_cpl *cpl, const struct prefix *p, const struct in6_addr *addr, const char *ifname)
{
	sput_fail_unless(!p || !prefix_cmp(&cpl->cp.prefix, p), "Correct prefix");
	sput_fail_unless(!ifname || (cpl->iface && !strcmp(cpl->iface->ifname, ifname)), "Correct ifname");

	sput_fail_unless(cpl->laa, "Assigned address");
	if(cpl->laa)
		sput_fail_unless(!addr || !memcmp(addr, &cpl->laa->aa.address, sizeof(struct in6_addr)), "Correct address");
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
	uloop_init();
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = false;
	pa.local.conf.use_ula = false;
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	valid = now_time + 100000;
	preferred = now_time + 50000;
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, valid , preferred, NULL, 0);

	fr_md5_push_prefix(&p1_1);
	res = to_run(6);
	sput_fail_unless(!res && !to_getfirst(), "Run and apply everything");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_checkcpl(_pa_cpl(cp), &p1_1, &p1_1_addr.prefix, PL_IFNAME1);

	/* Lower ID, Lower priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_notify(&pa.data, ap);
	sput_fail_unless(!to_run(1) && !to_getfirst(), "Run paa");
	sput_fail_if(btrie_empty(&pa.data.cps), "The cp remains");
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	/* Higher ID, Lower priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_notify(&pa.data, ap);
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run paa");
	sput_fail_if(btrie_empty(&pa.data.cps), "The cp remains");
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	/* Lower ID, higher priority */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MAX);
	pa_ap_notify(&pa.data, ap);
	fr_md5_push_prefix(&p1_1); /* This one should be ignored and the second one should be chosen */
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");
	sput_fail_if(btrie_empty(&pa.data.cps), "The cp remains");
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa and apply");
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_checkcpl(_pa_cpl(cp), &p1_2, &p1_2_addr.prefix, PL_IFNAME1);
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	/* Now let's delete the address */
	eaa = pa_eaa_get(&pa.data, &p1_2_addr.prefix, &rid_higher, true);
	pa_eaa_set_iface(eaa, pa_iface_get(&pa.data, PL_IFNAME1, true));
	pa_aa_notify(&pa.data, &eaa->aa);
	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa and apply");

	pa_aa_todelete(&eaa->aa);
	pa_aa_notify(&pa.data, &eaa->aa);
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run aaa");

	/* Adding an excluded prefix, which should remove the current cp and address */
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, &p1_excluded, valid, preferred, NULL, 0);
	/* That should trigger paa only */
	fr_md5_push_prefix(&p1_2); // <-this one is in excluded
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	sput_fail_unless(to_getfirst() == &pa.core.aaa_to.t, "Aaa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run aaa");

	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "No remaining timeout");

	/* Let's remove the excluded */
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, valid, preferred, NULL, 0);
	/* paa is not run in this case */

	/* Now let's make paa accept a prefix (using authority bit) */
	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_authoritative(ap, true);
	pa_ap_notify(&pa.data, ap);

	//Running paa
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	/* Now that ap suddenly come to our interface ! */
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, PL_IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	//Running paa
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	//Running aaa, cp apply and aa apply
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run everything");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(!prefix_cmp(&cp->prefix, &p1_1), "Correct accepted prefix");
	sput_fail_unless(cp->authoritative == false, "Authoritative is false");
	sput_fail_unless(cp->advertised == true, "We advertises it");
	sput_fail_unless(_pa_cpl(cp)->iface->do_dhcp, "We do dhcp");
	sput_fail_unless(cp->priority == PA_PRIORITY_AUTO_MIN, "We do dhcp");

	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");
	sput_fail_if(to_getfirst(), "No more schedule");

	/* Now let someone else start advertising another dp */
	edp = pa_edp_get(&pa.data, &p2, &rid_higher, true);
	pa_dp_set_lifetime(&edp->dp, preferred, valid);
	pa_dp_set_dhcp(&edp->dp, PL_DHCP_DATA, PL_DHCP_LEN);
	pa_dp_notify(&pa.data, &edp->dp);

	ap = pa_ap_get(&pa.data, &p2_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, PL_IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	res = to_run(2);
	sput_fail_unless(!res, "Run paa and aaa");

	cp2 = pa_cp_get(&pa.data, &p2_1, PA_CPT_L, false);
	sput_fail_unless(cp2, "New cp created");
	if(cp2) {
		sput_fail_unless(!_pa_cpl(cp2)->iface->designated, "Not designated on this iface");
		sput_fail_unless(!_pa_cpl(cp2)->iface->do_dhcp, "Don't do dhcp anymore");
		sput_fail_unless(!cp2->advertised, "Do not advertise this one");
	}

	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	res = to_run(4);
	sput_fail_unless(!res && !to_getfirst(), "Run paa and aaa and apply");

	cp = pa_cp_get(&pa.data, &p1_1, PA_CPT_L, false);
	cp2 = pa_cp_get(&pa.data, &p2_1, PA_CPT_L, false);
	sput_fail_unless(cp && cp2, "Two cps");
	if(cp && cp2) {
		sput_fail_unless(_pa_cpl(cp2)->iface->do_dhcp, "Doing dhcp now");
		sput_fail_unless(cp2->advertised, "Advertise cp2");
		sput_fail_unless(cp->advertised, "Advertise cp");
	}

	/* Now we are going to make the cp2 not advertised */
	ap = pa_ap_get(&pa.data, &p2_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_AUTO_MIN);
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, PL_IFNAME1, true));
	pa_ap_notify(&pa.data, ap);

	/* The router stops from beeing designated and stops advertising cp2 */
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res && !to_getfirst(), "Run paa");

	sput_fail_if(cp2->advertised, "cp2 not advertised");
	sput_fail_unless(cp->advertised, "cp advertised");
	sput_fail_unless(!_pa_cpl(cp2)->iface->do_dhcp, "Not do dhcp anymore");

	/* Now we are going to change our rid */
	pa_flood_set_rid(&pa.data, &rid_lower);
	pa_flood_notify(&pa.data);
	res = to_run(3);
	sput_fail_unless(!res && !to_getfirst(), "Run paa, aaa and local");

	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

void test_pa_static()
{
	hnetd_time_t valid, preferred;
	struct pa_ap *ap;
	struct pa_iface *i;
	struct pa_cp *cp;
	int res;

	//INIT
	uloop_init();
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = false;
	pa.local.conf.use_ula = false;
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	//Add interface and prefix
	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	valid = now_time + 100000;
	preferred = now_time + 50000;
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, valid , preferred, NULL, 0);

	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	i = pa_iface_get(&pa.data, PL_IFNAME1, false);
	sput_fail_unless(i, "Iface was there");
	pa_ap_set_iface(ap, i);
	pa_ap_notify(&pa.data, ap);
	res = to_run(6);
	sput_fail_unless(!res && !to_getfirst(), "Run and apply everything");

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "CP created");
	if(cp) {
		sput_fail_unless(!prefix_cmp(&cp->prefix, &p1_1), "Correct prefix");
		sput_fail_unless(!cp->authoritative, "Not authoritative");
	}

	pa_core_static_prefix_add(&pa.core, &p1_1, i); //Put existing as authoritative
	sput_fail_unless(cp->authoritative, "Now authoritative");
	sput_fail_unless(!cp->advertised, "Not advertised");

	pa_ap_todelete(ap); //Destroy the other ap
	pa_ap_notify(&pa.data, ap);

	res = to_run(4); //Run paa
	sput_fail_unless(cp->authoritative, "Now authoritative");
	sput_fail_unless(cp->advertised, "Advertised");

	//Another AP will send an authoritative (bug situation).
	ap = pa_ap_get(&pa.data, &p1_2, &rid_higher, true);
	pa_ap_set_authoritative(ap, true);
	pa_ap_set_iface(ap, i);
	pa_ap_notify(&pa.data, ap);

	to_run(4); //Run PAA ,AAA and apply

	sput_fail_unless(cp->authoritative, "Authoritative");
	sput_fail_unless(cp->advertised, "Advertised");
	sput_fail_unless(cp->applied, "Applied");

	pa_core_static_prefix_remove(&pa.core, &p1_1, i); //Remove authoritative assignment

	to_run(4); // Run PA, AA and apply

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "CP created");
	if(cp) {
		sput_fail_unless(!prefix_cmp(&cp->prefix, &p1_2), "Correct prefix");
		sput_fail_unless(!cp->authoritative, "Not authoritative");
	}

	pa_ap_todelete(ap); //Remove that ap
	pa_ap_notify(&pa.data, ap);

	to_run(1); // Run PA

	pa_core_static_prefix_add(&pa.core, &p1_1, i); //Create an authoritative again

	to_run(4); // Run All

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "CP created");
	if(cp) {
		sput_fail_unless(!prefix_cmp(&cp->prefix, &p1_1), "Correct prefix");
		sput_fail_unless(cp->authoritative, "Authoritative");
		sput_fail_unless(cp->advertised, "Advertised");
		sput_fail_unless(cp->applied, "Applied");
	}


	//TERM
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
	sput_run_test(test_pa_static);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
