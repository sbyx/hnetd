#ifndef L_LEVEL
#define L_LEVEL 7
#endif /* !L_LEVEL */

#include "hnetd.h"
#include "sput.h"
#include "smock.h"

#include "iface.h"
#include "pa.h"

int log_level = LOG_DEBUG;

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
		.iface = { .eui64_addr = {.s6_addr = { 0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00, PL_EUI64 }},
				.ip6_plen = 0,
} };

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

bool dncp_if_has_highest_id(__unused dncp o, __unused const char *ifname) {return true;};

/***************************************************** Data */

static struct pa_rid rid = { .id = {0x20} };
static struct pa_rid rid_higher = { .id = {0x30} };
static struct pa_rid rid_lower = { .id = {0x10} };

static struct prefix p1 = PL_P1;
static struct prefix p1_1 = PL_P1_01;
static struct prefix p1_2 = PL_P1_02;
static struct prefix p1_11 = PL_P1_11;
static struct prefix p1_24 = PL_P1_24;

static struct prefix p2 = PL_P2;
static struct prefix p2_1 = PL_P2_01;

static struct prefix p1_excluded = PL_P1_0;
static struct prefix p1_1_addr = PL_P1_01A;
static struct prefix p1_1_addr1 = PL_P1_01A1;
static struct prefix p1_1_addr2 = PL_P1_01A2;
static struct prefix p1_2_addr = PL_P1_02A;
static struct prefix pv4_1 = PL_PV4_1;
static struct prefix pv4_1_1 = PL_PV4_1_1;
static struct prefix pv4_1_f = PL_PV4_1_ff;

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
	struct pa_edp *edp;
	struct pa_cp *cp;
	hnetd_time_t when;
	int res;
	struct prefix otherv4 = PL_PV4b;

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

	fr_md5_push_prefix(&pv4_1); //The network address should not be used and pv4_1_1 should be used instead
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

	/* Testing changing uplink */
	fr_mask_md5 = false;
	iface.user->cb_ext4data(iface.user, PL_IFNAME2, NULL, 0);
	edp = pa_edp_get(&pa.data, &otherv4, &rid_higher, true); //another router advertises a different v4 prefix
	pa_dp_notify(&pa.data, &edp->dp);
	res = to_run(2); //Run PA and AA


	//Add a local connectivity again, shouldn' do anything
	iface.user->cb_ext4data(iface.user, PL_IFNAME2, PL_DHCP_DATA, PL_DHCP_LEN);

	//Destroy edp
	pa_dp_todelete(&edp->dp);
	pa_dp_notify(&pa.data, &edp->dp);
	to_run(5);

	ldp = pa_ldp_get(&pa.data, &pa.local.conf.v4_prefix, false);
	sput_fail_unless(ldp, "Found ldp");
	sput_fail_unless(!strcmp(ldp->iface->ifname, PL_IFNAME2), "Correct uplink");

	iface.user->cb_ext4data(iface.user, PL_IFNAME3, PL_DHCP_DATA, PL_DHCP_LEN);
	iface.user->cb_ext4data(iface.user, PL_IFNAME2, NULL, 0);
	to_run(5);

	ldp = pa_ldp_get(&pa.data, &pa.local.conf.v4_prefix, false);
	sput_fail_unless(ldp, "Found ldp");
	sput_fail_unless(!strcmp(ldp->iface->ifname, PL_IFNAME3), "Correct uplink");

	iface.user->cb_ext4data(iface.user, PL_IFNAME3, NULL, 0);
	res = to_run(6);
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

	fr_mask_md5 = true;

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
	fr_md5_push_prefix(&p1_2);
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
	fr_md5_push_prefix(&p1_11); //This one will be used
	sput_fail_unless(to_getfirst() == &pa.core.paa_to.t, "Paa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run paa");

	sput_fail_unless(to_getfirst() == &pa.core.aaa_to.t, "Aaa is to be run");
	res = to_run(1);
	sput_fail_unless(!res, "Run aaa");

	res = to_run(2);
	sput_fail_unless(!res && !to_getfirst(), "No remaining timeout");

	/* Tests for randomized selection */
	/* Let's invalidate that assignment */
	ap = pa_ap_get(&pa.data, &p1_11, &rid_higher, true);
	pa_ap_notify(&pa.data, ap);

	// Fill the pseudo random queue with invalid stuff
	int i;
	for(i = 0; i < PA_CORE_PSEUDORAND_TENTATIVES; i++)
		fr_md5_push_prefix(&p1_2); // <-this one is in excluded

	fr_mask_random = true;
	fr_random_push(19); //We want the 20'th available prefix in p1 that is not in excluded or p1_2. It is p1_24
	to_run(4);
	fr_mask_random = false;
	sput_fail_unless(!res && !to_getfirst(), "No remaining timeout");

	cp = btrie_first_down_entry(cp, &pa.data.cps, (btrie_key_t *)&p1_24, 64, be);
	sput_fail_unless(cp && !prefix_cmp(&cp->prefix, &p1_24), "Correct new prefix");
	/* End of tests for randomized selection */
	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

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

#define test_pa_check_cp(cp, p, auth, prio, adv) \
do { \
	sput_fail_unless(cp, "No CP");\
	if(cp) { \
		sput_fail_unless(!prefix_cmp(&cp->prefix, p), "Correct prefix"); \
		sput_fail_unless(cp->authoritative == auth, "Correct authoritative"); \
		sput_fail_unless(cp->priority == prio, "Correct priority"); \
		sput_fail_unless(cp->advertised == adv, "Correct advertised"); \
	} \
} while(0)

void test_pa_static()
{
	struct pa_ap *ap;
	struct pa_iface *i;
	struct pa_cp *cp;
	struct pa_static_prefix_rule sprule;

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
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, now_time + 100000 , now_time + 50000, NULL, 0);

	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	i = pa_iface_get(&pa.data, PL_IFNAME1, false);
	sput_fail_unless(i, "Iface was there");
	pa_ap_set_iface(ap, i);
	pa_ap_notify(&pa.data, ap);
	to_run(6);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PAD_PRIORITY_DEFAULT, false);

	pa_core_static_prefix_init(&sprule, NULL, &p1_1, true);
	sprule.rule.result.authoritative = true;
	sprule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &sprule.rule);
	to_run(1);

	sput_fail_unless(cp->authoritative, "Now authoritative");
	sput_fail_unless(cp->advertised, "Not advertised");

	pa_ap_todelete(ap); //Destroy the other ap
	pa_ap_notify(&pa.data, ap);

	to_run(4); //Run paa
	test_pa_check_cp(cp, &p1_1, true, PA_PRIORITY_DEFAULT, true);

	//Another AP will send an authoritative (bug situation).
	ap = pa_ap_get(&pa.data, &p1_2, &rid_lower, true);
	pa_ap_set_authoritative(ap, true);
	pa_ap_set_iface(ap, i);
	pa_ap_notify(&pa.data, ap);

	to_run(4); //Run PAA ,AAA and apply

	test_pa_check_cp(cp, &p1_1, true, PA_PRIORITY_DEFAULT, true); //Adv because designated
	sput_fail_unless(cp->applied, "Applied");

	pa_core_rule_del(&pa.core, &sprule.rule); //Remove authoritative assignment

	to_run(4); // Run PA, AA and apply

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true);

	//Test other mods

	//Soft mod should not change the prefix
	pa_core_static_prefix_init(&sprule, PL_IFNAME1, &p1_1, false);
	sprule.rule.result.authoritative = true;
	sprule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &sprule.rule);
	to_run(1);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true);
	pa_core_rule_del(&pa.core, &sprule.rule);
	to_run(4);

	//Reducing the priority should cause the rule to not be applied
	pa_core_static_prefix_init(&sprule, PL_IFNAME1, &p1_1, false);
	sprule.rule.result.authoritative = false;
	sprule.rule.result.priority = PA_PRIORITY_MIN;
	pa_core_rule_add(&pa.core, &sprule.rule);
	to_run(4);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true);

	//But it should override it once the ap is deleted
	pa_ap_todelete(ap); //Remove that ap
	pa_ap_notify(&pa.data, ap);
	to_run(4); // Run All

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true);

	//Now we delete the cp and watch the other cp be chosen
	cp->destroy(&pa.data, cp, (void *)1);
	to_run(4);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_MIN, true);

	pa_core_rule_del(&pa.core, &sprule.rule);
	to_run(4);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_MIN, true);

	//TERM
	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}


void test_pa_link_id()
{
	struct pa_ap *ap;
	struct pa_cp *cp;
	struct pa_link_id_rule lrule;

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
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, now_time + 100000 , now_time + 50000, NULL, 0);

	ap = pa_ap_get(&pa.data, &p1_1, &rid_lower, true);
	pa_ap_set_iface(ap, pa_iface_get(&pa.data, PL_IFNAME1, false));
	pa_ap_notify(&pa.data, ap);
	to_run(6);

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT, false);

	pa_core_link_id_init(&lrule, PL_IFNAME1, 2, 9, true); //To big to work
	lrule.rule.result.authoritative = true;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT, false); //No change
	pa_core_rule_del(&pa.core, &lrule.rule);

	pa_core_link_id_init(&lrule, PL_IFNAME2, 2, 4, true); //Bad interface
	lrule.rule.result.authoritative = true;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT, false); //No change
	pa_core_rule_del(&pa.core, &lrule.rule);

	pa_core_link_id_init(&lrule, PL_IFNAME1, 2, 4, false); //Shouldn't do anything cause not hard
	lrule.rule.result.authoritative = true;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT, false); //No change
	pa_core_rule_del(&pa.core, &lrule.rule);

	pa_core_link_id_init(&lrule, PL_IFNAME1, 2, 4, true); //Priority is not high enough
	lrule.rule.result.authoritative = false;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT, false); //No change
	pa_core_rule_del(&pa.core, &lrule.rule);

	pa_core_link_id_init(&lrule, PL_IFNAME1, 2, 8, true); //Priority is high enough
	lrule.rule.result.authoritative = false;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT + 1;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT + 1, true); //new prefix
	pa_core_rule_del(&pa.core, &lrule.rule);

	to_run(6);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be); //Keep the new one rid is higher
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true); //new prefix

	pa_ap_set_priority(ap, PA_PRIORITY_DEFAULT + 1);
	pa_ap_notify(&pa.data, ap);
	to_run(6);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be); //Other one has now better priority
	test_pa_check_cp(cp, &p1_1, false, PA_PRIORITY_DEFAULT + 1, true); //Adv cause designated

	pa_core_link_id_init(&lrule, PL_IFNAME1, 2, 8, true); //Priority is high enough
	lrule.rule.result.authoritative = true;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(5);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, true, PA_PRIORITY_DEFAULT, true); //Adv cause authoritative
	pa_core_rule_del(&pa.core, &lrule.rule);

	pa_ap_todelete(ap);
	pa_ap_notify(&pa.data, ap);

	pa_core_link_id_init(&lrule, PL_IFNAME1, 1, 8, false); //Priority is high enough
	lrule.rule.result.authoritative = false;
	lrule.rule.result.priority = PA_PRIORITY_DEFAULT + 2;
	pa_core_rule_add(&pa.core, &lrule.rule);
	to_run(1);
	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	test_pa_check_cp(cp, &p1_2, false, PA_PRIORITY_DEFAULT, true); //No change
	pa_core_rule_del(&pa.core, &lrule.rule);

	//TERM
	pa_stop(&pa);
	pa_term(&pa);
	sput_fail_unless(list_empty(&timeouts), "No more timeout");
}

void test_pa_iface_addr() {
	struct pa_cpl *cpl;
	struct pa_iface_addr a;
	struct in6_addr addr;
	struct pa_eaa *eaa;

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
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, now_time + 100000 , now_time + 50000, NULL, 0);
	fr_md5_push_prefix(&p1_1);
	to_run(6); //Do everything

	cpl = _pa_cpl(btrie_first_down_entry(&cpl->cp, &pa.data.cps, NULL, 0, be));
	sput_fail_unless(cpl, "Cpl exists");
	sput_fail_unless(!prefix_cmp(&cpl->cp.prefix, &p1_1), "Correct prefix");
	sput_fail_unless(cpl->laa, "Laa exists");
	memcpy(&addr, &iface.iface.eui64_addr, 16);
	memcpy(&addr, &p1_1.prefix, 8);
	sput_fail_unless(!memcmp(&addr, &cpl->laa->aa.address, 16), "Correct address");

	pa_core_iface_addr_init(&a, PL_IFNAME1, &p1_1_addr1.prefix, 64, NULL);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Proposed address is used
	sput_fail_unless(!memcmp(&p1_1_addr1.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);
	to_run(4); //The address remains
	sput_fail_unless(!memcmp(&p1_1_addr1.prefix, &cpl->laa->aa.address, 16), "Correct address");

	pa_core_iface_addr_init(&a, PL_IFNAME2, &p1_1_addr2.prefix, 64, NULL);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Bad ifname
	sput_fail_unless(!memcmp(&p1_1_addr1.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	pa_core_iface_addr_init(&a, NULL, &p1_1_addr2.prefix, 64, NULL);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Applyable to any interface
	sput_fail_unless(!memcmp(&p1_1_addr2.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	pa_core_iface_addr_init(&a, NULL, &p1_1_addr1.prefix, 63, NULL);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Mask too small
	sput_fail_unless(!memcmp(&p1_1_addr2.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	pa_core_iface_addr_init(&a, PL_IFNAME1, &p1_1_addr1.prefix, 64, &p2);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Invalid filter
	sput_fail_unless(!memcmp(&p1_1_addr2.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	pa_core_iface_addr_init(&a, PL_IFNAME1, &p1_1_addr1.prefix, 64, &p1);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Correct filter
	sput_fail_unless(!memcmp(&p1_1_addr1.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	//Add a eaa
	eaa = pa_eaa_get(&pa.data, &p1_1_addr1.prefix, &rid_higher, true);
	pa_eaa_set_iface(eaa, pa_iface_get(&pa.data, PL_IFNAME1, true));
	pa_aa_notify(&pa.data, &eaa->aa);
	to_run(4); //Go use storage address
	sput_fail_unless(!memcmp(&p1_1_addr2.prefix, &cpl->laa->aa.address, 16), "Correct address");

	pa_core_iface_addr_init(&a, PL_IFNAME1, &p1_1_addr1.prefix, 64, NULL);
	pa_core_iface_addr_add(&pa.core, &a);
	to_run(4); //Cannot use this one
	sput_fail_unless(!memcmp(&p1_1_addr2.prefix, &cpl->laa->aa.address, 16), "Correct address");

	pa_aa_todelete(&eaa->aa);
	pa_aa_notify(&pa.data, &eaa->aa);
	to_run(4);
	sput_fail_unless(!memcmp(&p1_1_addr1.prefix, &cpl->laa->aa.address, 16), "Correct address");
	pa_core_iface_addr_del(&pa.core, &a);

	//TERM
	pa_stop(&pa);
	pa_term(&pa);
}

void test_pa_plen()
{
	struct pa_cpl *cpl;

	//INIT
	uloop_init();
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = true;
	pa.local.conf.use_ula = false;
	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.iface.ip6_plen = 92;
	iface.iface.ip4_plen = 28;
	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, now_time + 100000 , now_time + 50000, NULL, 0);
	fr_md5_push_prefix(&p1_1);
	fr_md5_push_prefix(&p1_1_addr); //Because 92 len require a random address
	to_run(6); //Do everything

	cpl = _pa_cpl(btrie_first_down_entry(&cpl->cp, &pa.data.cps, NULL, 0, be));
	sput_fail_unless(cpl, "Cpl exists");
	sput_fail_unless(cpl->cp.prefix.plen == 92, "Custom prefix length");

	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1, NULL, 0 , 0, NULL, 0);
	iface.user->cb_ext4data(iface.user, PL_IFNAME2, PL_DHCP_DATA, PL_DHCP_LEN);
	fr_md5_push_prefix(&pv4_1_f);
	fr_md5_push_prefix(&pv4_1_f);
	to_run(6);
	cpl = _pa_cpl(btrie_first_down_entry(&cpl->cp, &pa.data.cps, NULL, 0, be));
	sput_fail_unless(cpl, "Cpl exists");
	sput_fail_unless(cpl->cp.prefix.plen == 124, "Custom prefix length");

	//TERM
	pa_stop(&pa);
	pa_term(&pa);
	iface.iface.ip6_plen = 0;
	iface.iface.ip4_plen = 0;
}

void test_pa_takeover()
{
	struct pa_cp *cp;
	struct pa_ap *ap;

	fr_mask_md5 = true;
	fr_mask_random = false;

	//INIT
	uloop_init();
	pa_init(&pa, NULL);
	pa.local.conf.use_ipv4 = false;
	pa.local.conf.use_ula = false;

	pa_flood_set_flooddelays(&pa.data, PA_TEST_FLOOD, PA_TEST_FLOOD_LL);
	pa_flood_set_rid(&pa.data, &rid);
	pa_flood_notify(&pa.data);
	pa_start(&pa);

	iface.user->cb_intiface(iface.user, PL_IFNAME1, true);

	//Let's add a /64 that is used by somebody else
	ap = pa_ap_get(&pa.data, &p1_1, &rid_higher, true);
	pa_ap_set_priority(ap, PA_PRIORITY_DEFAULT);
	pa_ap_notify(&pa.data, ap);
	iface.user->cb_prefix(iface.user, PL_IFNAME1, &p1_1, NULL, now_time + 100000 , now_time + 50000, NULL, 0);
	fr_md5_push_prefix(&p1_1);
	fr_md5_push_prefix(&p1_1_addr);
	to_run(6); //Do everything

	cp = btrie_first_down_entry(cp, &pa.data.cps, NULL, 0, be);
	sput_fail_unless(cp, "CP created");
	struct prefix p = PL_P1_01;
	p.plen = 96;
	sput_fail_if(prefix_cmp(&p, &cp->prefix), "Correct prefix");

	//TERM
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
	sput_run_test(test_pa_network);
	sput_run_test(test_pa_static);
	sput_run_test(test_pa_link_id);
	sput_run_test(test_pa_iface_addr);
	sput_run_test(test_pa_plen);
	sput_run_test(test_pa_takeover);
	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
