
#include <stdio.h>

#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */
#define L_LEVEL 7

#include <string.h>

#include "hnetd.h"
#include "sput.h"
#include "smock.h"
#include "pa_data.h"
#include "pa.h"

static struct pa pa;
#define data (&pa.data)

static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };
static struct prefix p1_1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x10}},
		.plen = 60 };

static struct pa_rid ridnull = {};
static struct pa_rid rid1 = { .id = {0x20} };
static struct pa_rid rid2 = { .id = {0x30} };

#define DHCP_DATA "DHCP_DATA"
#define DHCP_LEN strlen(DHCP_DATA)

#define IFNAME1 "iface.1"
#define IFNAME2 "iface.2"
#define IFNAMETOOLONG "This ifname is so long it could run all around yo' mama."

/**********************************************************/
/************ Callbacks checkers **************************/
/**********************************************************/

#define PADT_CB_FLOOD 0x01
#define PADT_CB_IPV4  0x02
#define PADT_CB_IFS   0x04
#define PADT_CB_DPS   0x08
#define PADT_CB_APS   0x10
#define PADT_CB_CPS   0x20
#define PADT_CB_AAS   0x40

static uint8_t last_cb;
static uint32_t last_flags;

#define padt_cb(cb, flags) do {\
	sput_fail_unless(!last_cb, "No previous unchecked callback"); \
	printf("Set flags %x\n", flags); \
	last_cb = cb; \
	last_flags = flags; } while(0)

static void padt_flood_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_flood *flood, uint32_t flags)
{
	padt_cb(PADT_CB_FLOOD, flags);
}
static void padt_ipv4_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_ipv4 *ipv4, uint32_t flags)
{
	padt_cb(PADT_CB_IPV4, flags);
}
static void padt_ifs_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_iface *iface, uint32_t flags)
{
	padt_cb(PADT_CB_IFS, flags);
}
static void padt_dps_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_dp *dp, uint32_t flags)
{
	padt_cb(PADT_CB_DPS, flags);
}
static void padt_aps_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_ap *ap, uint32_t flags)
{
	padt_cb(PADT_CB_APS, flags);
}
static void padt_cps_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_cp *cp, uint32_t flags)
{
	padt_cb(PADT_CB_CPS, flags);
}
static void padt_aas_cb(__attribute__((unused))struct pa_data_user *user,
		__attribute__((unused))struct pa_aa *aa, uint32_t flags)
{
	padt_cb(PADT_CB_AAS, flags);
}

static struct pa_data_user data_user = {
		.flood = padt_flood_cb,
		.ipv4 = padt_ipv4_cb,
		.ifs = padt_ifs_cb,
		.dps = padt_dps_cb,
		.aps = padt_aps_cb,
		.cps = padt_cps_cb,
		.aas = padt_aas_cb
};

static void padt_check_cb(uint8_t callback, uint32_t flags)
{
	sput_fail_unless((callback) == last_cb, "padt_check_cb correct function");
	sput_fail_unless((flags) == last_flags, "padt_check_cb correct flags");
	printf("Check flags %x %x\n", last_flags, flags);
	last_cb = 0;
	last_flags = 0;
}

/**********************************************************/
/************ Structure content checkers ******************/
/**********************************************************/

#define padt_check_scalar(object, value) \
			sput_fail_unless(value == object->value, #object" check "#value)
#define padt_check_other(test, object, value) \
			sput_fail_unless(test,  #object" check "#value)

void padt_check_iface(struct pa_iface *iface, const char *ifname,
		bool internal, bool do_dhcp, bool is_ipv4_uplink, size_t sp_count)
{
	padt_check_other(!strcmp(iface->ifname, ifname), iface, ifname);
	padt_check_scalar(iface, internal);
	padt_check_scalar(iface, do_dhcp);
	padt_check_scalar(iface, is_ipv4_uplink);
	padt_check_scalar(iface, sp_count);
}

void padt_check_dp(struct pa_dp *dp, struct prefix *p,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		size_t dhcp_len, void *dhcp_data, bool local)
{
	padt_check_other(!prefix_cmp(p, &dp->prefix), dp, prefix);
	padt_check_scalar(dp, local);
	padt_check_scalar(dp, valid_until);
	padt_check_scalar(dp, preferred_until);
	if(dhcp_len)
		padt_check_other(dp->dhcp_len == dhcp_len &&
				!memcmp(dhcp_data, dp->dhcp_data, dhcp_len), dp, dhcp_data);
	else
		padt_check_other(dp->dhcp_len == 0 && dp->dhcp_data == NULL,
				dp, dhcp_data);
}

void padt_check_ldp(struct pa_ldp *ldp, struct pa_iface *iface,
		struct prefix *excluded)
{
	padt_check_scalar(ldp, iface);
	if(excluded)
		padt_check_other(!prefix_cmp(excluded, &ldp->excluded.excluded),
				ldp, excluded);
	else
		padt_check_other(!ldp->excluded.valid, ldp, excluded);
}

void padt_check_edp(struct pa_edp *edp, struct pa_rid *rid)
{
	padt_check_other(!PA_RIDCMP(rid, &edp->rid), edp, rid);
}

void padt_check_ap(struct pa_ap *ap, struct prefix *p,
		struct pa_rid *rid, bool authoritative,
		uint8_t priority, struct pa_iface *iface)
{
	padt_check_other(!prefix_cmp(p, &ap->prefix), ap, prefix);
	padt_check_other(!PA_RIDCMP(rid, &ap->rid), ap, rid);
	padt_check_scalar(ap, authoritative);
	padt_check_scalar(ap, priority);
	padt_check_scalar(ap, iface);
}

void padt_check_cp(struct pa_cp *cp, struct prefix *p,
		bool advertised, bool applied, bool authoritative,
		uint8_t priority, struct pa_iface *iface, struct pa_dp *dp,
		struct pa_data *pa_data, struct pa_laa *laa)
{
	padt_check_other(!prefix_cmp(p, &cp->prefix), cp, prefix);
	padt_check_scalar(cp, advertised);
	padt_check_scalar(cp, applied);
	padt_check_scalar(cp, authoritative);
	padt_check_scalar(cp, priority);
	padt_check_scalar(cp, iface);
	padt_check_scalar(cp, dp);
	padt_check_scalar(cp, laa);
	padt_check_scalar(cp, pa_data);
}

void padt_check_aa(struct pa_aa *aa, struct in6_addr *address,
		bool local)
{
	padt_check_other(!memcmp(address, &aa->address,
			sizeof(struct in6_addr)), aa, address);
	padt_check_scalar(aa, local);
}

void padt_check_laa(struct pa_laa *laa, struct pa_cp *cp,
		bool applied)
{
	padt_check_scalar(laa, cp);
	padt_check_scalar(laa, applied);
}

void padt_check_eaa(struct pa_eaa *eaa, struct pa_rid *rid,
		struct pa_iface *iface)
{
	padt_check_other(!PA_RIDCMP(rid, &eaa->rid), eaa, rid);
	padt_check_scalar(eaa, iface);
}

void padt_check_flood(struct pa_flood *flood, struct pa_rid *rid,
		hnetd_time_t flooding_delay, hnetd_time_t flooding_delay_ll)
{
	padt_check_other(!PA_RIDCMP(rid, &flood->rid), flood, rid);
	padt_check_scalar(flood, flooding_delay);
	padt_check_scalar(flood, flooding_delay_ll);
}

void padt_check_ipv4(struct pa_ipv4 *ipv4, struct pa_iface *iface,
		size_t dhcp_len, void *dhcp_data)
{
	padt_check_scalar(ipv4, iface);
	if(dhcp_len)
		padt_check_other(ipv4->dhcp_len == dhcp_len &&
				!memcmp(dhcp_data, ipv4->dhcp_data, dhcp_len), dp, dhcp_data);
	else
		padt_check_other(ipv4->dhcp_len == 0 && ipv4->dhcp_data == NULL,
				dp, dhcp_data);
}

void padt_check_sp(struct pa_sp *sp, struct prefix *p,
		struct pa_iface *iface)
{
	padt_check_other(!prefix_cmp(p, &sp->prefix), sp, prefix);
	padt_check_scalar(sp, iface);
}

void pa_data_test_iface()
{
	struct pa_iface *iface, *iface2, *iter;
	iface = pa_iface_get(data, IFNAME1, false);
	sput_fail_if(iface, "Do not create");
	iface = pa_iface_get(data, IFNAME1, true);
	pa_iface_notify(data, iface);
	pa_iface_notify(data, iface); /* Should not notify */
	padt_check_iface(iface, IFNAME1, false, false, false, 0);
	padt_check_cb(PADT_CB_IFS, PADF_IF_CREATED);

	pa_iface_set_dodhcp(iface, false);
	pa_iface_notify(data, iface);

	pa_iface_set_dodhcp(iface, true);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_DODHCP);
	padt_check_iface(iface, IFNAME1, false, true, false, 0);

	pa_iface_set_internal(iface, false);
	pa_iface_notify(data, iface);

	pa_iface_set_internal(iface, true);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_INTERNAL);
	padt_check_iface(iface, IFNAME1, true, true, false, 0);

	iface2 = pa_iface_get(data, IFNAMETOOLONG, true);
	sput_fail_if(iface2, "Ifname too long");

	iface2 = pa_iface_get(data, IFNAME1, false);
	sput_fail_unless(iface == iface2, "Same iface");
	iface2 = pa_iface_get(data, IFNAME2, false);
	sput_fail_if(iface2, "Do not create");
	iface2 = pa_iface_get(data, IFNAME2, true);
	padt_check_iface(iface2, IFNAME2, false, false, false, 0);
	pa_iface_notify(data, iface2);
	padt_check_cb(PADT_CB_IFS, PADF_IF_CREATED);
	bool first = true;
	pa_for_each_iface(iter, data) {
		if(first) {
			sput_fail_unless(iter == iface2, "New iface");
			first = false;
		} else {
			sput_fail_unless(iter == iface, "First iface");
		}
	}

	pa_iface_todelete(iface);
	pa_iface_set_dodhcp(iface, false);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_DODHCP | PADF_IF_TODELETE);

	pa_for_each_iface(iter, data) {
			sput_fail_unless(iter == iface2, "Only remaining iface");
	}
	pa_iface_set_internal(iface2, true);
	pa_iface_todelete(iface2);
	pa_iface_notify(data, iface2);
	padt_check_cb(PADT_CB_IFS, PADF_IF_INTERNAL | PADF_IF_TODELETE);

	pa_for_each_iface(iter, data) {
		sput_fail_if(1, "Should not be any iface");
	}
}

void pa_data_test_dp()
{
	struct pa_dp *dp;
	struct pa_ldp *ldp, *ldp_i;
	ldp = pa_ldp_get(data, &p1_1, false);
	sput_fail_if(ldp, "Do not create");

	ldp = pa_ldp_get(data, &p1_1, true);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_CREATED);
	padt_check_dp(&ldp->dp, &p1_1, 0, 0, 0, NULL, true);

	pa_dp_set_lifetime(&ldp->dp, 100, 1000);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_LIFETIME);
	padt_check_dp(&ldp->dp, &p1_1, 1000, 100, 0, NULL, true);

	pa_dp_set_dhcp(&ldp->dp, DHCP_DATA, DHCP_LEN);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_DHCP);
	padt_check_dp(&ldp->dp, &p1_1, 1000, 100, DHCP_LEN, DHCP_DATA, true);
	padt_check_ldp(ldp, NULL, NULL);

	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	pa_ldp_set_iface(ldp, iface);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_LDP_IFACE);
	padt_check_dp(&ldp->dp, &p1_1, 1000, 100, DHCP_LEN, DHCP_DATA, true);
	padt_check_ldp(ldp, iface, NULL);

	pa_for_each_ldp_in_iface(ldp_i, iface) {
		sput_fail_unless(ldp_i == ldp, "Ldp in iface");
	}

	pa_ldp_set_excluded(ldp, &p1_1);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_LDP_EXCLUDED);
	padt_check_dp(&ldp->dp, &p1_1, 1000, 100, DHCP_LEN, DHCP_DATA, true);
	padt_check_ldp(ldp, iface, &p1_1);

	pa_ldp_set_iface(ldp, NULL);
	pa_ldp_set_excluded(ldp, NULL);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_LDP_EXCLUDED | PADF_LDP_IFACE);
	padt_check_dp(&ldp->dp, &p1_1, 1000, 100, DHCP_LEN, DHCP_DATA, true);
	padt_check_ldp(ldp, NULL, NULL);

	struct pa_edp *edp;
	edp = pa_edp_get(data, &p1_1, &rid1, false);
	sput_fail_if(edp, "Do not create");

	edp = pa_edp_get(data, &p1_1, &rid1, true);
	pa_dp_notify(data, &edp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_CREATED);
	padt_check_dp(&edp->dp, &p1_1, 0, 0, 0, NULL, false);
	padt_check_edp(edp, &rid1);

	pa_for_each_dp(dp, data) {
		if(dp->local)
			sput_fail_unless(dp == &ldp->dp, "Local one");
		else
			sput_fail_unless(dp == &edp->dp, "Distant one");
	}

	pa_dp_todelete(&edp->dp);
	pa_dp_notify(data, &edp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_TODELETE);
	pa_for_each_dp(dp, data) {
		sput_fail_unless(dp == &ldp->dp, "Local one");
	}

	pa_dp_todelete(&ldp->dp);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_TODELETE);
	pa_for_each_dp(dp, data) {
		sput_fail_unless(1, "No dp remaining");
	}

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_ap()
{
	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	struct pa_iface *iface2 = pa_iface_get(data, IFNAME2, true);
	struct pa_ap *ap, *ap2, *ap_i;

	ap = pa_ap_get(data, &p1, &rid1, false);
	sput_fail_if(ap, "Do not create");

	ap = pa_ap_get(data, &p1, &rid1, true);
	pa_ap_set_iface(ap, iface);

	sput_fail_unless(ap == pa_ap_get(data, &p1, &rid1, true), "No duplicate ap");
	sput_fail_if(pa_ap_get(data, &p1_1, &rid1, false), "No such ap");
	sput_fail_unless((ap2 = pa_ap_get(data, &p1, &rid2, true)) != ap, "Create new ap for different rid");

	pa_ap_notify(data, ap);
	padt_check_cb(PADT_CB_APS, PADF_AP_CREATED | PADF_AP_IFACE);
	padt_check_ap(ap, &p1, &rid1, 0, PA_PRIORITY_DEFAULT, iface);

	pa_ap_notify(data, ap2);
	padt_check_cb(PADT_CB_APS, PADF_AP_CREATED);
	padt_check_ap(ap2, &p1, &rid2, 0,  PA_PRIORITY_DEFAULT, NULL);

	pa_ap_set_authoritative(ap, false);
	pa_ap_set_priority(ap, PA_PRIORITY_DEFAULT);
	pa_ap_notify(data, ap);

	pa_ap_set_authoritative(ap, true);
	pa_ap_notify(data, ap);
	padt_check_cb(PADT_CB_APS, PADF_AP_AUTHORITY);
	padt_check_ap(ap, &p1, &rid1, true, PA_PRIORITY_DEFAULT, iface);

	pa_ap_set_priority(ap, 1);
	pa_ap_notify(data, ap);
	padt_check_cb(PADT_CB_APS, PADF_AP_PRIORITY);
	padt_check_ap(ap, &p1, &rid1, true, 1, iface);

	bool first = true;
	pa_for_each_ap(ap_i, data) {
		if(first) {
			sput_fail_unless(ap_i == ap, "First ap");
			first = false;
		} else {
			sput_fail_unless(ap_i == ap2, "Second ap");
		}
	}

	pa_for_each_ap_in_iface(ap_i, iface) {
		sput_fail_unless(ap_i == ap, "Ap in iface");
	}

	pa_for_each_ap_in_iface(ap_i, iface2) {
		sput_fail_unless(0, "No ap in this iface");
	}

	pa_ap_set_iface(ap2, NULL);
	pa_ap_notify(data, ap2);

	pa_ap_set_iface(ap, NULL);
	pa_ap_notify(data, ap);
	padt_check_cb(PADT_CB_APS, PADF_AP_IFACE);

	pa_ap_todelete(ap);
	pa_ap_notify(data, ap);
	padt_check_cb(PADT_CB_APS, PADF_AP_TODELETE);

	pa_ap_todelete(ap2);
	pa_ap_notify(data, ap2);
	padt_check_cb(PADT_CB_APS, PADF_AP_TODELETE);

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);

	pa_iface_todelete(iface2);
	pa_iface_notify(data, iface2);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_cp()
{
	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	struct pa_cp *cp, *cp2, *cp_i;
	struct pa_ldp *ldp;

	pa_for_each_cp_in_iface(cp_i, iface)
				sput_fail_unless(0, "No cp in iface");

	sput_fail_if(pa_cp_get(data, &p1, false), "Do not create");
	sput_fail_unless(cp = pa_cp_get(data, &p1, true), "Create first");
	sput_fail_unless(cp == pa_cp_get(data, &p1, true), "No duplicate");
	sput_fail_unless(cp2 = pa_cp_get(data, &p1_1, true), "Create second");

	pa_cp_notify(cp);
	padt_check_cb(PADT_CB_CPS, PADF_CP_CREATED);
	pa_cp_notify(cp2);
	padt_check_cb(PADT_CB_CPS, PADF_CP_CREATED);
	padt_check_cp(cp, &p1, false, false, false, PA_PRIORITY_DEFAULT, NULL, NULL, data, NULL);

	pa_cp_set_advertised(cp, true);
	pa_cp_set_iface(cp, iface);
	pa_cp_notify(cp);
	padt_check_cb(PADT_CB_CPS, PADF_CP_ADVERTISE | PADF_CP_IFACE);

	bool first = true;
	pa_for_each_cp(cp_i, data) {
		if(first) {
			sput_fail_unless(cp_i == cp2, "Second cp");
			first = false;
		} else {
			sput_fail_unless(cp_i == cp, "First cp");
		}
	}

	pa_for_each_cp_in_iface(cp_i, iface)
		sput_fail_unless(cp_i == cp, "cp in iface");

	ldp = pa_ldp_get(data, &p1, true);
	pa_cp_set_dp(cp2, &ldp->dp);
	pa_cp_notify(cp2);
	padt_check_cb(PADT_CB_CPS, PADF_CP_DP);

	pa_for_each_cp_in_dp(cp_i, &ldp->dp)
		sput_fail_unless(cp_i == cp2, "Cp in dp");

	padt_check_cp(cp, &p1, true, false, false, PA_PRIORITY_DEFAULT, iface, NULL, data, NULL);
	padt_check_cp(cp2, &p1_1, false, false, false, PA_PRIORITY_DEFAULT, NULL, &ldp->dp, data, NULL);

	pa_dp_todelete(&ldp->dp);
	pa_dp_notify(data, &ldp->dp);
	padt_check_cb(PADT_CB_DPS, PADF_DP_TODELETE | PADF_DP_CREATED);

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_aa()
{
	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	struct pa_cp *cp = pa_cp_get(data, &p1, true);
	struct pa_eaa *eaa, *eaa_i;

	struct pa_laa *laa = pa_laa_create(&p1.prefix, cp);
	sput_fail_if(pa_laa_create(&p1.prefix, cp), "A single laa per cp");
	padt_check_aa(&laa->aa, &p1.prefix, true);
	padt_check_laa(laa, cp, false);
	pa_aa_notify(data, &laa->aa);
	padt_check_cb(PADT_CB_AAS,  PADF_AA_CREATED);

	pa_laa_set_applied(laa, true);
	pa_aa_notify(data, &laa->aa);
	padt_check_aa(&laa->aa, &p1.prefix, true);
	padt_check_laa(laa, cp, true);
	padt_check_cb(PADT_CB_AAS,  PADF_LAA_APPLIED);

	pa_aa_todelete(&laa->aa);
	pa_aa_notify(data, &laa->aa);
	padt_check_cb(PADT_CB_AAS,  PADF_AA_TODELETE);

	eaa = pa_eaa_get(data, &p1.prefix, &rid1, false);
	sput_fail_if(eaa, "Do not create");
	sput_fail_unless(eaa = pa_eaa_get(data, &p1.prefix, &rid1, true), "Create new eaa");
	sput_fail_unless(eaa == pa_eaa_get(data, &p1.prefix, &rid1, false), "No duplicate");
	pa_aa_notify(data, &eaa->aa);
	padt_check_cb(PADT_CB_AAS,  PADF_AA_CREATED);
	padt_check_aa(&laa->aa, &p1.prefix, false);
	padt_check_eaa(eaa, &rid1, NULL);

	pa_for_each_eaa(eaa_i, data) {
		sput_fail_unless(eaa_i == eaa, "Only a single eaa");
	}

	pa_eaa_set_iface(eaa, iface);
	pa_aa_notify(data, &eaa->aa);
	padt_check_cb(PADT_CB_AAS,  PADF_EAA_IFACE);
	padt_check_aa(&eaa->aa, &p1.prefix, false);
	padt_check_eaa(eaa, &rid1, iface);

	pa_aa_todelete(&eaa->aa);
	pa_aa_notify(data, &eaa->aa);
	padt_check_cb(PADT_CB_AAS,  PADF_AA_TODELETE);

	pa_cp_todelete(cp);
	pa_cp_notify(cp);
	padt_check_cb(PADT_CB_CPS, PADF_CP_TODELETE | PADF_CP_CREATED);

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_sp()
{
	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	struct pa_iface *iface2 = pa_iface_get(data, IFNAME2, true);
	struct pa_sp *sp, *sp2, *sp3, *sp_i;

	sput_fail_if(pa_sp_get(data, iface, &p1, false), "Do not create");
	sput_fail_unless(sp = pa_sp_get(data, iface, &p1, true), "Create new");
	sput_fail_unless(sp2 = pa_sp_get(data, iface2, &p1_1, true), "Create new");

	sput_fail_unless(sp == pa_sp_get(data, iface, &p1, false), "Get previous");
	sput_fail_unless(sp2 == pa_sp_get(data, iface2, &p1_1, false), "Get previous");

	sput_fail_unless(data->sp_count == 2, "Two sps");
	sput_fail_unless(iface->sp_count == 1, "One sps");
	sput_fail_unless(iface2->sp_count == 1, "One sps");

	sput_fail_unless(sp3 = pa_sp_get(data, iface2, &p1, true), "New sp");

	pa_for_each_sp_in_iface(sp_i, iface2)
		sput_fail_unless(sp_i == sp3, "A single sp in iface");

	pa_for_each_sp_in_iface(sp_i, iface)
		sput_fail_unless(sp_i == sp, "A single sp in iface");

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);

	pa_iface_todelete(iface2);
	pa_iface_notify(data, iface2);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_ipv4()
{
	struct pa_iface *iface = pa_iface_get(data, IFNAME1, true);
	padt_check_ipv4(&data->ipv4, NULL, 0, NULL);
	pa_ipv4_set_dhcp(data, DHCP_DATA, DHCP_LEN);
	pa_ipv4_set_uplink(data, iface);
	pa_ipv4_notify(data);
	padt_check_cb(PADT_CB_IPV4, PADF_IPV4_DHCP | PADF_IPV4_IFACE);

	pa_iface_todelete(iface);
	pa_iface_notify(data, iface);
	padt_check_cb(PADT_CB_IFS, PADF_IF_TODELETE | PADF_IF_CREATED);
}

void pa_data_test_flood()
{
	pa_flood_set_flooddelays(data, 100, 10);
	pa_flood_notify(data);
	padt_check_cb(PADT_CB_FLOOD, PADF_FLOOD_DELAY);
	padt_check_flood(&data->flood, &ridnull, 100, 10);

	pa_flood_set_rid(data, &rid1);
	pa_flood_notify(data);
	padt_check_cb(PADT_CB_FLOOD, PADF_FLOOD_RID);
	padt_check_flood(&data->flood, &rid1, 100, 10);
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
  openlog("test_pa_data", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("test_pa_data");
  pa.conf.max_sp = 2;
  pa.conf.max_sp_per_if = 1;
  pa_data_init(data);
  pa_data_subscribe(data, &data_user);
  sput_run_test(pa_data_test_iface);
  sput_run_test(pa_data_test_dp);
  sput_run_test(pa_data_test_ap);
  sput_run_test(pa_data_test_cp);
  sput_run_test(pa_data_test_aa);
  sput_run_test(pa_data_test_sp);
  sput_run_test(pa_data_test_ipv4);
  sput_run_test(pa_data_test_flood);
  pa_data_unsubscribe(&data_user);
  pa_data_term(data);
  sput_leave_suite();
  sput_finish_testing();
  return sput_get_return_value();
}


