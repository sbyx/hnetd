
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

static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };
static struct prefix p1_1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x10}},
		.plen = 60 };

static struct pa_rid rid1 = { .id = {0x20} };
static struct pa_rid rid2 = { .id = {0x30} };

#define DHCP_DATA "DHCP_DATA"
#define DHCP_LEN strlen(DHCP_DATA)

#define IFNAME1 "iface.1"
#define IFNAME2 "iface.2"
#define IFNAMETOOLONG "This ifname is so long it could run all around your mama."

void pa_data_test_iface()
{
	struct pa_data data;
	pa_data_init(&data, NULL, NULL);

	struct pa_iface *iface;

	sput_fail_if(pa_iface_get(&data, IFNAME1), "No iface yet");
	sput_fail_unless((iface = pa_iface_goc(&data, IFNAME1)), "Create iface");
	sput_fail_unless(iface == pa_iface_goc(&data, IFNAME1), "Use same iface");
	sput_fail_if(pa_iface_get(&data, IFNAME2), "No iface with that name");
	sput_fail_unless(pa_iface_get(&data, IFNAME1) == iface, "Found iface");
	sput_fail_if(pa_iface_goc(&data, IFNAMETOOLONG), "Name too long");

	pa_iface_destroy(&data, iface);
}

void pa_data_test_dp_loops(struct pa_data *data, bool is_edp, bool is_ldp)
{
	struct pa_dp *dp;
	struct pa_ldp *ldp;
	struct pa_edp *edp;

	pa_for_each_ldp_begin(ldp, data) {
		sput_fail_if(!is_ldp, "Shouldn't be any ldp");
	} pa_for_each_ldp_end;

	pa_for_each_edp_begin(edp, data) {
		sput_fail_if(!is_edp, "Shouldn't be any edp");
	} pa_for_each_edp_end;

	pa_for_each_dp(dp, data) {
		sput_fail_if(!(is_edp || is_ldp), "Shouldn't be any dp");
	}
}

void pa_data_test_checkdp(struct pa_dp *dp, void *dhcp_data, size_t dhcp_len,
		hnetd_time_t preferred_until, hnetd_time_t valid_until,
		bool local) {
	if(!dhcp_data) {
		sput_fail_if(dp->dhcp_len, "Length should be zero");
		sput_fail_if(dp->dhcp_data, "Dhcp data should be null");
	} else {
		sput_fail_if(!dp->dhcp_data || dp->dhcp_len != dhcp_len || memcmp(dp->dhcp_data, dhcp_data, dhcp_len), "Same dhcp data");
	}
	sput_fail_unless(dp->valid_until == valid_until, "Correct valid_until value");
	sput_fail_unless(dp->preferred_until == preferred_until, "Correct preferred until value");
	sput_fail_unless(dp->local == local, "Correct local bool");
}

void pa_data_test_dp() {
	struct pa_data data;
	struct pa_ldp *ldp;
	struct pa_edp *edp;
	struct pa_iface *iface;

	pa_data_init(&data, NULL, NULL);

	pa_data_test_dp_loops(&data, 0, 0);

	ldp = pa_ldp_get(&data, &p1);
	sput_fail_if(ldp, "No ldp yet");

	ldp = pa_ldp_goc(&data, &p1);
	sput_fail_unless(ldp, "New ldp created");
	pa_data_test_checkdp(&ldp->dp, NULL, 0, 0, 0, true);
	sput_fail_unless(pa_ldp_goc(&data, &p1) == ldp, "No new created");
	pa_data_test_dp_loops(&data, 0, 1);

	sput_fail_unless(pa_dp_set_dhcp(&ldp->dp, DHCP_DATA, DHCP_LEN), "Modified dhcp data");
	pa_data_test_checkdp(&ldp->dp, DHCP_DATA, DHCP_LEN, 0, 0, true);

	sput_fail_unless(pa_dp_set_dhcp(&ldp->dp, NULL, 10), "Modified dhcp data");
	pa_data_test_checkdp(&ldp->dp, NULL, 0, 0, 0, true);

	sput_fail_unless(pa_dp_set_lifetime(&ldp->dp, 100, 200), "Modified lifetimes");
	pa_data_test_checkdp(&ldp->dp, NULL, 0, 100, 200, true);

	sput_fail_unless(pa_ldp_get(&data, &p1) == ldp, "Correct ldp ref");
	sput_fail_if(pa_ldp_get(&data, &p1_1), "No ldp");

	iface = pa_iface_goc(&data, IFNAME1);
	pa_iface_destroy(&data, iface);

	edp = pa_edp_get(&data, &p1_1, &rid1);
	sput_fail_if(edp, "No edp yet");

	edp = pa_edp_goc(&data, &p1_1, &rid1);
	sput_fail_unless(edp, "New edp created");
	pa_data_test_checkdp(&edp->dp, NULL, 0, 0, 0, false);
	sput_fail_unless(pa_edp_goc(&data, &p1_1, &rid1) == edp, "No new created");
	sput_fail_if(PA_RIDCMP(&rid1, &edp->rid), "Correct rid");
	pa_data_test_dp_loops(&data, 1, 1);

	sput_fail_unless(edp == pa_edp_get(&data, &p1_1, &rid1), "Correct edp");
	sput_fail_if(pa_edp_get(&data, &p1, &rid1), "No edp");
	sput_fail_if(pa_edp_get(&data, &p1_1, &rid2), "No edp");

	pa_ldp_destroy(ldp);
	pa_data_test_dp_loops(&data, 1, 0);

	pa_edp_destroy(edp);
	pa_data_test_dp_loops(&data, 0, 0);

}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
  openlog("test_pa_data", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("test_pa_data");
  sput_run_test(pa_data_test_iface);
  sput_run_test(pa_data_test_dp);
  sput_leave_suite();
  sput_finish_testing();
  return sput_get_return_value();
}


