/*
 * Author: Pierre Pfister
 *
 * Testing pa.c functions.
 *
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <unistd.h>
#include <stdio.h>

#include "pa.h"
#include "sput.h"
#include "iface.h"
#include "smock.h"

static struct dmy_iface {
	int registered;
	struct iface_user *user;
	struct pa_iface_callbacks ifcb;
} iface = { .registered = 0 };


static struct dmy_hcp {
	struct pa_flood_callbacks floodcb;

	const char *last_lap_ifname;
	const struct prefix *last_lap_prefix;
	bool last_lap_todelete;

} hcp;

static pa_t pa;

static struct pa_rid rid = { .id = {20} };
static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x00, 0x01}},
		.plen = 54 };

static struct pa_conf conf;

static struct uloop_timeout uloop_to;

#define TEST_1 0x01
int current_test = 0;



static void dmy_iface_register_user(struct iface_user *user) {
	iface.user = user;
	iface.registered = 1;
}

static void dmy_iface_unregister_user(__attribute__((unused))struct iface_user *user) {
	iface.user = NULL;
	iface.registered = 0;
}

static void dmy_update_prefix(const struct prefix *p, const char *ifname,
						hnetd_time_t valid_until,
						hnetd_time_t preferred_until, void *priv)
{

}

static void dmy_update_link_owner(const char *ifname, bool owner, void *priv)
{
	switch (current_test) {
	default:
		sput_fail_if(0, "dmy_updated_lap should not be called here");
		break;
	}
}

static void dmy_updated_lap(const struct prefix *prefix, const char *ifname,
							int to_delete, void *priv)
{
	printf("Updated lap called\n");
	switch (current_test) {
	case TEST_1:
		hcp.last_lap_ifname = ifname;
		hcp.last_lap_prefix = prefix;
		hcp.last_lap_todelete = to_delete;
		break;
	default:
		sput_fail_if(0, "dmy_updated_lap should not be called here");
		break;
	}
}


static void dmy_updated_ldp(const struct prefix *prefix, hnetd_time_t valid_until,
							hnetd_time_t preferred_until, void *priv)
{

}

static void pa_test_uloop_timeout_cb(struct uloop_timeout *to)
{
	uloop_end();
}

static void pa_test_runloopfor(int ms)
{
	uloop_to = (struct uloop_timeout) {
			.cb = pa_test_uloop_timeout_cb,
	};
	uloop_timeout_set(&uloop_to, ms);
	uloop_run();
}

void pa_test_1(void)
{
	/* Simple test.
	 * We add one interface and one prefix (p1).
	 * We need to get a lap on that interface. */
	hnetd_time_t now = hnetd_time();

	current_test = TEST_1;
	hcp.last_lap_ifname = NULL;
	hcp.last_lap_prefix = NULL;
	hcp.last_lap_todelete = 0;

	/* Creating iface */
	iface.user->cb_intiface(iface.user, "iface0", true);
	/* Creating prefix */
	iface.user->cb_prefix(iface.user, &p1, now + 100000, now + 50000, 0);

	sput_fail_if(hcp.last_lap_ifname || hcp.last_lap_prefix, "Should wait for schedule");

	pa_test_runloopfor(50);

	sput_fail_unless(hcp.last_lap_prefix, "Prefix should be allocated now");

}

void pa_test_init(void)
{
	int res;

	pa_conf_default(&conf);
	conf.iface_registration = dmy_iface_register_user;
	conf.iface_unregistration = dmy_iface_unregister_user;
	conf.commit_lap_delay = 1; /* Shortest possible delay */
	pa = pa_create(&conf);
	sput_fail_unless(pa, "Initialize pa");
	res = pa_start(pa);
	sput_fail_if(res, "PA start return");
	sput_fail_unless(iface.registered, "Iface registration");

	iface.ifcb.priv = NULL;
	iface.ifcb.update_link_owner = dmy_update_link_owner;
	iface.ifcb.update_prefix = dmy_update_prefix;
	pa_iface_subscribe(pa, &iface.ifcb);

	hcp.floodcb.priv = NULL;
	hcp.floodcb.updated_lap = dmy_updated_lap;
	hcp.floodcb.updated_ldp = dmy_updated_ldp;
	pa_flood_subscribe(pa, &hcp.floodcb);

	pa_set_rid(pa, &rid);
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	sput_start_testing();
	sput_enter_suite("Prefix assignment algorithm (pa.c)"); /* optional */

	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	sput_run_test(pa_test_init);
	sput_run_test(pa_test_1);

	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
