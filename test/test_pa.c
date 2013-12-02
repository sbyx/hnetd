/*
 * Author: Pierre Pfister
 *
 * Testing pa.c functions.
 *
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <unistd.h>

#include "pa.h"
#include "sput.h"
#include "iface.h"

static struct dmy_iface {
	int registered;
	struct iface_user *user;
	struct pa_iface_callbacks ifcb;
} iface = { .registered = 0 };


static struct dmy_hcp {
	struct pa_flood_callbacks floodcb;
} hcp;

static pa_t pa;

static struct pa_conf conf;

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

}

static void dmy_updated_lap(const struct prefix *prefix, const char *ifname,
							int to_delete, void *priv)
{

}


static void dmy_updated_ldp(const struct prefix *prefix, hnetd_time_t valid_until,
							hnetd_time_t preferred_until, void *priv)
{

}


void pa_test_init(void)
{
	int res;

	pa_conf_default(&conf);
	conf.iface_registration = dmy_iface_register_user;
	conf.iface_unregistration = dmy_iface_unregister_user;
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
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	sput_start_testing();
	sput_enter_suite("Prefix assignment algorithm (pa.c)"); /* optional */

	uloop_init();

	sput_run_test(pa_test_init);

	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
