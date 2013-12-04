/*
 * Author: Pierre Pfister
 *
 * Testing pa.c functions.
 *
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/uloop.h>

#define L_LEVEL 7
#include "hnetd.h"
#include "sput.h"
#include "smock.h"
#include "iface.h"

/***************************************************** Mask for pa.c */

#define iface_register_user dmy_iface_register_user
#define iface_unregister_user dmy_iface_unregister_user

static void dmy_iface_register_user(struct iface_user *user);
static void dmy_iface_unregister_user(struct iface_user *user);

#define hnetd_time test_pa_time
static hnetd_time_t now_time = 0;
static hnetd_time_t test_pa_time(void) {
	return now_time;
}

#define uloop_timeout_set		test_pa_timeout_set
#define uloop_timeout_cancel	test_pa_timeout_cancel

static int test_pa_timeout_set(struct uloop_timeout *timeout, int ms);
static int test_pa_timeout_cancel(struct uloop_timeout *timeout);

/* pa.c */
#include "pa.c"


/***************************************************** Smock callbacks */

#define SMOCK_PREFIX_UPDATE "prefix_update"
#define SMOCK_LINK_UPDATE "link_update"
#define SMOCK_LAP_UPDATE "lap_update"
#define SMOCK_LDP_UPDATE "ldp_update"

#define SMOCK_SET_TIMEOUT "set_timeout"
#define SMOCK_SET_TIMEOUT_MS "set_timeout_ms"
#define SMOCK_CANCEL_TIMEOUT "cancel_timeout"

struct link_update_call {
	char ifname[IFNAMSIZ];
	bool owner;
	void *priv;
};

struct px_update_call {
	char ifname[IFNAMSIZ];
	struct prefix prefix;
	hnetd_time_t valid_until;
	hnetd_time_t preferred_until;
	void *priv;
};

struct lap_update_call {
	char ifname[IFNAMSIZ];
	struct prefix prefix;
	bool to_delete;
	void *priv;
};

struct ldp_update_call {
	struct prefix prefix;
	hnetd_time_t valid_until;
	hnetd_time_t preferred_until;
	void *priv;
};

static struct px_update_call *new_px_update(const struct prefix *p, const char *ifname,
						hnetd_time_t valid_until,
						hnetd_time_t preferred_until, void *priv)
{
	struct px_update_call *px;
	if(!(px = malloc(sizeof(struct px_update_call))))
		return NULL;

	px->prefix = *p;
	strcpy(px->ifname, ifname);
	px->preferred_until = preferred_until;
	px->valid_until = valid_until;
	px->priv = priv;

	return px;
}

static struct link_update_call *new_link_update(const char *ifname, bool owner, void *priv)
{
	struct link_update_call *lu;
	if(!(lu = malloc(sizeof(struct link_update_call))))
		return NULL;

	strcpy(lu->ifname, ifname);
	lu->owner = owner;
	lu->priv = priv;

	return lu;
}

static struct lap_update_call *new_lap_update(const struct prefix *prefix, const char *ifname,
		int to_delete, void *priv)
{
	struct lap_update_call *lapu;
	if(!(lapu = malloc(sizeof(struct lap_update_call))))
		return NULL;

	lapu->prefix = *prefix;
	lapu->priv = priv;
	lapu->to_delete = to_delete;
	strcpy(lapu->ifname, ifname);

	return lapu;
}

static struct ldp_update_call *new_ldp_update(const struct prefix *prefix, hnetd_time_t valid_until,
		hnetd_time_t preferred_until, void *priv)
{
	struct ldp_update_call *ldpu;
	if(!(ldpu = malloc(sizeof(struct ldp_update_call))))
		return NULL;

	ldpu->preferred_until = preferred_until;
	ldpu->valid_until = valid_until;
	ldpu->prefix = *prefix;
	ldpu->priv = priv;

	return ldpu;
}

static int test_pa_timeout_set(struct uloop_timeout *timeout, int ms)
{
	printf("Timeout set called\n");
	timeout->pending = 1;
	smock_push(SMOCK_SET_TIMEOUT, timeout);
	smock_push_int(SMOCK_SET_TIMEOUT_MS, ms);
	return 0;
}

static int test_pa_timeout_cancel(struct uloop_timeout *timeout)
{
	printf("Timeout cancel called\n");
	timeout->pending = 0;
	smock_push(SMOCK_CANCEL_TIMEOUT, timeout);
	return 0;
}

static void test_pa_timeout_fire(struct uloop_timeout *timeout)
{
	sput_fail_unless(timeout->pending, "Timeout not pending");
	if(timeout->pending) {
		timeout->pending = 0;
		timeout->cb(timeout);
	}
}


#define SPUT_FAIL_AND_RETURN_IF(a, test) \
	do {if(a) {sput_fail_if(a, test); return;} } while(0)

static void dmy_update_prefix(const struct prefix *p, const char *ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len,
		void *priv)
{
	//TODO: Save other arguments
	printf("dmy_update_prefix\n");
	struct px_update_call *pxu = new_px_update(p, ifname, valid_until, preferred_until, priv);
	SPUT_FAIL_AND_RETURN_IF(!pxu, "new_px_update");
	smock_push(SMOCK_PREFIX_UPDATE, pxu);
}

static void dmy_update_link_owner(const char *ifname, bool owner, void *priv)
{
	printf("dmy_update_link_owner\n");
	struct link_update_call *lu = new_link_update(ifname, owner, priv);
	SPUT_FAIL_AND_RETURN_IF(!lu, "new_link_update");
	smock_push(SMOCK_LINK_UPDATE, lu);
}

static void dmy_updated_lap(const struct prefix *prefix, const char *ifname,
							int to_delete, void *priv)
{
	printf("dmy_updated_lap\n");
	struct lap_update_call *lau = new_lap_update(prefix, ifname, to_delete, priv);
	SPUT_FAIL_AND_RETURN_IF(!lau, "new_lap_update");
	smock_push(SMOCK_LAP_UPDATE, lau);
}

static void dmy_updated_ldp(const struct prefix *prefix,
		const struct prefix *excluded, const char *dp_ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len,
		void *priv)
{
	//TODO: Save others
	printf("dmy_updated_ldp\n");
	struct ldp_update_call *ldu = new_ldp_update(prefix, valid_until, preferred_until, priv);
	SPUT_FAIL_AND_RETURN_IF(!ldu, "new_ldp_update");
	smock_push(SMOCK_LDP_UPDATE, ldu);
}

/******** Test *******/

static struct dmy_iface {
	int registered;
	struct iface_user *user;
	struct pa_iface_callbacks ifcb;
} iface = { .registered = 0 };


static struct dmy_hcp {
	struct pa_flood_callbacks floodcb;
} hcp;

static pa_t pa;

static struct pa_rid rid = { .id = {20} };
static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x00, 0x01}},
		.plen = 54 };

static struct pa_conf conf;

#define TEST_IFNAME_1 "iface0"

static void dmy_iface_register_user(struct iface_user *user) {
	iface.user = user;
	iface.registered = 1;
}

static void dmy_iface_unregister_user(__attribute__((unused))struct iface_user *user) {
	iface.user = NULL;
	iface.registered = 0;
}


/* This test adds one dp and one iface,
 * with nobody else on the link. And then removes it.
 * This function test deeply pa behaviour by looking at
 * all scheduled timeouts. */
void pa_test_minimal(void)
{
	struct lap_update_call *lap_update;
	struct ldp_update_call *ldp_update;
	struct link_update_call *link_update;
	struct px_update_call *px_update;
	struct uloop_timeout *dp_to, *pa_to, *lap_to;
	int ms;
	struct prefix chosen_prefix;
	chosen_prefix.plen = 0;

	hnetd_time_t valid_until, preferred_until;

	sput_fail_unless(smock_empty(), "Queue empty at test beginning");

	/* Creating iface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, true);
	/* This is supposed to create a schedule event */
	pa_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(pa_to)
		sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Schedule delay");

	/* Calling the pa algorithm */
	now_time = PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(pa_to);

	smock_is_empty();

	/* Creating prefix */
	valid_until = 100000;
	preferred_until = 50000;
	//TODO: Use exclude and dhcp
	iface.user->cb_prefix(iface.user, TEST_IFNAME_1, &p1, NULL,
			valid_until, preferred_until, NULL, 0);

	/* This will trigger a new scheduling */
	pa_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(pa_to)
		sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Schedule delay");

	/* We also should have a new ldp */
	ldp_update = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp_update) {
		sput_fail_unless(ldp_update->preferred_until == preferred_until, "Correct preferred lifetime");
		sput_fail_unless(ldp_update->valid_until == valid_until, "Correct valid lifetime");
		sput_fail_unless(ldp_update->priv == &hcp.floodcb, "Correct private field");
		sput_fail_if(prefix_cmp(&ldp_update->prefix, &p1), "Correct dp value");
		free(ldp_update);
	}

	smock_is_empty();

	/* Calling the pa algorithm */
	now_time = 2 * PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(pa_to);

	/* Now we should have a new prefix to flood, inside p1.
	 * We should have dp timeout scheduled
	 * We should have a lap assignment timeout scheduled
	 * We should also own the interface.
	 * Have a new schedule PA because we added stuff. */

	/* Scheduled dp */
	dp_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(dp_to) {
		/* The +1 is for free loops and imprecisions */
		sput_fail_unless(ms == valid_until - now_time, "Delayed assignment delay");
		sput_fail_unless(dp_to->cb == pa_dp_do_uloop, "Correct timeout callback");
	}

	/* Assigned lap */
	lap_update = smock_pull(SMOCK_LAP_UPDATE);
	if(lap_update) {
		sput_fail_if(strcmp(lap_update->ifname, TEST_IFNAME_1), "Correct lap ifname");
		sput_fail_unless(prefix_contains(&p1, &lap_update->prefix), "Created prefix is in p1");
		sput_fail_unless(lap_update->priv == &hcp.floodcb, "Correct hcp private field");
		sput_fail_unless(lap_update->to_delete == 0, "New lap");
		memcpy(&chosen_prefix, &lap_update->prefix, sizeof(struct prefix));
		free(lap_update);
	}

	/* Scheduled PA */
	pa_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(pa_to)
		sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Schedule delay");

	/* Interface owner */
	link_update = smock_pull(SMOCK_LINK_UPDATE);
	if(link_update) {
		sput_fail_if(strcmp(link_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(link_update->owner, "We own the link");
	}

	/* Delayed lap assignment */
	lap_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(lap_to) {
		sput_fail_unless(ms == (int) conf.commit_lap_delay, "Delayed assignment delay");
		sput_fail_unless(lap_to->cb == pa_lap_delayed_cb, "Correct timeout callback");
	}

	smock_is_empty();

	/* Executes the scheduled PA */

	now_time = 3 * PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(pa_to);

	/* Nothing should be changed here */
	/* The algorithm is stable */
	smock_is_empty();


	/* Test delayed assignment */

	now_time += conf.commit_lap_delay; /* Moving to when the prefix must be assigned */
	test_pa_timeout_fire(lap_to);

	px_update = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px_update) {
		sput_fail_if(strcmp(px_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(px_update->preferred_until == preferred_until, "Correct preferred lifetime");
		sput_fail_unless(px_update->valid_until == valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&px_update->prefix, &chosen_prefix), "Correct lap prefix");
		sput_fail_if(px_update->priv == &iface.ifcb, "Correct private field");
	}

	/* Assignment should not schedule anything new */
	smock_is_empty();


	/* Now, let's timeout the assigned prefix */
	now_time = valid_until;
	test_pa_timeout_fire(dp_to);

	/* The algorithm should have been run, the dp destroyed,
	 * and the lap with it. Which makes pa to reschedule itself later.*/

	lap_update = smock_pull(SMOCK_LAP_UPDATE);
	if(lap_update) {
		sput_fail_if(prefix_cmp(&lap_update->prefix, &chosen_prefix), "Correct lap prefix");
		sput_fail_unless(lap_update->to_delete, "Lap must be deleted");
	}

	ldp_update = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp_update) {
		sput_fail_if(prefix_cmp(&ldp_update->prefix, &p1), "Correct dp value");
		sput_fail_unless(ldp_update->valid_until == 0, "Dp must be deleted");
	}

	link_update = smock_pull(SMOCK_LINK_UPDATE);
	if(link_update) {
		sput_fail_if(strcmp(link_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(!link_update->owner, "Not owner anymore");
	}

	px_update = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px_update) {
		sput_fail_if(strcmp(px_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_if(prefix_cmp(&px_update->prefix, &chosen_prefix), "Correct prefix");
		sput_fail_unless(!px_update->valid_until, "Prefix should be unassigned");
	}

	pa_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(pa_to)
			sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Schedule delay");

	smock_is_empty();

	/* Schedule pa */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(pa_to);

	/* Nothing should be enqueued here */
	smock_is_empty();

	/* Delete interface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, false);

	/* Only pa should be scheduled here */
	pa_to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	if(pa_to)
		sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Schedule delay");

	/* Execute scheduled pa */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(pa_to);

	/* Should be stabilized to... nothing */
	smock_is_empty();
}

/* This test initialized the pa
 * and checks if everything is ok */
void pa_test_init(void)
{
	int res, ms;
	struct uloop_timeout *to;

	now_time = 0;

	pa_conf_default(&conf);
	//conf.iface_registration = dmy_iface_register_user;
	//conf.iface_unregistration = dmy_iface_unregister_user;
	conf.commit_lap_delay = 20000;
	pa = pa_create(&conf);
	sput_fail_unless(pa, "Initialize pa");
	res = pa_start(pa);
	sput_fail_if(res, "PA start return");
	sput_fail_unless(iface.registered, "Iface registration");

	iface.ifcb.priv = &iface.ifcb;
	iface.ifcb.update_link_owner = dmy_update_link_owner;
	iface.ifcb.update_prefix = dmy_update_prefix;
	pa_iface_subscribe(pa, &iface.ifcb);

	hcp.floodcb.priv = &hcp.floodcb;
	hcp.floodcb.updated_lap = dmy_updated_lap;
	hcp.floodcb.updated_ldp = dmy_updated_ldp;
	pa_flood_subscribe(pa, &hcp.floodcb);

	pa_set_rid(pa, &rid); /* This will schedule a PA */
	to = smock_pull(SMOCK_SET_TIMEOUT);
	ms = smock_pull_int(SMOCK_SET_TIMEOUT_MS);
	sput_fail_unless(to, "Should have a pa scheduled");
	if(to) {
		sput_fail_unless(ms == PA_SCHEDULE_RUNNEXT_MS, "Small schedule delay");
	}

	/* Let's trigger the pa */
	now_time = PA_SCHEDULE_RUNNEXT_MS + 1;
	pa_do_uloop(to);

	/* No dp or iface => No new schedule */
	sput_fail_unless(smock_empty(), "End of init with empty smock queues");
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	sput_start_testing();
	sput_enter_suite("Prefix assignment algorithm (pa.c)"); /* optional */

	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);

	sput_run_test(pa_test_init);
	sput_run_test(pa_test_minimal);

	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
