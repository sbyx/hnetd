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
#include <fcntl.h>

#define L_LEVEL 7
#include "hnetd.h"
#include "sput.h"
#include "smock.h"
#include "iface.h"

/***************************************************** Test behaviour */
static bool test_schedule_events = false;
static bool mask_random = false;

#define SMOCK_RANDOM_QUEUE "random queue"

//#define TEST_PA_DEBUG
#ifdef TEST_PA_DEBUG
#define test_pa_printf(...) printf(__VA_ARGS__)
#else
#define test_pa_printf(...)
#endif


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

static int test_pa_random() {
	test_pa_printf("Called random\n");
	if(mask_random) {
		return smock_pull_int(SMOCK_RANDOM_QUEUE);
	}
	return random();
}

#define random test_pa_random

/* prefix_utils */
#include "prefix_utils.c"

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
	size_t dhcpv6_len;
	const void * dhcpv6_data; /* NOT COPIED */
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
	size_t dhcpv6_len;
	const void *dhcpv6_data; /* NOT COPIED */
	const char *dp_ifname; /* NOT COPIED */
	const struct prefix *excluded; /* NOT COPIED */
	void *priv;
};

static struct px_update_call *new_px_update(const struct prefix *p, const char *ifname,
						hnetd_time_t valid_until, hnetd_time_t preferred_until,
						const void * dhcpv6_data, size_t dhcpv6_len,
						void *priv)
{
	struct px_update_call *px;
	if(!(px = malloc(sizeof(struct px_update_call))))
		return NULL;

	px->dhcpv6_data = dhcpv6_data;
	px->dhcpv6_len = dhcpv6_len;
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

static struct ldp_update_call *new_ldp_update(const struct prefix *prefix,
		const struct prefix *excluded, const char *dp_ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len,
		void *priv)
{
	struct ldp_update_call *ldpu;
	if(!(ldpu = malloc(sizeof(struct ldp_update_call))))
		return NULL;

	ldpu->dhcpv6_data = dhcpv6_data;
	ldpu->dhcpv6_len = dhcpv6_len;
	ldpu->preferred_until = preferred_until;
	ldpu->valid_until = valid_until;
	ldpu->prefix = *prefix;
	ldpu->priv = priv;
	ldpu->dp_ifname = dp_ifname;
	ldpu->excluded = excluded;

	return ldpu;
}

static int test_pa_timeout_set(struct uloop_timeout *timeout, int ms)
{
	test_pa_printf("Timeout set called\n");
	timeout->pending = 1;
	if(test_schedule_events) {
		smock_push(SMOCK_SET_TIMEOUT, timeout);
		smock_push_int(SMOCK_SET_TIMEOUT_MS, ms);
	}
	return 0;
}

static int test_pa_timeout_cancel(struct uloop_timeout *timeout)
{
	test_pa_printf("Timeout cancel called\n");
	timeout->pending = 0;
	if(test_schedule_events) {
		smock_push(SMOCK_CANCEL_TIMEOUT, timeout);
	}
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
	test_pa_printf("dmy_update_prefix\n");
	struct px_update_call *pxu = new_px_update(p, ifname, valid_until, preferred_until, dhcpv6_data, dhcpv6_len, priv);
	SPUT_FAIL_AND_RETURN_IF(!pxu, "new_px_update");
	smock_push(SMOCK_PREFIX_UPDATE, pxu);
}

static void dmy_update_link_owner(const char *ifname, bool owner, void *priv)
{
	test_pa_printf("dmy_update_link_owner\n");
	struct link_update_call *lu = new_link_update(ifname, owner, priv);
	SPUT_FAIL_AND_RETURN_IF(!lu, "new_link_update");
	smock_push(SMOCK_LINK_UPDATE, lu);
}

static void dmy_updated_lap(const struct prefix *prefix, const char *ifname,
							int to_delete, void *priv)
{
	test_pa_printf("dmy_updated_lap\n");
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
	test_pa_printf("dmy_updated_ldp\n");
	struct ldp_update_call *ldu = new_ldp_update(prefix, excluded, dp_ifname,
			valid_until, preferred_until, dhcpv6_data, dhcpv6_len, priv);
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

static struct pa_rid rid = { .id = {0x20} };
static struct pa_rid rid_higher = { .id = {0x30} };
static struct pa_rid rid_lower = { .id = {0x10} };
static struct prefix p1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff}},
		.plen = 56 };
static struct prefix p1_1 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x10}},
		.plen = 60 };
/*static struct prefix p1_2 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x20}},
		.plen = 60 };*/
static struct prefix p1_20 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x20}},
		.plen = 64 };
static struct prefix p1_21 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x21}},
		.plen = 64 };
static struct prefix p1_22 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x22}},
		.plen = 64 };
/*static struct prefix p1_23 = {
		.prefix = { .s6_addr = {
				0x20, 0x01, 0x20, 0x01, 0xff, 0xff, 0xff, 0x23}},
		.plen = 64 };*/

static struct pa_conf conf;
static struct pa_store_conf store_conf;

#define PA_STORE_FILE "/tmp/test_pa-store.db"

#define TEST_IFNAME_1 "iface0"
#define TEST_IFNAME_2 "iface1"
#define TEST_IFNAME_WAN "wan0"
#define TEST_DHCPV6_DATA "DHCPV DATA -----"
#define TEST_DHCPV6_LEN strlen(TEST_DHCPV6_DATA) + 1
#define TEST_COMMIT_LAP_DELAY 20000

static void dmy_iface_register_user(struct iface_user *user) {
	iface.user = user;
	iface.registered = 1;
}

static void dmy_iface_unregister_user(__attribute__((unused))struct iface_user *user) {
	iface.user = NULL;
	iface.registered = 0;
}

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

static void pa_test_pa_empty(void)
{
	smock_is_empty();

	sput_fail_unless(list_empty(&pa->dps), "No remaining dps");
	sput_fail_unless(list_empty(&pa->ifaces), "No remaining ifaces");
	sput_fail_unless(avl_is_empty(&pa->eaps), "No remaining eaps");
	sput_fail_unless(avl_is_empty(&pa->laps), "No remaining laps");
}

/* This test destroys the pa.
 * It must have no current dp, ifaces, lap or eap */
void pa_test_destroy(void)
{
	test_schedule_events = 0;
	mask_random = 1;
	pa_destroy(pa);
	smock_is_empty();
}

void pa_test_storage(void)
{
	test_schedule_events = 0;
	mask_random = 1;

	/* This test is intended to see if pa.c
	 * correctly reads information from persistent storage.
	 */

	smock_is_empty();

	/* Add a fake stored prefix */
	sput_fail_if(pa_store_prefix_add(conf.storage, TEST_IFNAME_1,  &p1_21),
			"Adding p1_21 to storage");

	/* Add a random prefix */
	test_pa_random_push_prefix(&p1_22);

	/* Now let's run the pa */
	struct lap_update_call *lap1, *lap2;
	struct link_update_call *l1, *l2;
	struct pa_iface *pa_iface;
	struct pa_lap *pa_lap;
	struct px_update_call *px;
	struct ldp_update_call *ldp;

	now_time += 10000;
	hnetd_time_t dp_valid_until = now_time + 100000;
	hnetd_time_t dp_preferred_until = now_time + 50000;
	pa_update_edp(pa, &p1, &rid_higher, NULL, dp_valid_until, dp_preferred_until,
				NULL, 0);

	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, true);
	iface.user->cb_intiface(iface.user, TEST_IFNAME_2, true);

	/* Run pa */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	lap2 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1 && lap2) {
		if(prefix_cmp(&lap1->prefix, &p1_21)) {
			struct lap_update_call *s; /* switch */
			s = lap1;
			lap1 = lap2;
			lap2 = s;
		}
		sput_fail_if(prefix_cmp(&lap1->prefix, &p1_21), "First lap prefix is correct");
		sput_fail_unless(lap1->to_delete == 0, "New lap");
		sput_fail_if(strcmp(lap1->ifname, TEST_IFNAME_1), "Correct iface");
		sput_fail_if(prefix_cmp(&lap2->prefix, &p1_22), "Second lap is correct");
		sput_fail_unless(lap2->to_delete == 0, "New lap");
		sput_fail_if(strcmp(lap2->ifname, TEST_IFNAME_2), "Correct iface");
		free(lap1);
		free(lap2);
	}

	l1 = smock_pull(SMOCK_LINK_UPDATE);
	l2 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1 && l2) {
		sput_fail_unless(l1->owner, "Owner on the link");
		sput_fail_unless(l2->owner, "Owner on the link");
		free(l1);
		free(l2);
	}

	smock_is_empty();

	/* Assign prefixes (so that they are pushed to storage) */
	now_time += conf.commit_lap_delay;
	pa_iface = pa_iface_goc(pa, TEST_IFNAME_1);
	sput_fail_if(list_empty(&pa_iface->laps), "Existing lap");
	pa_lap = list_first_entry(&pa_iface->laps, struct pa_lap, if_le);
	sput_fail_unless(pa_lap, "Get the only current lap");
	if(pa_lap) {
		test_pa_timeout_fire(&pa_lap->delayed.timeout);
	}

	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px) {
		sput_fail_if(strcmp(px->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(px->preferred_until == dp_preferred_until, "Correct preferred lifetime");
		sput_fail_unless(px->valid_until == dp_valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&px->prefix, &p1_21), "Correct prefix");
		free(px);
	}


	pa_iface = pa_iface_goc(pa, TEST_IFNAME_2);
	sput_fail_if(list_empty(&pa_iface->laps), "Existing lap");
	pa_lap = list_first_entry(&pa_iface->laps, struct pa_lap, if_le);
	sput_fail_unless(pa_lap, "Get the only current lap");
	if(pa_lap) {
		test_pa_timeout_fire(&pa_lap->delayed.timeout);
	}

	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px) {
		sput_fail_if(strcmp(px->ifname, TEST_IFNAME_2), "Correct link ifname");
		sput_fail_unless(px->preferred_until == dp_preferred_until, "Correct preferred lifetime");
		sput_fail_unless(px->valid_until == dp_valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&px->prefix, &p1_22), "Correct prefix");
		free(px);
	}

	/* Timeout edp */
	now_time = dp_valid_until;
	test_pa_timeout_fire(&pa->pa_dp_timeout); /* dp timeout */

	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	lap2 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1 && lap2) {
		free(lap1);
		free(lap2);
	}

	l1 = smock_pull(SMOCK_LINK_UPDATE);
	l2 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1 && l2) {
		sput_fail_if(l1->owner, "Not owner on the link");
		sput_fail_if(l2->owner, "Not owner on the link");
		free(l1);
		free(l2);
	}

	/* Both assignments are destroyed */
	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px)
		free(px);

	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px)
		free(px);

	smock_is_empty();

	/* Add the same prefix, but locally this time */
	dp_valid_until = now_time + 100000;
	dp_preferred_until = now_time + 50000;
	iface.user->cb_prefix(iface.user, TEST_IFNAME_1, &p1, NULL,
				dp_valid_until, dp_preferred_until, NULL, 0);
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, false);

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	l1 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1) {
		sput_fail_unless(l1->owner, "Owner on the link");
		free(l1);
	}

	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1) {
		sput_fail_if(prefix_cmp(&lap1->prefix, &p1_22), "Second lap is correct");
		sput_fail_unless(lap1->to_delete == 0, "New lap");
		sput_fail_if(strcmp(lap1->ifname, TEST_IFNAME_2), "Correct iface");
		free(lap1);
	}

	ldp = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp) {
		sput_fail_unless(ldp->preferred_until == dp_preferred_until, "Correct preferred lifetime");
		sput_fail_unless(ldp->valid_until == dp_valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&ldp->prefix, &p1), "Correct prefix value");
		sput_fail_if(strcmp(ldp->dp_ifname, TEST_IFNAME_1), "Correct dp_ifname value");
		free(ldp);
	}

	/* Update the ldp */
	iface.user->cb_prefix(iface.user, TEST_IFNAME_1, &p1, NULL,
					0, 0, NULL, 0);
	iface.user->cb_intiface(iface.user, TEST_IFNAME_2, false);

	l1 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1) {
		sput_fail_if(l1->owner, "Not owner on the link");
		free(l1);
	}

	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1) {
		sput_fail_unless(lap1->to_delete == 1, "Delete lap");
		free(lap1);
	}

	ldp = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp) {
		sput_fail_unless(ldp->valid_until == 0, "Prefix must be deleted");
		free(ldp);
	}

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	pa_test_pa_empty();
}

/* This test explores simple situations with multiple interfaces
 * and no neighbors. */
void pa_test_multiple_ifaces(void)
{
	test_schedule_events = 0;
	mask_random = 1;

	struct prefix *prefix = &p1;
	struct prefix *to_use_1 = &p1_20;
	struct prefix *to_use_2 = &p1_21;
	struct prefix *to_use_3 = &p1_22;

	struct lap_update_call *lap1, *lap2;
	struct link_update_call *l1, *l2;

	sput_fail_unless(smock_empty(), "Queue empty at test beginning");

	now_time += 10000;
	hnetd_time_t dp_valid_until = now_time + 100000;
	hnetd_time_t dp_preferred_until = now_time + 50000;

	/* This time, the prefix comes from elsewhere on an interface that we share
	 * but that will be declared external (Just to make things messier). */
	pa_update_edp(pa, prefix, &rid_higher, NULL, dp_valid_until, dp_preferred_until,
			NULL, 10 /* This is a test */);

	/* That guy uses a prefix on another interface that we also share, but is external for us. */
	pa_update_eap(pa, to_use_2, &rid_higher, TEST_IFNAME_WAN, 0);

	/* Adding two internal interfaces */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, true);
	iface.user->cb_intiface(iface.user, TEST_IFNAME_2, true);

	test_pa_random_push_prefix(to_use_1); /* First taken prefix */
	test_pa_random_push_prefix(to_use_1); /* Will need to be rejected because allocated on the other interface */
	test_pa_random_push_prefix(to_use_2); /* Will be rejected because used by somebody else */
	test_pa_random_push_prefix(to_use_3); /* Will be accepted as second local */

	/* Running prefix assignment algorithm */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	/*  */
	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	lap2 = smock_pull(SMOCK_LAP_UPDATE);

	if(lap1 && lap2) {
		if(prefix_cmp(&lap1->prefix, to_use_1)) {
			struct lap_update_call *s; /* switch */
			s = lap1;
			lap1 = lap2;
			lap2 = s;
		}

		sput_fail_if(prefix_cmp(&lap1->prefix, to_use_1), "First lap prefix is correct");
		sput_fail_unless(lap1->to_delete == 0, "New lap");
		sput_fail_if(prefix_cmp(&lap2->prefix, to_use_3), "Second lap is correct");
		sput_fail_unless(lap2->to_delete == 0, "New lap");

		sput_fail_unless(((!strcmp(lap1->ifname, TEST_IFNAME_1)) || (!strcmp(lap2->ifname, TEST_IFNAME_1))) &&
				((!strcmp(lap1->ifname, TEST_IFNAME_2)) || (!strcmp(lap2->ifname, TEST_IFNAME_2))),
				"Both interfaces have lap");
		free(lap1);
		free(lap2);
	}

	l1 = smock_pull(SMOCK_LINK_UPDATE);
	l2 = smock_pull(SMOCK_LINK_UPDATE);

	if(l1 && l2) {
		sput_fail_unless(l1->owner, "Owner on the link");
		sput_fail_unless(l2->owner, "Owner on the link");
		sput_fail_unless(((!strcmp(l1->ifname, TEST_IFNAME_1)) || (!strcmp(l2->ifname, TEST_IFNAME_1))) &&
				((!strcmp(l1->ifname, TEST_IFNAME_2)) || (!strcmp(l2->ifname, TEST_IFNAME_2))),
				"Own both interfaces");
		free(l1);
		free(l2);
	}

	smock_is_empty();

	/* Let's remove the first interface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, false);

	/* Destroyed lap */
	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1) {
		sput_fail_if(strcmp(lap1->ifname, TEST_IFNAME_1), "Removing lap attached to deleted iface");
		free(lap1);
	}

	/* And the link is not owned anymore */
	l1 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1) {
		test_pa_printf("%s", l1->ifname);
		sput_fail_if(strcmp(l1->ifname,  TEST_IFNAME_1), "Not owning interface anymore");
		free(l1);
	}

	/* Removing eaps */
	pa_update_eap(pa, to_use_2, &rid_higher, TEST_IFNAME_WAN, 1);
	/* Nothing happens */

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	/* Nothing new happens */

	/* Removing edp */
	pa_update_edp(pa, prefix, &rid_higher, NULL, 0, 0,
				NULL, 10 /* This is a test */);

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	/* The remaining lap should have been deleted */
	lap1 = smock_pull(SMOCK_LAP_UPDATE);
	if(lap1) {
		sput_fail_if(strcmp(lap1->ifname, TEST_IFNAME_2), "Removing lap attached to deleted iface");
		free(lap1);
	}

	/* And the link is not owned anymore */
	l1 = smock_pull(SMOCK_LINK_UPDATE);
	if(l1) {
		test_pa_printf("%s", l1->ifname);
		sput_fail_if(strcmp(l1->ifname,  TEST_IFNAME_2), "Not owning interface anymore");
		free(l1);
	}

	smock_is_empty();

	/* Now we just need to remove the last interface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_2, false);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	pa_test_pa_empty();
}

/* This test sees how pa behaves regarding to collision detection.
 * There are one local link, one other node, one distant link and
 * one locally allocated prefix.
 * Random generator is faked in order to force collision detection.
 */
void pa_test_collisions(void) {
	test_schedule_events = 0;
	mask_random = 1;

	struct prefix *prefix = &p1;
	struct prefix *excluded = &p1_1;
	struct prefix *not_excluded = &p1_20;
	struct prefix *not_excluded_bis = &p1_21;
	struct prefix *not_excluded_tier = &p1_22;
	struct ldp_update_call *ldp;
	struct lap_update_call *lap;
	struct link_update_call *link;
	struct px_update_call *px;
	struct pa_iface *pa_iface;
	struct pa_lap *pa_lap;

	sput_fail_unless(smock_empty(), "Queue empty at test beginning");

	now_time += 10000;
	hnetd_time_t dp_valid_until = now_time + 100000;
	hnetd_time_t dp_preferred_until = now_time + 50000;



	/* Creating iface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, true);
	/* Fireing schedule */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty();

	now_time += 1000;
	/* Creating dp */
	iface.user->cb_prefix(iface.user, TEST_IFNAME_WAN, prefix, excluded,
				dp_valid_until, dp_preferred_until, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN);
	/* hcp dp update */
	ldp = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp) {
		sput_fail_unless(ldp->preferred_until == dp_preferred_until, "Correct preferred lifetime");
		sput_fail_unless(ldp->valid_until == dp_valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&ldp->prefix, prefix), "Correct prefix value");
		sput_fail_unless(ldp->excluded, "Non null excluded prefix");
		if(ldp->excluded)
			sput_fail_if(prefix_cmp(ldp->excluded, excluded), "Correct excluded value");

		sput_fail_unless(ldp->dhcpv6_len == TEST_DHCPV6_LEN, "Correct dhcpv6 len value");
		if(ldp->dhcpv6_len == TEST_DHCPV6_LEN) {
			sput_fail_if(memcmp(ldp->dhcpv6_data, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN), "Correct dhcpv6 data value");
		}
		sput_fail_if(strcmp(ldp->dp_ifname, TEST_IFNAME_WAN), "Correct dp_ifname value");
		free(ldp);
	}
	smock_is_empty();
	/* Run next PA */
	/* Next PA will generate lap for p1. We want to propose one
	 * in collision first. Then propose one correct.
	 */

	test_pa_random_push_prefix(excluded);
	test_pa_random_push_prefix(not_excluded);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	/* New lap must have been generated with not_excluded value */
	lap = smock_pull(SMOCK_LAP_UPDATE);
	if(lap) {
		sput_fail_if(strcmp(lap->ifname, TEST_IFNAME_1), "Correct lap ifname");
		sput_fail_if(prefix_cmp(not_excluded, &lap->prefix), "Correct lap prefix");
		sput_fail_unless(lap->priv == &hcp.floodcb, "Correct hcp private field");
		sput_fail_unless(lap->to_delete == 0, "New lap");
		free(lap);
	}

	/* We have also become link owner */
	link = smock_pull(SMOCK_LINK_UPDATE);
	if(link) {
		sput_fail_if(strcmp(link->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(link->owner, "We own the link");
		free(link);
	}
	smock_is_empty();

	/* Now let's add a second router on the same link, that has a lower
	 * id, and that is using the prefix on another link.
	 * A new pa should be scheduled, but no prefix collision detected
	 * because the router has lower id.
	 */
	now_time += 500;
	pa_update_eap(pa, not_excluded, &rid_lower,
					NULL, 0);

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty(); /* Nothing is changed */

	now_time += 500;
	/* The other router stops using that prefix and uses another one */
	pa_update_eap(pa, not_excluded, &rid_lower,
						NULL, 1);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty(); /* Nothing is changed */

	/* Do the same with a router with higher router id */
	now_time += 500;
	pa_update_eap(pa, not_excluded, &rid_higher,
							NULL, 0);

	test_pa_random_push_prefix(excluded); /* Should be rejected due to exclusion */
	test_pa_random_push_prefix(not_excluded); /* Should be rejected due to collision */
	test_pa_random_push_prefix(not_excluded_bis); /* Should be accepted and assigned */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	/* One lap deleted, one created. Still link owner */
	lap = smock_pull(SMOCK_LAP_UPDATE);
	if(lap) {
		sput_fail_if(prefix_cmp(not_excluded, &lap->prefix), "Correct lap prefix");
		sput_fail_unless(lap->to_delete == 1, "Lap must be deleted");
		free(lap);
	}

	lap = smock_pull(SMOCK_LAP_UPDATE);
	if(lap) {
		sput_fail_if(prefix_cmp(not_excluded_bis, &lap->prefix), "Correct lap prefix");
		sput_fail_unless(lap->to_delete == 0, "This is a new lap");
		free(lap);
	}

	/* Removing that lap */
	pa_update_eap(pa, not_excluded, &rid_higher,
								NULL, 1);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty(); /* Nothing is changed */

	/* Now let's see what happens on local links
	 * The guy with lower id comes to our link and annouces a
	 * different prefix. */
	now_time += 500;
	pa_update_eap(pa, not_excluded_tier, &rid_lower,
							TEST_IFNAME_1, 0);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty(); /* Nothing is changed */

	/* The guy removes its assignement */
	pa_update_eap(pa, not_excluded_tier, &rid_lower,
								TEST_IFNAME_1, 1);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	smock_is_empty(); /* Nothing is changed */

	/* Now some guy with higher id comes using the same prefix than us */
	pa_update_eap(pa, not_excluded_bis, &rid_higher,
									TEST_IFNAME_1, 0);
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);
	/* Should remove prefix from hcp and not be owner for the link */
	lap = smock_pull(SMOCK_LAP_UPDATE);
	if(lap) {
		sput_fail_if(prefix_cmp(not_excluded_bis, &lap->prefix), "Correct lap prefix");
		sput_fail_unless(lap->to_delete == 1, "This is a new lap");
		free(lap);
	}

	link = smock_pull(SMOCK_LINK_UPDATE);
	if(link) {
		sput_fail_if(strcmp(link->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_if(link->owner, "We don't own the link anymore");
		free(link);
	}

	smock_is_empty();

	/* Now the neighbor with higher id will use a different prefix.
	 * We should change and use this one. */
	pa_update_eap(pa, not_excluded_bis, &rid_higher,
							TEST_IFNAME_1, 1); /* removing previous one */
	pa_update_eap(pa, not_excluded_tier, &rid_higher,
							TEST_IFNAME_1, 0); /* adding a new one */

	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	smock_is_empty();

	/* Waiting for assignment */
	now_time += TEST_COMMIT_LAP_DELAY;

	/* We need to get the lap to trigger the timeout */
	pa_iface = pa_iface_goc(pa, TEST_IFNAME_1);
	sput_fail_if(list_empty(&pa_iface->laps), "Existing lap");
	pa_lap = list_first_entry(&pa_iface->laps, struct pa_lap, if_le);
	sput_fail_unless(pa_lap, "Get the only current lap");
	if(pa_lap) {
		test_pa_timeout_fire(&pa_lap->delayed.timeout);
	}

	/* Get interface assignment */
	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px) {
		sput_fail_if(strcmp(px->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(px->preferred_until == dp_preferred_until, "Correct preferred lifetime");
		sput_fail_unless(px->valid_until == dp_valid_until, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&px->prefix, not_excluded_tier), "Correct lap prefix");
		sput_fail_unless(px->priv == &iface.ifcb, "Correct private field");
		sput_fail_unless(px->dhcpv6_len == TEST_DHCPV6_LEN, "Correct dhcpv6 len value");
		if(px->dhcpv6_len == TEST_DHCPV6_LEN) {
			sput_fail_if(memcmp(px->dhcpv6_data, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN), "Correct dhcpv6 data value");
		}
		free(px);
	}

	smock_is_empty();

	/* Now let's timeout the dp */
	now_time = dp_valid_until;
	test_pa_timeout_fire(&pa->pa_dp_timeout);
	/* Should unassign the prefix */
	px = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px) {
		sput_fail_if(strcmp(px->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(px->preferred_until == 0, "Correct preferred lifetime");
		sput_fail_unless(px->valid_until == 0, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&px->prefix, not_excluded_tier), "Correct lap prefix");
		sput_fail_unless(px->priv == &iface.ifcb, "Correct private field");
		free(px);
	}

	/* Shoudl stop flooding the prefix */
	ldp = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp) {
		sput_fail_unless(ldp->preferred_until == 0, "Correct preferred lifetime");
		sput_fail_unless(ldp->valid_until == 0, "Correct valid lifetime");
		sput_fail_if(prefix_cmp(&ldp->prefix, prefix), "Correct prefix value");
		free(ldp);
	}

	smock_is_empty();

	/* Destroy the remaining eap */
	pa_update_eap(pa, not_excluded_tier, &rid_higher,
								TEST_IFNAME_1, 1);

	/* This will create a schedule, but nothing happens then */
	now_time += PA_SCHEDULE_RUNNEXT_MS;
	test_pa_timeout_fire(&pa->pa_short_timeout);

	smock_is_empty();

	/* Removing the interface */
	iface.user->cb_intiface(iface.user, TEST_IFNAME_1, false);
	smock_is_empty();

	pa_test_pa_empty();
}


/* This test adds one dp and one iface,
 * with nobody else on the link. And then removes it.
 * This function test deeply pa behaviour by looking at
 * all scheduled timeouts. */
void pa_test_minimal(void)
{
	test_schedule_events = 1;
	mask_random = 0;

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

	iface.user->cb_prefix(iface.user, TEST_IFNAME_1, &p1, NULL,
			valid_until, preferred_until, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN);

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
		sput_fail_unless(ldp_update->dhcpv6_len == TEST_DHCPV6_LEN, "Correct dhcpv6 len value");
		if(ldp_update->dhcpv6_len == TEST_DHCPV6_LEN) {
			sput_fail_if(memcmp(ldp_update->dhcpv6_data, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN), "Correct dhcpv6 data value");
		}
		sput_fail_if(strcmp(ldp_update->dp_ifname, TEST_IFNAME_1), "Correct dp_ifname value");
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
		free(link_update);
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
		sput_fail_unless(px_update->priv == &iface.ifcb, "Correct private field");
		sput_fail_unless(px_update->dhcpv6_len == TEST_DHCPV6_LEN, "Correct dhcpv6 len value");
		if(px_update->dhcpv6_len == TEST_DHCPV6_LEN) {
			sput_fail_if(memcmp(px_update->dhcpv6_data, TEST_DHCPV6_DATA, TEST_DHCPV6_LEN), "Correct dhcpv6 data value");
		}
		free(px_update);
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
		free(lap_update);
	}

	ldp_update = smock_pull(SMOCK_LDP_UPDATE);
	if(ldp_update) {
		sput_fail_if(prefix_cmp(&ldp_update->prefix, &p1), "Correct dp value");
		sput_fail_unless(ldp_update->valid_until == 0, "Dp must be deleted");
		free(ldp_update);
	}

	link_update = smock_pull(SMOCK_LINK_UPDATE);
	if(link_update) {
		sput_fail_if(strcmp(link_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_unless(!link_update->owner, "Not owner anymore");
		free(link_update);
	}

	px_update = smock_pull(SMOCK_PREFIX_UPDATE);
	if(px_update) {
		sput_fail_if(strcmp(px_update->ifname, TEST_IFNAME_1), "Correct link ifname");
		sput_fail_if(prefix_cmp(&px_update->prefix, &chosen_prefix), "Correct prefix");
		sput_fail_unless(!px_update->valid_until, "Prefix should be unassigned");
		free(px_update);
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

	pa_test_pa_empty();
}

/* This test initialized the pa
 * and checks if everything is ok */
void pa_test_init(void)
{
	test_schedule_events = 1;
	mask_random = 0;

	int res, ms;
	struct uloop_timeout *to;

	now_time = 0;

	conf.commit_lap_delay = TEST_COMMIT_LAP_DELAY;
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
	now_time = PA_SCHEDULE_RUNNEXT_MS;
	pa_do_uloop(to);

	/* No dp or iface => No new schedule */
	sput_fail_unless(smock_empty(), "End of init with empty smock queues");

	pa_test_pa_empty();
}

/* Testing pa.c subfunctions */
void pa_test_misc(void)
{
	sput_fail_if(PA_RIDCMP(&rid, &rid), "Same rid should be equal");
	sput_fail_unless(PA_RIDCMP(&rid, &rid_higher), "Different rids should be... different");
	sput_fail_unless(PA_RIDCMP(&rid_higher, &rid) > 0, "Higher rid should be higher");
	sput_fail_unless(PA_RIDCMP(&rid_lower, &rid) < 0, "Lower rid should be lower");
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
	int urandom_fd;
	if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) >= 0) {
		unsigned int seed;
		read(urandom_fd, &seed, sizeof(seed));
		close(urandom_fd);
		srandom(seed);
	}

	openlog("hnetd_test_pa", LOG_PERROR | LOG_PID, LOG_DAEMON);


	sput_start_testing();

	sput_enter_suite("Prefix assignment algorithm (pa.c)"); /* optional */

	sput_run_test(pa_test_misc);

	pa_conf_default(&conf);
	sput_run_test(pa_test_init);
	sput_run_test(pa_test_minimal);
	sput_run_test(pa_test_collisions);
	sput_run_test(pa_test_multiple_ifaces);
	sput_run_test(pa_test_destroy);

	sput_leave_suite(); /* optional */

	sput_enter_suite("pa + storage"); /* optional */

	pa_conf_default(&conf);
	store_conf.max_px = 100;
	store_conf.max_px_per_if = 10;
	conf.storage = pa_store_create(&store_conf, PA_STORE_FILE);
	pa_store_empty(conf.storage);
	sput_fail_unless(conf.storage, "Pa store successfully created");

	if(conf.storage) {
		sput_run_test(pa_test_init);
		sput_run_test(pa_test_storage);
		sput_run_test(pa_test_destroy);
		pa_store_destroy(conf.storage);
	}

	sput_leave_suite(); /* optional */
	sput_finish_testing();
	return sput_get_return_value();
}
