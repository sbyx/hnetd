/*
 * $Id: test_dncp_nio.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 10:02:45 2013 mstenber
 * Last modified: Tue Feb 10 20:47:47 2015 mstenber
 * Edit time:     235 min
 *
 */

/* This test code assumes that we have wrapped dncp_io to produce fake
 * input+output, as well as fake hnetd_time to produce fake time
 * signal. With those, we can prod the state machine(s) as much as we
 * want to without actually needing to have real sockets or wait for
 * long periods of time.. */

#include "hnetd.h"
#include <stdlib.h>
#define random random_mock
static int random_mock(void);

#include <net/if.h>
#define FIXED_IF_INDEX 42
struct in6_addr fixed_ia6;
#define FIXED_PORT 1234

#define if_nametoindex(x) FIXED_IF_INDEX

#include "dncp.c"
#include "dncp_notify.c"
#include "dncp_proto.c"
#include "dncp_timeout.c"
#include "sput.h"
#include "smock.h"

/* Work-around to prevent side effects of dncp_if_set_enabled; it
   produces some TLVs now on it's own, and this test code does not
   deal with it yet. Could adapt test code at some point.. -MSt 02/2015
*/
#define dncp_if_set_enabled(o, ifname, val) \
  dncp_find_link_by_name(o, ifname, true)

int log_level = LOG_DEBUG;

/********************************************************* Mocked interfaces */

bool check_timing = true;
bool check_send = true;
bool check_random = true;

int want_schedule;
int want_send;
hnetd_time_t current_hnetd_time;

/* Fake version of the I/O interface. */
bool dncp_io_init(dncp o)
{
  o->udp_socket = 1;
  sput_fail_unless(o, "hncp");
  o->disable_prune = true;
  return smock_pull_bool("init_result");
}
void dncp_io_uninit(dncp o)
{
  o->udp_socket = 0;
  sput_fail_unless(o, "hncp");
  smock_pull("uninit");
}

bool dncp_io_set_ifname_enabled(dncp o, const char *ifname, bool enabled)
{
  sput_fail_unless(o, "hncp");
  sput_fail_unless(o && o->udp_socket == 1, "dncp_io ready");
  smock_pull_string_is("set_enable_ifname", ifname);
  smock_pull_bool_is("set_enable_enabled", enabled);
  return smock_pull_bool("set_enable_result");
}

int dncp_io_get_hwaddrs(unsigned char *buf, int buf_left)
{
  unsigned char *r = smock_pull("get_hwaddrs_buf");
  int r_len = smock_pull_int("get_hwaddrs_len");

  memcpy(buf, r, r_len);
  sput_fail_unless(r_len <= buf_left, "result length reasonable");
  return r_len;
}

void dncp_io_schedule(dncp o, int msecs)
{
  if (check_timing)
    {
      sput_fail_unless(o, "hncp");
      sput_fail_unless(o && o->udp_socket == 1, "dncp_io ready");
      smock_pull_int_is("schedule", msecs);
    }
  else
    {
      want_schedule = msecs;
    }
}

ssize_t dncp_io_recvfrom(dncp o, void *buf, size_t len,
                         char *ifname,
                         struct sockaddr_in6 *src,
                         struct in6_addr *dst)
{
  unsigned char *r = smock_pull("recvfrom_buf");
  int r_len = smock_pull_int("recvfrom_len");
  struct sockaddr_in6 *r_src = smock_pull("recvfrom_src");
  struct in6_addr *r_dst = smock_pull("recvfrom_dst");
  smock_pull_string_is("recvfrom_ifname", ifname);

  sput_fail_unless(o, "hncp");
  sput_fail_unless(o && o->udp_socket == 1, "dncp_io_schedule valid");
  sput_fail_unless(r_len <= ((int) len), "result length reasonable");
  *src = *r_src;
  *dst = *r_dst;
  memcpy(buf, r, r_len);
  return r_len;
}

ssize_t dncp_io_sendto(dncp o, void *buf, size_t len,
                       const struct sockaddr_in6 *dst)
{
  if (check_send)
    {
      sput_fail_unless(o, "hncp");
      sput_fail_unless(o && o->udp_socket == 1, "dncp_io ready");
      struct sockaddr_in6 *e_dst = smock_pull("sendto_dst");
      sput_fail_unless(e_dst && memcmp(e_dst, dst, sizeof(*dst)) == 0, "dst match");
      /* Two optional verification steps.. */
      if (_smock_get_queue("sendto_len", false))
        {
          int r_len = smock_pull_int("sendto_len");
          sput_fail_unless(r_len == (int) len, "len");
        }
      if (_smock_get_queue("sendto_buf", false))
        {
          unsigned char *r = smock_pull("sendto_buf");
          sput_fail_unless(memcmp(r, buf, len), "buf");
        }
      return smock_pull_int("sendto_return");
    }
  else
    {
      want_send++;
      return 1;
    }
}

hnetd_time_t dncp_io_time(dncp o __unused)
{
  if (check_timing)
    return smock_pull_int("time");
  return current_hnetd_time;
}

static int random_mock(void)
{
  if (check_random)
    return smock_pull_int("random");
#undef random
  return random();
}

/************************************************************* Dummy profile */

struct tlv_attr *dncp_profile_node_validate_data(dncp_node n __unused,
                                                 struct tlv_attr *a)
{
  return a;
}

/* Profile-specific method of sending keep-alive on a link. */
void dncp_profile_link_send_network_state(dncp_link l)
{
  struct sockaddr_in6 dst =
    { .sin6_family = AF_INET6,
      .sin6_addr = fixed_ia6,
      .sin6_port = htons(FIXED_PORT),
      .sin6_scope_id = FIXED_IF_INDEX
    };
  dncp_link_send_network_state(l, &dst, 0);
}

/* Profile hook to allow overriding collision handling. */
bool dncp_profile_handle_collision(dncp o __unused)
{
  return false;
}


/********************************************************** Fake subscribers */

static void dummy_tlv_cb(dncp_subscriber s,
                         dncp_node n, struct tlv_attr *tlv, bool add)
{
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->tlv_change_callback == dummy_tlv_cb, "tlv cb set");
  sput_fail_unless(n, "node set");
  sput_fail_unless(tlv, "tlv set");
  L_NOTICE("tlv callback %s/%s %s",
           DNCP_NODE_REPR(n), TLV_REPR(tlv), add ? "add" : "remove");
  int exp_v = (add ? 1 : -1) * tlv_id(tlv);
  smock_pull_int_is("tlv_callback", exp_v);
}

static void dummy_local_tlv_cb(dncp_subscriber s,
                               struct tlv_attr *tlv, bool add)
{
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->local_tlv_change_callback == dummy_local_tlv_cb,
                   "tlv cb set");
  sput_fail_unless(tlv, "tlv set");
  L_NOTICE("local tlv callback %s %s", TLV_REPR(tlv), add ? "add" : "remove");
  int exp_v = (add ? 1 : -1) * tlv_id(tlv);
  smock_pull_int_is("local_tlv_callback", exp_v);
}

static void dummy_node_cb(dncp_subscriber s, dncp_node n, bool add)
{
  L_NOTICE("node callback %s %s",
           DNCP_NODE_REPR(n), add ? "add" : "remove");
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->node_change_callback == dummy_node_cb, "node cb set");
  sput_fail_unless(n, "node set");
  smock_pull_bool_is("node_callback", add);
}

static void dummy_republish_cb(dncp_subscriber s __unused)
{
  L_NOTICE("republish callback");
  smock_pull("republish_callback");
}

static dncp_subscriber_s dummy_subscriber_1 = {
  .tlv_change_callback = dummy_tlv_cb
};

static dncp_subscriber_s dummy_subscriber_2 = {
  .node_change_callback = dummy_node_cb
};

static dncp_subscriber_s dummy_subscriber_3 = {
  .republish_callback = dummy_republish_cb
};


static dncp_subscriber_s dummy_subscriber_4 = {
  .local_tlv_change_callback = dummy_local_tlv_cb
};


/******************************************************* Start of test cases */

static char *dummy_ifname = "eth0";

static void hncp_init_no_hwaddr(void)
{
  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddrs_buf", NULL);
  smock_push_int("get_hwaddrs_len", 0);

  dncp o = dncp_create();
  sput_fail_unless(!o, "dncp_create -> !hncp");
  smock_is_empty();
}

static void hncp_init_iofail(void)
{
  char buf[4] = "foo";

  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddrs_buf", buf);
  smock_push_int("get_hwaddrs_len", sizeof(buf));

  /* io init succeeds */
  smock_push_bool("init_result", false);

  dncp o = dncp_create();
  sput_fail_unless(!o, "dncp_create -> !hncp");
  smock_is_empty();
}

static dncp create_hncp(void)
{
  char buf[4] = "foo";

  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddrs_buf", buf);
  smock_push_int("get_hwaddrs_len", sizeof(buf));

  /* io init succeeds */
  smock_push_bool("init_result", true);

  /* schedule happens _once_ */
  smock_push("schedule", NULL);

  dncp o = dncp_create();
  sput_fail_unless(o, "dncp_create -> hncp");
  smock_is_empty();

  /* clear the scheduled timeout - for now, we're empty slate anyway*/
  smock_push_int("time", 0);
  /* second one occurs from originating us (no caching due to 0 return value) */
  smock_push_int("time", 0);
  dncp_run(o);
  smock_is_empty();

  /* Disable keep-alives; this is essentially Trickle-only test
   * set. */
  dncp_link_conf conf = dncp_if_find_conf_by_name(o, dummy_ifname);
  conf->keepalive_interval = 0;

  return o;
}

static void destroy_hncp(dncp o)
{
  smock_push("uninit", NULL);
  dncp_destroy(o);
  smock_is_empty();
}


static void hncp_ok_minimal(void)
{
  dncp o = create_hncp();
  destroy_hncp(o);
}

static void one_join(bool ok)
{
  smock_push("set_enable_ifname", dummy_ifname);
  smock_push_bool("set_enable_enabled", true);
  smock_push_bool("set_enable_result", ok);
}

static void hncp_rejoin_works(void)
{
  dncp o = create_hncp();
  int t = 123000;


  /* we'll try to join dummy_ifname; however, it fails. */
  smock_is_empty();
  smock_push_int("schedule", 0);
  dncp_if_set_enabled(o, dummy_ifname, true);
  smock_is_empty();

  one_join(false);
  smock_push_int("schedule", DNCP_REJOIN_INTERVAL);
  smock_push_int("time", t);
  dncp_run(o);
  smock_is_empty();

  /* make sure next timeout before DNCP_REJOIN_INTERVAL just re-schedules. */
  t += DNCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", DNCP_REJOIN_INTERVAL / 2);
  dncp_run(o);
  smock_is_empty();

  /* now that the time _has_ expired, we should try joining.. fail again. */
  t += DNCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", DNCP_REJOIN_INTERVAL);
  one_join(false);
  dncp_run(o);
  smock_is_empty();

  /* again try after DNCP_REJOIN_INTERVAL, it should work. trickle
   * scheduling should require exactly one random call. */
  t += DNCP_REJOIN_INTERVAL;
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", DNCP_TRICKLE_IMIN / 2);
  one_join(true);
  dncp_run(o);
  smock_is_empty();

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hncp(o);
}


static void hncp_ok(void)
{
  dncp o = create_hncp();
  int t = 123000;
  int i;

  memset(&fixed_ia6, 1, sizeof(fixed_ia6));

  /* Pushing in a new subscriber should result in us being called. */
  smock_is_empty();
  smock_push_bool("node_callback", true);
  dncp_subscribe(o, &dummy_subscriber_1);
  dncp_subscribe(o, &dummy_subscriber_2);
  dncp_subscribe(o, &dummy_subscriber_3);
  dncp_subscribe(o, &dummy_subscriber_4);

  smock_is_empty();
  smock_push_int("schedule", 0);
  dncp_if_set_enabled(o, dummy_ifname, true);
  smock_is_empty();

  /* The join really happens within _run. */
  one_join(true);

  /* Ok. We're cooking with gas. */
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", DNCP_TRICKLE_IMIN / 2);
  dncp_run(o);
  smock_is_empty();

  t += DNCP_TRICKLE_IMIN / 2 - 1;
  smock_push_int("time", t);
  smock_push_int("schedule", 1);
  dncp_run(o);
  smock_is_empty();

  t += 1;
  /* Ok. we get timestamp -> woah, need to do something. */
  smock_push_int("time", t);

  /* Should send stuff on an interface. */
  struct sockaddr_in6 dummydst = { .sin6_family = AF_INET6,
                                   .sin6_addr = fixed_ia6,
                                   .sin6_port = htons(FIXED_PORT),
                                   .sin6_scope_id = FIXED_IF_INDEX
  };
  smock_push("sendto_dst", &dummydst);
  smock_push_int("sendto_return", 1);

  /* And schedule next one (=end of interval). */
  smock_push_int("schedule", DNCP_TRICKLE_IMIN / 2);
  dncp_run(o);
  smock_is_empty();

  /* overshoot what we were asked for.. shouldn't be a problem. */
  t += DNCP_TRICKLE_IMIN;
  smock_push_int("time", t);
  /* should be queueing next send, and now we go for 'max' value. */
  smock_push_int("random", 999);
  smock_push_int("schedule", 2 * DNCP_TRICKLE_IMIN * (1000 + 999) / 2000);
  dncp_run(o);
  smock_is_empty();

  /* run the clock until we hit DNCP_TRICKLE_IMAX/2 delay; or we run
   * out of iterations. */
  check_timing = false;
  check_send = false;
  check_random = false;
  want_send = 0;
  for (i = 0 ; i < 100 ; i++)
    {
      current_hnetd_time = t;
      want_schedule = 0;
      dncp_run(o);
      if (want_schedule >= (DNCP_TRICKLE_IMAX / 2))
        {
          sput_fail_unless(want_schedule <= DNCP_TRICKLE_IMAX, "reasonable timeout");
          break;
        }
      t += want_schedule;
      current_hnetd_time += want_schedule;
    }
  sput_fail_unless(want_send <= i / 2, "few sends");
  sput_fail_unless(i < 100, "did not encounter big enough delta");
  /* then, run for few more iterations, making sure we don't hit too long ones. */
  want_send = 0;
  for (i = 0 ; i < 10 ; i++)
    {
      current_hnetd_time = t;
      want_schedule = 0;
      dncp_run(o);
      sput_fail_unless(want_schedule <= DNCP_TRICKLE_IMAX, "reasonable timeout");
      t += want_schedule;
      current_hnetd_time += want_schedule;
    }
  sput_fail_unless(want_send > 0 && want_send <= i / 2, "few sends");
  check_timing = true;
  check_send = true;
  check_random = true;

  /* Ok, Trickle was in a stable state 'long' time. Make sure the
   * state resets once we push something new in. */
  L_NOTICE("add tlv a");
#define TLV_ID_A 123
#define TLV_ID_B 125
#define TLV_ID_C 127
#define TLV_ID_D 124
  smock_push_int("schedule", 0);
  smock_push_int("local_tlv_callback", TLV_ID_A);
  dncp_add_tlv(o, TLV_ID_A, NULL, 0, 0);
  smock_is_empty();

  L_NOTICE("add tlv b");
  /* should NOT cause extra schedule! */
  smock_push_int("local_tlv_callback", TLV_ID_B);
  dncp_add_tlv(o, TLV_ID_B, NULL, 0, 0);
  smock_is_empty();

  L_NOTICE("running.");
  printf("last run starting\n");
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", DNCP_TRICKLE_IMIN / 2);

  /* Should get notification about two added TLVs. */
  smock_push_int("tlv_callback", TLV_ID_A);
  smock_push_int("tlv_callback", TLV_ID_B);
  smock_push_bool("republish_callback", true);
  dncp_run(o);
  smock_is_empty();

  /* Adding / removing last entry have special handling. So let's
   * test both by adding and removing tlv c (which > a, b). */

  /* Our interest in timing has waned by now though, so we disable
   * those checks. */
  check_timing = false;
  check_random = false;

  /* So, let's add one more TLV. Make sure we get notification about it. */
  L_NOTICE("add tlv c");
  smock_push_int("local_tlv_callback", TLV_ID_C);
  dncp_add_tlv(o, TLV_ID_C, NULL, 0, 0);
  smock_is_empty();
  smock_push_int("tlv_callback", TLV_ID_C);
  smock_push_bool("republish_callback", true);
  dncp_run(o);
  smock_is_empty();

  /* Remove it. */
  L_NOTICE("remove tlv c");
  smock_push_int("local_tlv_callback", -TLV_ID_C);
  dncp_remove_tlv_matching(o, TLV_ID_C, NULL, 0);
  smock_is_empty();
  smock_push_int("tlv_callback", -TLV_ID_C);
  smock_push_bool("republish_callback", true);
  dncp_run(o);
  smock_is_empty();

  /* Add TLV D in the middle. */
  L_NOTICE("add tlv d");
  smock_push_int("local_tlv_callback", TLV_ID_D);
  dncp_add_tlv(o, TLV_ID_D, NULL, 0, 0);
  smock_is_empty();
  smock_push_int("tlv_callback", TLV_ID_D);
  smock_push_bool("republish_callback", true);
  dncp_run(o);
  smock_is_empty();

  /* Unsubscribing should result in callbacks too. */
  L_NOTICE("unsubscribe");
  smock_push_int("local_tlv_callback", -TLV_ID_A);
  smock_push_int("local_tlv_callback", -TLV_ID_D);
  smock_push_int("local_tlv_callback", -TLV_ID_B);
  smock_push_int("tlv_callback", -TLV_ID_A);
  smock_push_int("tlv_callback", -TLV_ID_D);
  smock_push_int("tlv_callback", -TLV_ID_B);
  smock_push_bool("node_callback", false);
  dncp_unsubscribe(o, &dummy_subscriber_1);
  dncp_unsubscribe(o, &dummy_subscriber_2);
  dncp_unsubscribe(o, &dummy_subscriber_3);
  dncp_unsubscribe(o, &dummy_subscriber_4);
  smock_is_empty();

  /* Re-enable checks */
  check_timing = true;
  check_random = true;

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hncp(o);
}

static void hncp_49d_republish()
{

  dncp o = create_hncp();

  check_timing = false;
  check_random = false;
  check_send = false;

  current_hnetd_time = 123000;

  int i;
  dncp_link_conf lc = dncp_if_find_conf_by_name(o, dummy_ifname);
  lc->trickle_imax = HNETD_TIME_PER_SECOND * 86400;
  lc->keepalive_interval = 0;

  dncp_if_set_enabled(o, dummy_ifname, true);
  smock_is_empty();

  /* The join really happens within _run. */
  one_join(true);

  /* Set Trickle maximum interval to a day, so we don't have to do
   * zillion iterations to hit 49d.. Unfortunately,
   * post-timeout-kludge, we _will_ have timeout every minute or so
   * (65.x seconds). */

  for (i = 0 ; i < (1 << 17) ; i++)
    {
      want_schedule = 0;
      dncp_run(o);
      current_hnetd_time += want_schedule;
    }
  sput_fail_unless(current_hnetd_time  >
                   (1LL<<32), "time advanced enough");
  sput_fail_unless((current_hnetd_time - o->own_node->origination_time) <
                   (1LL<<32), "fresh own tlv");

  check_timing = true;
  check_random = true;
  check_send = true;
}

#define maybe_run_test(fun) sput_maybe_run_test(fun, do {} while(0))

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp_nio", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hncp_nio"); /* optional */
  argc -= 1;
  argv += 1;

  maybe_run_test(hncp_init_no_hwaddr);
  maybe_run_test(hncp_init_iofail);
  maybe_run_test(hncp_ok_minimal);
  maybe_run_test(hncp_rejoin_works);
  maybe_run_test(hncp_ok);
  maybe_run_test(hncp_49d_republish);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
