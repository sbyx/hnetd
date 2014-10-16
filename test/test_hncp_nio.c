/*
 * $Id: test_hncp_nio.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 10:02:45 2013 mstenber
 * Last modified: Thu Oct 16 10:04:46 2014 mstenber
 * Edit time:     175 min
 *
 */

/* This test code assumes that we have wrapped hncp_io to produce fake
 * input+output, as well as fake hnetd_time to produce fake time
 * signal. With those, we can prod the state machine(s) as much as we
 * want to without actually needing to have real sockets or wait for
 * long periods of time.. */

#include "hnetd.h"
#include <stdlib.h>
#define random random_mock
static int random_mock(void);
#include "hncp.c"
#include "hncp_notify.c"
#include "hncp_proto.c"
#include "hncp_timeout.c"
#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;

/********************************************************* Mocked interfaces */

bool check_timing = true;
bool check_send = true;
bool check_random = true;

int want_schedule;
int want_send;
int current_hnetd_time;

/* Fake version of the I/O interface. */
bool hncp_io_init(hncp o)
{
  o->udp_socket = 1;
  sput_fail_unless(o, "hncp");
  o->disable_prune = true;
  return smock_pull_bool("init_result");
}
void hncp_io_uninit(hncp o)
{
  o->udp_socket = 0;
  sput_fail_unless(o, "hncp");
  smock_pull("uninit");
}

bool hncp_io_set_ifname_enabled(hncp o, const char *ifname, bool enabled)
{
  sput_fail_unless(o, "hncp");
  sput_fail_unless(o && o->udp_socket == 1, "hncp_io ready");
  smock_pull_string_is("set_enable_ifname", ifname);
  smock_pull_bool_is("set_enable_enabled", enabled);
  return smock_pull_bool("set_enable_result");
}

int hncp_io_get_hwaddrs(unsigned char *buf, int buf_left)
{
  unsigned char *r = smock_pull("get_hwaddrs_buf");
  int r_len = smock_pull_int("get_hwaddrs_len");

  memcpy(buf, r, r_len);
  sput_fail_unless(r_len <= buf_left, "result length reasonable");
  return r_len;
}

void hncp_io_schedule(hncp o, int msecs)
{
  if (check_timing)
    {
      sput_fail_unless(o, "hncp");
      sput_fail_unless(o && o->udp_socket == 1, "hncp_io ready");
      smock_pull_int_is("schedule", msecs);
    }
  else
    {
      want_schedule = msecs;
    }
}

ssize_t hncp_io_recvfrom(hncp o, void *buf, size_t len,
                         char *ifname,
                         struct in6_addr *src,
                         uint16_t *src_port,
                         struct in6_addr *dst)
{
  unsigned char *r = smock_pull("recvfrom_buf");
  int r_len = smock_pull_int("recvfrom_len");
  struct in6_addr *r_src = smock_pull("recvfrom_src");
  struct in6_addr *r_dst = smock_pull("recvfrom_dst");
  smock_pull_string_is("recvfrom_ifname", ifname);

  sput_fail_unless(o, "hncp");
  sput_fail_unless(o && o->udp_socket == 1, "hncp_io_schedule valid");
  sput_fail_unless(r_len <= ((int) len), "result length reasonable");
  *src = *r_src;
  *src_port = o->udp_port;
  *dst = *r_dst;
  memcpy(buf, r, r_len);
  return r_len;
}

ssize_t hncp_io_sendto(hncp o, void *buf, size_t len,
                       const char *ifname,
                       const struct in6_addr *dst, uint16_t dst_port)
{
  if (check_send)
    {
      sput_fail_unless(o, "hncp");
      sput_fail_unless(!dst_port || dst_port == o->udp_port,
                       "weird destination port");
      sput_fail_unless(o && o->udp_socket == 1, "hncp_io ready");
      smock_pull_string_is("sendto_ifname", ifname);
      struct in6_addr *e_dst = smock_pull("sendto_dst");
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

hnetd_time_t hncp_io_time(hncp o __unused)
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

/********************************************************** Fake subscribers */

static void dummy_tlv_cb(hncp_subscriber s,
                         hncp_node n, struct tlv_attr *tlv, bool add)
{
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->tlv_change_callback == dummy_tlv_cb, "tlv cb set");
  sput_fail_unless(n, "node set");
  sput_fail_unless(tlv, "tlv set");
  L_NOTICE("tlv callback %s/%s %s",
           HNCP_NODE_REPR(n), TLV_REPR(tlv), add ? "add" : "remove");
  if (tlv_id(tlv) == HNCP_T_VERSION) return;
  int exp_v = (add ? 1 : -1) * tlv_id(tlv);
  smock_pull_int_is("tlv_callback", exp_v);
}

static void dummy_local_tlv_cb(hncp_subscriber s,
                               struct tlv_attr *tlv, bool add)
{
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->local_tlv_change_callback == dummy_local_tlv_cb,
                   "tlv cb set");
  sput_fail_unless(tlv, "tlv set");
  L_NOTICE("local tlv callback %s %s", TLV_REPR(tlv), add ? "add" : "remove");
  if (tlv_id(tlv) == HNCP_T_VERSION) return;
  int exp_v = (add ? 1 : -1) * tlv_id(tlv);
  smock_pull_int_is("local_tlv_callback", exp_v);
}

static void dummy_node_cb(hncp_subscriber s, hncp_node n, bool add)
{
  L_NOTICE("node callback %s %s",
           HNCP_NODE_REPR(n), add ? "add" : "remove");
  sput_fail_unless(s, "subscriber provided");
  sput_fail_unless(s->node_change_callback == dummy_node_cb, "node cb set");
  sput_fail_unless(n, "node set");
  smock_pull_bool_is("node_callback", add);
}

static void dummy_republish_cb(hncp_subscriber s __unused)
{
  L_NOTICE("republish callback");
  smock_pull("republish_callback");
}

static hncp_subscriber_s dummy_subscriber_1 = {
  .tlv_change_callback = dummy_tlv_cb
};

static hncp_subscriber_s dummy_subscriber_2 = {
  .node_change_callback = dummy_node_cb
};

static hncp_subscriber_s dummy_subscriber_3 = {
  .republish_callback = dummy_republish_cb
};


static hncp_subscriber_s dummy_subscriber_4 = {
  .local_tlv_change_callback = dummy_local_tlv_cb
};


/******************************************************* Start of test cases */

static char *dummy_ifname = "eth0";

static void hncp_init_no_hwaddr(void)
{
  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddrs_buf", NULL);
  smock_push_int("get_hwaddrs_len", 0);

  hncp o = hncp_create();
  sput_fail_unless(!o, "hncp_create -> !hncp");
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

  hncp o = hncp_create();
  sput_fail_unless(!o, "hncp_create -> !hncp");
  smock_is_empty();
}

static hncp create_hncp(void)
{
  char buf[4] = "foo";

  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddrs_buf", buf);
  smock_push_int("get_hwaddrs_len", sizeof(buf));

  /* io init succeeds */
  smock_push_bool("init_result", true);

  /* schedule happens _once_ */
  smock_push("schedule", NULL);

  hncp o = hncp_create();
  sput_fail_unless(o, "hncp_create -> hncp");
  smock_is_empty();

  /* clear the scheduled timeout - for now, we're empty slate anyway*/
  smock_push_int("time", 0);
  /* second one occurs from originating us (no caching due to 0 return value) */
  smock_push_int("time", 0);
  hncp_run(o);
  smock_is_empty();

  return o;
}

static void destroy_hncp(hncp o)
{
  smock_push("uninit", NULL);
  hncp_destroy(o);
  smock_is_empty();
}


static void hncp_ok_minimal(void)
{
  hncp o = create_hncp();
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
  hncp o = create_hncp();
  int t = 123000;


  /* we'll try to join dummy_ifname; however, it fails. */
  smock_is_empty();
  one_join(false);
  smock_push_int("schedule", 0);
  smock_push_int("time", t);
  hncp_if_set_enabled(o, dummy_ifname, true);
  smock_is_empty();

  /* make sure next timeout before HNCP_REJOIN_INTERVAL just re-schedules. */
  t += HNCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", HNCP_REJOIN_INTERVAL / 2);
  hncp_run(o);
  smock_is_empty();

  /* now that the time _has_ expired, we should try joining.. fail again. */
  t += HNCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", HNCP_REJOIN_INTERVAL);
  one_join(false);
  hncp_run(o);
  smock_is_empty();

  /* again try after HNCP_REJOIN_INTERVAL, it should work. trickle
   * scheduling should require exactly one random call. */
  t += HNCP_REJOIN_INTERVAL;
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", HNCP_TRICKLE_IMIN / 2);
  one_join(true);
  hncp_run(o);
  smock_is_empty();

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hncp(o);
}


static void hncp_ok(void)
{
  hncp o = create_hncp();
  int t = 123000;
  int i;

  /* Pushing in a new subscriber should result in us being called. */
  smock_is_empty();
  smock_push_bool("node_callback", true);
  hncp_subscribe(o, &dummy_subscriber_1);
  hncp_subscribe(o, &dummy_subscriber_2);
  hncp_subscribe(o, &dummy_subscriber_3);
  hncp_subscribe(o, &dummy_subscriber_4);

  smock_is_empty();
  one_join(true);
  smock_push_int("schedule", 0);
  hncp_if_set_enabled(o, dummy_ifname, true);
  smock_is_empty();

  /* Ok. We're cooking with gas. */
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", HNCP_TRICKLE_IMIN / 2);
  hncp_run(o);
  smock_is_empty();

  t += HNCP_TRICKLE_IMIN / 2 - 1;
  smock_push_int("time", t);
  smock_push_int("schedule", 1);
  hncp_run(o);
  smock_is_empty();

  t += 1;
  /* Ok. we get timestamp -> woah, need to do something. */
  smock_push_int("time", t);

  /* Should send stuff on an interface. */
  smock_push("sendto_ifname", dummy_ifname);
  smock_push("sendto_dst", &o->multicast_address);
  smock_push_int("sendto_return", 1);

  /* And schedule next one (=end of interval). */
  smock_push_int("schedule", HNCP_TRICKLE_IMIN / 2);
  hncp_run(o);
  smock_is_empty();

  /* overshoot what we were asked for.. shouldn't be a problem. */
  t += HNCP_TRICKLE_IMIN;
  smock_push_int("time", t);
  /* should be queueing next send, and now we go for 'max' value. */
  smock_push_int("random", 999);
  smock_push_int("schedule", 2 * HNCP_TRICKLE_IMIN * (1000 + 999) / 2000);
  hncp_run(o);
  smock_is_empty();

  /* run the clock until we hit HNCP_TRICKLE_IMAX/2 delay; or we run
   * out of iterations. */
  check_timing = false;
  check_send = false;
  check_random = false;
  want_send = 0;
  for (i = 0 ; i < 100 ; i++)
    {
      current_hnetd_time = t;
      want_schedule = 0;
      hncp_run(o);
      if (want_schedule >= (HNCP_TRICKLE_IMAX / 2))
        {
          sput_fail_unless(want_schedule <= HNCP_TRICKLE_IMAX, "reasonable timeout");
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
      hncp_run(o);
      sput_fail_unless(want_schedule <= HNCP_TRICKLE_IMAX, "reasonable timeout");
      t += want_schedule;
      current_hnetd_time += want_schedule;
    }
  sput_fail_unless(want_send > 0 && want_send <= i / 2, "few sends");
  check_timing = true;
  check_send = true;
  check_random = true;

  /* Ok, Trickle was in a stable state 'long' time. Make sure the
   * state resets once we push something new in. */
  struct tlv_attr ta;
  L_NOTICE("add tlv a");
#define TLV_ID_A 123
#define TLV_ID_B 125
#define TLV_ID_C 127
#define TLV_ID_D 124
  tlv_init(&ta, TLV_ID_A, 4);
  smock_push_int("schedule", 0);
  smock_push_int("local_tlv_callback", TLV_ID_A);
  hncp_add_tlv(o, &ta);
  smock_is_empty();

  L_NOTICE("add tlv b");
  tlv_init(&ta, TLV_ID_B, 4);
  /* should NOT cause extra schedule! */
  smock_push_int("local_tlv_callback", TLV_ID_B);
  hncp_add_tlv(o, &ta);
  smock_is_empty();

  L_NOTICE("running.");
  printf("last run starting\n");
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", 0);

  /* Should get notification about two added TLVs. */
  smock_push_int("tlv_callback", TLV_ID_A);
  smock_push_int("tlv_callback", TLV_ID_B);
  smock_push_bool("republish_callback", true);
  hncp_run(o);
  smock_is_empty();

  /* Adding / removing last entry have special handling. So let's
   * test both by adding and removing tlv c (which > a, b). */

  /* Our interest in timing has waned by now though, so we disable
   * those checks. */
  check_timing = false;
  check_random = false;

  /* So, let's add one more TLV. Make sure we get notification about it. */
  L_NOTICE("add tlv c");
  tlv_init(&ta, TLV_ID_C, 4);
  smock_push_int("local_tlv_callback", TLV_ID_C);
  hncp_add_tlv(o, &ta);
  smock_is_empty();
  smock_push_int("tlv_callback", TLV_ID_C);
  smock_push_bool("republish_callback", true);
  hncp_run(o);
  smock_is_empty();

  /* Remove it. */
  L_NOTICE("remove tlv c");
  smock_push_int("local_tlv_callback", -TLV_ID_C);
  hncp_remove_tlv(o, &ta);
  smock_is_empty();
  smock_push_int("tlv_callback", -TLV_ID_C);
  smock_push_bool("republish_callback", true);
  hncp_run(o);
  smock_is_empty();

  /* Add TLV D in the middle. */
  L_NOTICE("add tlv d");
  tlv_init(&ta, TLV_ID_D, 4);
  smock_push_int("local_tlv_callback", TLV_ID_D);
  hncp_add_tlv(o, &ta);
  smock_is_empty();
  smock_push_int("tlv_callback", TLV_ID_D);
  smock_push_bool("republish_callback", true);
  hncp_run(o);
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
  hncp_unsubscribe(o, &dummy_subscriber_1);
  hncp_unsubscribe(o, &dummy_subscriber_2);
  hncp_unsubscribe(o, &dummy_subscriber_3);
  hncp_unsubscribe(o, &dummy_subscriber_4);
  smock_is_empty();

  /* Re-enable checks */
  check_timing = true;
  check_random = true;

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hncp(o);
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
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
