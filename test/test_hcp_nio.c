/*
 * $Id: test_hcp_nio.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 10:02:45 2013 mstenber
 * Last modified: Tue Nov 26 12:55:23 2013 mstenber
 * Edit time:     83 min
 *
 */

/* This test code assumes that we have wrapped hcp_io to produce fake
 * input+output, as well as fake hnetd_time to produce fake time
 * signal. With those, we can prod the state machine(s) as much as we
 * want to without actually needing to have real sockets or wait for
 * long periods of time.. */

#include "hnetd.h"
#define hnetd_time hnetd_time_mock
#include <stdlib.h>
#define random random_mock
static hnetd_time_t hnetd_time_mock(void);
static int random_mock(void);
#include "hcp.c"
#include "hcp_recv.c"
#include "hcp_timeout.c"
#include "sput.h"
#include "smock.h"

/********************************************************* Mocked interfaces */

/* Fake version of the I/O interface. */
bool hcp_io_init(hcp o)
{
  o->udp_socket = 1;
  sput_fail_unless(o, "hcp");
  return smock_pull_bool("init_result");
}
void hcp_io_uninit(hcp o)
{
  o->udp_socket = 0;
  sput_fail_unless(o, "hcp");
  smock_pull("uninit");
}

bool hcp_io_set_ifname_enabled(hcp o, const char *ifname, bool enabled)
{
  sput_fail_unless(o, "hcp");
  sput_fail_unless(o && o->udp_socket == 1, "hcp_io ready");
  smock_pull_string_is("set_enable_ifname", ifname);
  smock_pull_bool_is("set_enable_enabled", enabled);
  return smock_pull_bool("set_enable_result");
}

int hcp_io_get_hwaddr(const char *ifname, unsigned char *buf, int buf_left)
{
  unsigned char *r = smock_pull("get_hwaddr_buf");
  int r_len = smock_pull_int("get_hwaddr_len");

  smock_pull_string_is("get_hwaddr_ifname", ifname);
  memcpy(buf, r, r_len);
  sput_fail_unless(r_len <= buf_left, "result length reasonable");
  return r_len;
}

void hcp_io_schedule(hcp o, int msecs)
{
  sput_fail_unless(o, "hcp");
  sput_fail_unless(o && o->udp_socket == 1, "hcp_io ready");
  smock_pull_int_is("schedule", msecs);
}

ssize_t hcp_io_recvfrom(hcp o, void *buf, size_t len,
                        char *ifname,
                        struct in6_addr *src,
                        struct in6_addr *dst)
{
  unsigned char *r = smock_pull("recvfrom_buf");
  int r_len = smock_pull_int("recvfrom_len");
  struct in6_addr *r_src = smock_pull("recvfrom_src");
  struct in6_addr *r_dst = smock_pull("recvfrom_dst");
  smock_pull_string_is("recvfrom_ifname", ifname);

  sput_fail_unless(o, "hcp");
  sput_fail_unless(o && o->udp_socket == 1, "hcp_io_schedule valid");
  sput_fail_unless(r_len <= ((int) len), "result length reasonable");
  *src = *r_src;
  *dst = *r_dst;
  memcpy(buf, r, r_len);
  return r_len;
}

ssize_t hcp_io_sendto(hcp o, void *buf, size_t len,
                      const char *ifname,
                      const struct in6_addr *dst)
{
  sput_fail_unless(o, "hcp");
  sput_fail_unless(o && o->udp_socket == 1, "hcp_io ready");
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

static hnetd_time_t hnetd_time_mock(void)
{
  return smock_pull_int("time");
}

static int random_mock(void)
{
  return smock_pull_int("random");
}

/******************************************************* Start of test cases */

static char *dummy_ifname = "eth0";

static void hcp_init_no_hwaddr(void)
{
  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddr_ifname", dummy_ifname);
  smock_push("get_hwaddr_buf", NULL);
  smock_push_int("get_hwaddr_len", 0);

  smock_push("get_hwaddr_ifname", "eth1");
  smock_push("get_hwaddr_buf", NULL);
  smock_push_int("get_hwaddr_len", 0);

  hcp o = hcp_create();
  sput_fail_unless(!o, "hcp_create -> !hcp");
  sput_fail_unless(smock_empty(), "smock_empty");
}

static void hcp_init_iofail(void)
{
  char buf[4] = "foo";

  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddr_ifname", dummy_ifname);
  smock_push("get_hwaddr_buf", buf);
  smock_push_int("get_hwaddr_len", sizeof(buf));

  smock_push("get_hwaddr_ifname", "eth1");
  smock_push("get_hwaddr_buf", NULL);
  smock_push_int("get_hwaddr_len", 0);

  /* io init succeeds */
  smock_push_bool("init_result", false);

  hcp o = hcp_create();
  sput_fail_unless(!o, "hcp_create -> !hcp");
  sput_fail_unless(smock_empty(), "smock_empty");
}

static hcp create_hcp(void)
{
  char buf[4] = "foo";

  /* Feed in fake hwaddr for eth0+eth1 (hardcoded, ugh) */
  smock_push("get_hwaddr_ifname", dummy_ifname);
  smock_push("get_hwaddr_buf", buf);
  smock_push_int("get_hwaddr_len", sizeof(buf));

  smock_push("get_hwaddr_ifname", "eth1");
  smock_push("get_hwaddr_buf", NULL);
  smock_push_int("get_hwaddr_len", 0);

  /* io init succeeds */
  smock_push_bool("init_result", true);

  /* schedule happens _once_ */
  smock_push("schedule", NULL);

  hcp o = hcp_create();
  sput_fail_unless(o, "hcp_create -> hcp");
  sput_fail_unless(smock_empty(), "smock_empty");

  return o;
}

static void destroy_hcp(hcp o)
{
  smock_push("uninit", NULL);
  hcp_destroy(o);
  sput_fail_unless(smock_empty(), "smock_empty");
}


static void hcp_ok_minimal(void)
{
  hcp o = create_hcp();
  destroy_hcp(o);
}

static void one_join(bool ok)
{
  smock_push("set_enable_ifname", dummy_ifname);
  smock_push_bool("set_enable_enabled", true);
  smock_push_bool("set_enable_result", ok);
}

static void hcp_ok(void)
{
  hcp o = create_hcp();

  sput_fail_unless(smock_empty(), "smock_empty");
  one_join(true);
  hcp_set_link_enabled(o, dummy_ifname, true);
  sput_fail_unless(smock_empty(), "smock_empty");

  /* Ok. We're cooking with gas. */

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hcp(o);
}

static void hcp_rejoin_works(void)
{
  hcp o = create_hcp();
  int t = 123000;


  /* we'll try to join dummy_ifname; however, it fails. */
  sput_fail_unless(smock_empty(), "smock_empty");
  one_join(false);
  smock_push_int("schedule", 0);
  smock_push_int("time", t);
  hcp_set_link_enabled(o, dummy_ifname, true);
  sput_fail_unless(smock_empty(), "smock_empty");

  /* make sure next timeout before HCP_REJOIN_INTERVAL just re-schedules. */
  t += HCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", HCP_REJOIN_INTERVAL / 2);
  hcp_run(o);
  sput_fail_unless(smock_empty(), "smock_empty");

  /* now that the time _has_ expired, we should try joining.. fail again. */
  t += HCP_REJOIN_INTERVAL / 2;
  smock_push_int("time", t);
  smock_push_int("schedule", HCP_REJOIN_INTERVAL);
  one_join(false);
  hcp_run(o);
  sput_fail_unless(smock_empty(), "smock_empty");

  /* again try after HCP_REJOIN_INTERVAL, it should work. trickle
   * scheduling should require exactly one random call. */
  t += HCP_REJOIN_INTERVAL;
  smock_push_int("time", t);
  smock_push_int("random", 0);
  smock_push_int("schedule", HCP_TRICKLE_IMIN / 2);
  one_join(true);
  hcp_run(o);
  sput_fail_unless(smock_empty(), "smock_empty");

  /* no unregisters at end, as we first kill io, and then flush
   * structures (socket kill should take care of it in any case). */
  destroy_hcp(o);
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hcp_nio"); /* optional */
  sput_run_test(hcp_init_no_hwaddr);
  sput_run_test(hcp_init_iofail);
  sput_run_test(hcp_ok_minimal);
  sput_run_test(hcp_ok);
  sput_run_test(hcp_rejoin_works);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
