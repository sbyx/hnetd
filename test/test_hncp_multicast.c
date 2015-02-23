/*
 * $Id: test_hncp_multicast.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 21:40:08 2015 mstenber
 * Last modified: Mon Feb 23 22:51:47 2015 mstenber
 * Edit time:     3 min
 *
 */

#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */
#define L_LEVEL 7

#define DISABLE_HNCP_PA
#define DISABLE_HNCP_SD
#include "net_sim.h"
#include "sput.h"
#include "smock.h"

#include "fake_fork_exec.h"

#include "hncp_multicast.c"

int log_level = LOG_DEBUG;


int pa_update_eap(net_node node, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  const char *ifname, bool to_delete)
{ return 0; }

int pa_update_edp(net_node node, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  hnetd_time_t valid_until, hnetd_time_t preferred_until,
                  const void *dhcpv6_data, size_t dhcpv6_len)
{ return 0; }

int pa_update_eaa(net_node node, const struct in6_addr *addr,
                  const struct pa_rid *rid,
                  const char *ifname, bool to_delete)
{return 0;}

void test_hncp_multicast()
{
  /* TBD - write the test code here. It seems not to crash
   * test_hncp_net, but sanity better be checked here too. */
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(test_hncp_multicast);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
