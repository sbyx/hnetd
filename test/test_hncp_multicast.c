/*
 * $Id: test_hncp_multicast.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 21:40:08 2015 mstenber
 * Last modified: Wed Feb 25 15:04:01 2015 mstenber
 * Edit time:     18 min
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

void test_hncp_multicast_base(bool aa_enabled)
{
  /* Create two nodes. Eventually, one of them has to be RP, and the
   * one with (fake) DP must publish it's address. */
  net_sim_s s;
  dncp n1, n2;
  dncp_link l1, l2;

  net_sim_init(&s);
  s.disable_link_auto_address = !aa_enabled;
  n1 = net_sim_find_hncp(&s, "n1");
  l1 = net_sim_dncp_find_link_by_name(n1, "eth0");
  /* Fake external connection */
  dncp_add_tlv(n1, HNCP_T_EXTERNAL_CONNECTION, 0, 0, 0);

  n2 = net_sim_find_hncp(&s, "n2");
  l2 = net_sim_dncp_find_link_by_name(n2, "eth0");

  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);

  SIM_WHILE(&s, 100, net_sim_is_busy(&s) || !net_sim_is_converged(&s));

  /* Make sure there is exactly 1 RPA, and 1 BP */
  int types[] = { HNCP_T_PIM_RPA_CANDIDATE,
                  HNCP_T_PIM_BORDER_PROXY,
                  0
  };
  int i;
  for (i = 0 ; types[i] ; i++)
  {
    int c = 0;
    dncp_node n;
    struct tlv_attr *a;
    dncp_for_each_node(n1, n)
      dncp_node_for_each_tlv_with_type(n, a, types[i])
        c++;
    L_DEBUG("tlv #%d: %d", types[i], c);
    sput_fail_unless(c == (aa_enabled ? 1 : 0), "1 of tlv");
  }
  net_sim_uninit(&s);
}

void test_hncp_multicast()
{
  test_hncp_multicast_base(true);
}

void test_hncp_multicast_noaddr()
{
  test_hncp_multicast_base(false);
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(test_hncp_multicast);
  sput_run_test(test_hncp_multicast_noaddr);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
