/*
 * $Id: test_hcp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan 15 17:17:36 2014 mstenber
 * Last modified: Wed Jan 15 21:16:46 2014 mstenber
 * Edit time:     22 min
 *
 */
#define L_LEVEL 7
#define DISABLE_HCP_PA

#include "net_sim.h"
#include "sput.h"
#include "smock.h"

/* Prevent execve/vfork/waitpid/_exit definition */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Stub out the code that calls things */
#define execv(cmd, argv) do {                   \
int i = 0;                                      \
while (argv[i]) i++;                            \
L_DEBUG("execv:%s (%d arguments)", cmd, i);     \
smock_pull_string_is("execv_cmd", cmd);         \
smock_pull_int_is("execv_argc", i);             \
} while(0)

#define vfork() 0
#define waitpid(pid, x, y)
#define _exit(code)

#include "hcp_sd.c"

/*
 * This is minimalist piece of test code that just exercises the
 * hcp_sd module _and_ makes sure appropriate calls are called (And
 * that dnsmasq config file looks mostly sane).
 *
 */

void test_hcp_sd(void)
{
  net_sim_s s;
  hcp n1, n2;
  hcp_link l1, l2, l21;
  net_node node1, node2;
  struct prefix p;
  bool rv;

  net_sim_init(&s);
  n1 = net_sim_find_hcp(&s, "n1");
  n2 = net_sim_find_hcp(&s, "n2");
  node1 = container_of(n1, net_node_s, n);
  node2 = container_of(n2, net_node_s, n);
  l1 = net_sim_hcp_find_link_by_name(n1, "eth0");
  l2 = net_sim_hcp_find_link_by_name(n2, "eth1");
  l21 = net_sim_hcp_find_link_by_name(n2, "eth2");
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);
  sput_fail_unless(prefix_pton("2001:dead:beef::/64", &p), "prefix_pton");
  hcp_tlv_update_ap(n1, &p, "eth0", true);
  sput_fail_unless(prefix_pton("2001:feed:beef::/64", &p), "prefix_pton");
  hcp_tlv_update_ap(n2, &p, "eth2", true);
  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));
  net_sim_uninit(&s);
  sput_fail_unless(strcmp(node1->sd->router_name, node2->sd->router_name),
                   "router names different");
  smock_is_empty();
  rv = hcp_sd_write_dnsmasq_conf(node1->sd, "/tmp/n1.conf");
  sput_fail_unless(rv, "write 1 works");
  smock_is_empty();

  smock_push("execv_cmd", "/bin/yes");
  smock_push_int("execv_argc", 0);
  rv = hcp_sd_restart_dnsmasq(node1->sd);
  sput_fail_unless(rv, "restart dnsmasq works");
  smock_is_empty();
  rv = hcp_sd_reconfigure_ohp(node1->sd);
  sput_fail_unless(rv, "reconfigure ohp works");
  smock_is_empty();
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(test_hcp_sd);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
