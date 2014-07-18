/*
 * $Id: test_hncp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Jan 15 17:17:36 2014 mstenber
 * Last modified: Tue Jun 17 16:13:31 2014 mstenber
 * Edit time:     116 min
 *
 */

#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */
#define L_LEVEL 7
#define DISABLE_HNCP_PA

#include "hncp_trust.h"
#include "net_sim.h"
#include "sput.h"
#include "smock.h"

/* Prevent execve/vfork/waitpid/_exit definition */
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Stub out the code that calls things */
#define execv(cmd, argv) do                             \
{                                                       \
  if (check_exec || debug_exec)                         \
    {                                                   \
      int i;                                            \
      L_DEBUG("execv: '%s'", cmd);                      \
      if (check_exec)                                   \
        smock_pull_string_is("execv_cmd", cmd);         \
      for (i = 1; argv[i]; i++)                         \
        {                                               \
          L_DEBUG(" arg#%d: '%s'", i, argv[i]);         \
          if (check_exec)                               \
            smock_pull_string_is("execv_arg", argv[i]); \
        }                                               \
    }                                                   \
  else                                                  \
    execs++;                                            \
} while (0)

bool check_exec, debug_exec;
int execs;

#define vfork() 0
#define waitpid(pid, x, y)
#define _exit(code)

#include "hncp_sd.c"

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

/*
 * This is minimalist piece of test code that just exercises the
 * hncp_sd module _and_ makes sure appropriate calls are called (And
 * that dnsmasq config file looks mostly sane).
 *
 */

void _file_contains(const char *filename, const char *string, bool has)
{
  /* Rather lazy implementation; we know the files aren't very big. */
  char buf[4096];
  int c;
  FILE *f;

  f = fopen(filename, "r");
  sput_fail_unless(f, "fopen in file_contains");
  if (f)
    {
      c = fread(buf, 1, sizeof(buf), f);
      sput_fail_unless(c > 0, "fread in file_contains");
      if (c > 0)
        {
          buf[c] = 0;
          sput_fail_unless(!has == !strstr(buf, string), string);
        }
      fclose(f);
    }
}

void file_contains(const char *filename, const char *string)
{
  _file_contains(filename, string, true);
}

void file_does_not_contain(const char *filename, const char *string)
{
  _file_contains(filename, string, false);
}

bool net_sim_is_busy(net_sim s)
{
  net_node n;

  if (!list_empty(&s->messages))
    {
      L_DEBUG("net_sim_is_busy: messages pending");
      return true;
    }
  list_for_each_entry(n, &s->nodes, h)
    {
      if (n->n.immediate_scheduled)
        {
          L_DEBUG("net_sim_is_busy: immediate scheduled");
          return true;
        }
#ifndef DISABLE_HNCP_SD
      if (!s->disable_sd && n->sd->should_update)
        {
          L_DEBUG("net_sim_is_busy: should_update: %d", n->sd->should_update);
          return true;
        }
#endif /* !DISABLE_HNCP_SD */
    }
  return false;
}

void test_hncp_sd(void)
{
  net_sim_s s;
  hncp n1, n2, n3;
  hncp_link l1, l2, l21 __unused, l3;
  net_node node1, node2, node3;
  struct prefix p;
  bool rv;

  check_exec = false;
  debug_exec = false;
  execs = 0;
  net_sim_init(&s);
  n1 = net_sim_find_hncp(&s, "n1");
  node1 = container_of(n1, net_node_s, n);
  l1 = net_sim_hncp_find_link_by_name(n1, "eth0.0");
  strcpy(l1->conf->dnsname, "label");
  sput_fail_unless(prefix_pton("2001:dead:beef::/64", &p), "prefix_pton");
  hncp_tlv_ap_update(n1, &p, "eth0.0", false, 0, true);
  sput_fail_unless(prefix_pton("2001:dead:beef::1/128", &p), "prefix_pton");
  hncp_tlv_ra_update(n1, 0, &p.prefix, true);

  /* Make sure .home shows up even with zero conf and no TLV traffic */
  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));
  rv = hncp_sd_write_dnsmasq_conf(node1->sd, "/tmp/n0.conf");
  sput_fail_unless(rv, "write 0 works");
  smock_is_empty();
  file_contains("/tmp/n0.conf", "r.home");

  n2 = net_sim_find_hncp(&s, "n2");
  node2 = container_of(n2, net_node_s, n);
  l2 = net_sim_hncp_find_link_by_name(n2, "eth1");
  l21 = net_sim_hncp_find_link_by_name(n2, "eth2");
  strcpy(l21->conf->dnsname, "fqdn.");
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);

  sput_fail_unless(prefix_pton("1.2.3.4/24", &p), "prefix_pton");
  sput_fail_unless(prefix_is_ipv4(&p), "IPv4 prefix parsing failed");
  hncp_tlv_ap_update(n1, &p, "eth0.0", false, 0, true);
  hncp_tlv_ra_update(n1, 1, &p.prefix, true);
  sput_fail_unless(prefix_pton("2001:feed:beef::/64", &p), "prefix_pton");
  hncp_tlv_ap_update(n2, &p, "eth2", false, 0, true);

  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));
  hncp_trust_begin_friend_search(n1, 0);
  hncp_trust_begin_friend_search(n2, 0);
  SIM_WHILE(&s, 100, !net_sim_is_converged(&s)|| net_sim_is_busy(&s));
  sput_fail_unless(strcmp(node1->sd->router_name, node2->sd->router_name),
                   "router names different");
  smock_is_empty();

  /* Play with dnsmasq utilities */
  memset(&node1->sd->dnsmasq_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_write_dnsmasq_conf(node1->sd, "/tmp/n1.conf");
  sput_fail_unless(rv, "write 1 works");
  smock_is_empty();
  file_contains("/tmp/n1.conf", "r.home");
  file_contains("/tmp/n1.conf", "r1.home");

  rv = hncp_sd_write_dnsmasq_conf(node1->sd, "/tmp/n1.conf");
  sput_fail_unless(!rv, "write 1 'fails'");
  smock_is_empty();

  memset(&node2->sd->dnsmasq_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_write_dnsmasq_conf(node2->sd, "/tmp/n2.conf");
  sput_fail_unless(rv, "write 2 works");
  smock_is_empty();
  file_contains("/tmp/n2.conf", "label.r.home");
  file_contains("/tmp/n2.conf", "r1.home");

  check_exec = true;
  smock_push("execv_cmd", "s-dnsmasq");
  smock_push("execv_arg", "restart");
  rv = hncp_sd_restart_dnsmasq(node1->sd);
  sput_fail_unless(rv, "restart dnsmasq works");
  smock_is_empty();

  /* Play with ohybridproxy */
  smock_push("execv_cmd", "s-ohp");
  smock_push("execv_arg", "start");
  smock_push("execv_arg", "-a");
  smock_push("execv_arg", "127.0.0.2");
  smock_push("execv_arg", "-p");
  smock_push("execv_arg", "54");
  smock_push("execv_arg", "eth0.0=label.r.home.");
  memset(&node1->sd->ohp_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_reconfigure_ohp(node1->sd);
  sput_fail_unless(rv, "reconfigure ohp works");
  smock_is_empty();

  /* Make sure second run is NOP */
  rv = hncp_sd_reconfigure_ohp(node1->sd);
  sput_fail_unless(!rv, "reconfigure ohp works (2)");
  smock_is_empty();

  smock_push("execv_cmd", "s-ohp");
  smock_push("execv_arg", "start");
  smock_push("execv_arg", "-a");
  smock_push("execv_arg", "127.0.0.2");
  smock_push("execv_arg", "-p");
  smock_push("execv_arg", "54");
  smock_push("execv_arg", "eth1=eth1.r1.home.");
  smock_push("execv_arg", "eth2=fqdn.");
  memset(&node2->sd->ohp_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_reconfigure_ohp(node2->sd);
  sput_fail_unless(rv, "reconfigure ohp works");
  smock_is_empty();

  /* Make sure second run is NOP */
  rv = hncp_sd_reconfigure_ohp(node2->sd);
  sput_fail_unless(!rv, "reconfigure ohp works (2)");
  smock_is_empty();

  check_exec = false;
  debug_exec = true;
  /* Play with PCP - due to dynamic addresses, unfortunately unable to
   * check arguments. */
  memset(&node2->sd->pcp_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_reconfigure_pcp(node2->sd);
  sput_fail_unless(rv, "reconfigure pcp works (1)");

  rv = hncp_sd_reconfigure_pcp(node2->sd);
  sput_fail_unless(!rv, "reconfigure pcp works (2)");
  debug_exec = false;


  /* Add third node, with hardcoded .domain (yay). It should result in
   * .home disappearing from n1 eventually. */
  s.disable_sd = true;
  n3 = net_sim_find_hncp(&s, "n3");
  node3 = container_of(n3, net_node_s, n);
  static hncp_sd_params_s sd_params = {
    .dnsmasq_script = "s-dnsmasq",
    .dnsmasq_bonus_file = "/tmp/n3.conf",
    .ohp_script = "s-ohp",
    .router_name = "xorbo",
    .domain_name = "domain."
  };
  node3->sd = hncp_sd_create(&node3->n, &sd_params);
  s.disable_sd = false;
  l3 = net_sim_hncp_find_link_by_name(n3, "eth0");
  net_sim_set_connected(l2, l3, true);
  net_sim_set_connected(l3, l2, true);
  SIM_WHILE(&s, 100, net_sim_is_busy(&s) || !net_sim_is_converged(&s));
  hncp_trust_begin_friend_search(n2, 0);
  hncp_trust_begin_friend_search(n3, 0);
  SIM_WHILE(&s, 1000, net_sim_is_busy(&s) || !net_sim_is_converged(&s));

  memset(&node1->sd->dnsmasq_state, 0, HNCP_HASH_LEN);
  rv = hncp_sd_write_dnsmasq_conf(node1->sd, "/tmp/n12.conf");
  sput_fail_unless(rv, "write 12 works");
  smock_is_empty();
  file_contains("/tmp/n12.conf", "r.domain");
  file_contains("/tmp/n12.conf", "r1.domain");
  file_contains("/tmp/n12.conf", "xorbo.domain");
  file_does_not_contain("/tmp/n12.conf", "home");

  net_sim_uninit(&s);
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog(argv[0], LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite(argv[0]); /* optional */
  sput_run_test(test_hncp_sd);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
