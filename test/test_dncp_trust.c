/*
 * $Id: test_dncp_trust.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Tue Jan 13 15:03:51 2015 mstenber
 * Last modified: Tue Jan 13 17:16:57 2015 mstenber
 * Edit time:     16 min
 *
 */

#include "net_sim.h"
#include "dncp_trust.h"

#include <unistd.h>

/******************************************************* PA NOP callbacks..  */

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

/***************************************** Actual test code (fairly minimal) */

#define TESTFILENAME1 "/tmp/i.dat"
#define TESTFILENAME2 "/tmp/j.dat"

void dncp_trust_base()
{
  net_sim_s s;
  net_sim_init(&s);

  dncp d1 = net_sim_find_hncp(&s, "x");
  dncp_trust dt1 = dncp_trust_create(d1, TESTFILENAME1);

  dncp d2 = net_sim_find_hncp(&s, "y");
  dncp_trust dt2 = dncp_trust_create(d2, TESTFILENAME2);


  dncp_trust_destroy(dt1);
  dncp_trust_destroy(dt2);

  net_sim_uninit(&s);
}

void dncp_trust_io()
{
  net_sim_s s;
  net_sim_init(&s);
  uloop_init();
  /* Make sure the (implicit) load + save work as advertised */
  unlink(TESTFILENAME1);
  dncp d = net_sim_find_hncp(&s, "x");
  sput_fail_unless(d, "dncp_create");
  dncp_trust dt = dncp_trust_create(d, TESTFILENAME1);
  sput_fail_unless(dt, "dncp_trust_create");
  dncp_trust_destroy(dt);
  net_sim_uninit(&s);
}

#define maybe_run_test(fun) sput_maybe_run_test(fun, do {} while(0))

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_dncp_trust", LOG_CONS | LOG_PERROR, LOG_DAEMON);

  sput_start_testing();
  sput_enter_suite("dncp_trust"); /* optional */

  argc -= 1;
  argv += 1;

  maybe_run_test(dncp_trust_base);
  maybe_run_test(dncp_trust_io);

  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
