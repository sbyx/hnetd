/*
 * $Id: test_dncp_trust.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Tue Jan 13 15:03:51 2015 mstenber
 * Last modified: Thu Feb 26 13:58:48 2015 mstenber
 * Edit time:     48 min
 *
 */

#include "net_sim.h"
#include "dncp_trust.h"

#include <unistd.h>

int log_level = LOG_DEBUG;

/************************************************************ NOP callbacks. */

int platform_rpc_register(struct platform_rpc_method *m)
{return 0;}

int platform_rpc_cli(const char *method, struct blob_attr *in)
{return 0;}

/***************************************** Actual test code (fairly minimal) */

#define TESTFILENAME "/tmp/dncp_trust.dat"

void dncp_trust_base()
{
  dncp_sha256_s ha[3];
  int v[3] = { DNCP_VERDICT_NONE,
               DNCP_VERDICT_NEUTRAL,
               DNCP_VERDICT_CONFIGURED_POSITIVE };
  memset(&ha[0], 42, sizeof(ha[0]));
  memset(&ha[1], 7, sizeof(ha[0]));
  memset(&ha[2], 3, sizeof(ha[0]));

  net_sim_s s;
  net_sim_init(&s);

  /* 3 different cases (before sync)
  - nonexistent hash (ha[0])
  - requested hash (ha[1])
  - set hash (ha[2]) */
  dncp d1 = net_sim_find_hncp(&s, "x");
  dncp_trust dt1 = dncp_trust_create(d1, NULL);

  dncp d2 = net_sim_find_hncp(&s, "y");
  dncp_trust dt2 = dncp_trust_create(d2, NULL);


  dncp_link l1 = net_sim_dncp_find_link_by_name(d1, "down");
  dncp_link l2 = net_sim_dncp_find_link_by_name(d2, "up");
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);

  dncp_trust_request_verdict(dt1, &ha[1], "bar");
  dncp_trust_set(dt1, &ha[2], DNCP_VERDICT_CONFIGURED_POSITIVE, "foo");

  SIM_WHILE(&s, 100000, !net_sim_is_converged(&s));

  /* Verdict must be same for all hashes */

  int i;
  for (i = 0 ; i < 3 ; i++)
    {
      int v1 = dncp_trust_get_verdict(dt1, &ha[i], NULL);
      int v2 = dncp_trust_get_verdict(dt2, &ha[i], NULL);
      sput_fail_unless(v1 == v[i], "verdict1 expected");
      sput_fail_unless(v2 == v[i], "verdict2 expected");

    }
  char buf[DNCP_T_TRUST_VERDICT_CNAME_LEN];
  dncp_trust_get_verdict(dt1, &ha[2], buf);
  sput_fail_unless(strcmp(buf, "foo")==0, "local cname foo");
  dncp_trust_get_verdict(dt2, &ha[2], buf);
  sput_fail_unless(strcmp(buf, "foo")==0, "remote cname foo");
  dncp_trust_get_verdict(dt2, &ha[1], buf);
  sput_fail_unless(strcmp(buf, "bar")==0, "cname bar");

  i = 0;
  dncp_sha256 h;
  dncp_trust_for_each_hash(dt1, h)
    i++;
  L_DEBUG("dt1 i=%d", i);
  sput_fail_unless(i == 2, "dt1 have data for ha[1]+ha[2]");

  i = 0;
  dncp_trust_for_each_hash(dt2, h)
    i++;
  L_DEBUG("dt2 i=%d", i);
  sput_fail_unless(i == 2, "dt2 have data for ha[1]+ha[2]");

  dncp_trust_destroy(dt1);
  dncp_trust_destroy(dt2);

  net_sim_uninit(&s);
}

void dncp_trust_io()
{
  net_sim_s s;
  dncp_sha256_s h;

  memset(&h, 42, sizeof(h));
  net_sim_init(&s);
  uloop_init();
  /* Make sure the (implicit) load + save work as advertised */
  unlink(TESTFILENAME);
  dncp d = net_sim_find_hncp(&s, "x");
  sput_fail_unless(d, "dncp_create");
  dncp_trust dt = dncp_trust_create(d, TESTFILENAME);
  sput_fail_unless(dt, "dncp_trust_create");
  sput_fail_unless(dncp_trust_get_verdict(dt, &h, NULL) == DNCP_VERDICT_NONE,
                   "verdict none");
  dncp_trust_set(dt, &h, DNCP_VERDICT_CONFIGURED_POSITIVE, "foo");
  dncp_trust_destroy(dt);

  dt = dncp_trust_create(d, TESTFILENAME);
  sput_fail_unless(dt, "dncp_trust_create 2");
  char buf[DNCP_T_TRUST_VERDICT_CNAME_LEN];
  sput_fail_unless(dncp_trust_get_verdict(dt, &h, buf) == DNCP_VERDICT_CONFIGURED_POSITIVE,
                   "verdict none");
  sput_fail_unless(strcmp(buf, "foo")==0, "cname foo");
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
