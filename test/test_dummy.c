/*
 * $Id: test_dummy.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 12:51:48 2013 mstenber
 * Last modified: Mon Jun  8 09:53:07 2015 mstenber
 * Edit time:     15 min
 *
 */


#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */
#define L_LEVEL 7

#include "hnetd.h"
#include "sput.h"
#include "smock.h"

#include "fake_log.h"

#include <stdio.h>

int dummy_cb(int i)
{
  int v1 = smock_pull_int("in");
  int v2 = smock_pull_int("out");
  printf("i %d->o %d\n", v1, v2);
  sput_fail_unless(i == v1, "wrong input argument");
  return v2;
}

void sample(void)
{
  int r;

  L_DEBUG("debug");
  L_INFO("info");
  L_NOTICE("notice");
  L_WARN("warn");
  L_ERR("err");

  sput_fail_if(0, "0 isn't false!");
  sput_fail_unless(1, "1 isn't true!");

  /* Play with smock */
  sput_fail_unless(smock_empty(), "smock empty");
  smock_push_int("in", 1);
  sput_fail_unless(!smock_empty(), "smock not empty");
  smock_push_int("out", 2);
  smock_push_int("in", 3);
  smock_push_int("out", 6);
  r = dummy_cb(1);
  sput_fail_unless(r == 2, "dummy_cb broken");
  r = dummy_cb(3);
  sput_fail_unless(r == 6, "dummy_cb broken");
  /* In the end, we should be again gone. */
  sput_fail_unless(smock_empty(), "smock empty");
}

int main(__unused int argc, __unused char **argv)
{
  openlog("test_dummy", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dummysuite"); /* optional */
  sput_run_test(sample);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
