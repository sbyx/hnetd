/*
 * $Id: test_dummy.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 12:51:48 2013 mstenber
 * Last modified: Thu Nov 21 13:21:44 2013 mstenber
 * Edit time:     6 min
 *
 */

#include "sput.h"
#ifndef __unused
#define __unused __attribute__((unused))
#endif /* !__unused */


void sample(void)
{
  sput_fail_if(0, "0 isn't false!");
  sput_fail_unless(1, "1 isn't true!");
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("dummysuite"); /* optional */
  sput_run_test(sample);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}

