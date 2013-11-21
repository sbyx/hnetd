/*
 * $Id: test_hcp.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 13:26:21 2013 mstenber
 * Last modified: Thu Nov 21 13:31:23 2013 mstenber
 * Edit time:     2 min
 *
 */

#include "hcp.h"
#include "sput.h"
#ifndef __unused
#define __unused __attribute__((unused))
#endif /* !__unused */

void setup_hpc(void)
{
  hcp o = hcp_create();
  sput_fail_if(!o, "create works");
  hcp_destroy(o);
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hpc"); /* optional */
  sput_run_test(setup_hpc);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}

