
#include <stdio.h>

#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */
#define L_LEVEL 7

#include "hnetd.h"
#include "sput.h"
#include "smock.h"
#include "pa_data.h"

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
  openlog("test_pa_data", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("test_pa_data"); /* optional */
  //sput_run_test(sample);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}


