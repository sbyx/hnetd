#include "hnetd.h"
#include "sput.h"
#include <stdio.h>

#include "bitops.h"
#include <libubox/utils.h>

void hamming(void)
{
	uint64_t a[] = { 0x1111111111111111, 0x2222222222222222, 0xffffffffffffffff, 0x000000000000ffff, 0x0};
	a[3] = cpu_to_be64(a[3]);
	sput_fail_unless(hamming_distance_64(a, a, 64) == 0, "");
	sput_fail_unless(hamming_distance_64(a, a + 1, 64) == 32, "");
	sput_fail_unless(hamming_distance_64(a, a + 2, 64) == 48, "");
	sput_fail_unless(hamming_distance_64(a, a + 3, 64) == 24, "");
	sput_fail_unless(hamming_distance_64(a + 2, a + 3, 64) == 48, "");
	sput_fail_unless(hamming_distance_64(a + 2, a + 4, 64) == 64, "");

	size_t i;
	for(i=0; i<=64; i++)
		sput_fail_unless(hamming_distance_64(a + 2, a + 4, i) == i, "");

	for(i=0; i<48; i++)
		sput_fail_unless(hamming_distance_64(a + 3, a + 4, i) == 0, "");
	for(i=48; i<=64; i++)
		sput_fail_unless(hamming_distance_64(a + 3, a + 4, i) == i - 48, "");

	for(i=0; i<48; i++)
		sput_fail_unless(hamming_distance_64(a + 2, a + 3, 64+i) == 48, "");
	for(i=48; i<=64; i++)
		sput_fail_unless(hamming_distance_64(a + 2, a + 3, 64+i) == i - 48 + 48, "");
}

int main(__unused int argc, __unused char **argv)
{
  openlog("test_bitops", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("bitops"); /* optional */
  sput_run_test(hamming);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
