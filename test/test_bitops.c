/*
 * Copyright (c) 2015 Cisco Systems, Inc.
 */
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

	uint8_t b[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t d[10];
	for(i=0; i<8; i++)
		sput_fail_unless(hamming_minimize(b+8, b+i, d, 0, 8) == 0 && *d == b[i], "");

	sput_fail_unless(hamming_minimize(b, b+0, d, 0, 8) == 0 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 0, 8) == 1 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+2, d, 0, 8) == 1 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+3, d, 0, 8) == 2 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+4, d, 0, 8) == 1 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+5, d, 0, 8) == 2 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+6, d, 0, 8) == 2 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+7, d, 0, 8) == 3 && *d == 0, "");
	sput_fail_unless(hamming_minimize(b, b+8, d, 0, 8) == 1 && *d == 0, "");

	int t;
	for(t=1; t<32; t++) {
		sput_fail_unless(hamming_minimize(b+1, b, d, 0, t) == 0, "Long string");
		sput_fail_unless(hamming_minimize(b+1, b, d, 1, t) == 0, "Long string");
		sput_fail_unless(hamming_minimize(b+1, b, d, 4, t) == 0, "Long string");
	}

#define _(a1,a2,a3,a4) (d[0] == a1) && (d[1] == a2) && (d[2] == a3) && (d[3] == a4)
	sput_fail_unless(hamming_minimize(b, b+1, d, 0, 32) == 2 && _(0, 0, 3, 4), "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 7, 32-7) == 2 && _(0, 0, 3, 4), "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 8, 32-8) == 1 && _(0, 0, 3, 4), "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 14, 32-14) == 1 && _(0, 0, 3, 4), "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 15, 32-15) == 0 && _(0, 0, 3, 4), "");
	sput_fail_unless(hamming_minimize(b, b+1, d, 16, 32-16) == 1 && _(0, 0, 1, 4), "");
#undef _
}

void bmemcmp_s_test()
{
	uint8_t a[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	int i, j, k;
	for(i=0; i<=10; i++) {
		for(j=0; j<=10;j++) {
			int r1 = bmemcmp_s(&a[i], &a[j], 0, 8);
			int r2 = bmemcmp_s(&a[i], &a[j], 1, 7);
			int r3 = bmemcmp_s(&a[i], &a[j], 2, 6);
			if(a[i] == a[j]) {
				sput_fail_unless(r1==0,"");
				sput_fail_unless(r2==0,"");
				sput_fail_unless(r3==0,"");
			} else if(a[i] > a[j]) {
				sput_fail_unless(r1>0,"");
				sput_fail_unless(r2>0,"");
				sput_fail_unless(r3>0,"");
			} else {
				sput_fail_unless(r1<0,"");
				sput_fail_unless(r2<0,"");
				sput_fail_unless(r3<0,"");
			}
		}
	}

	for(i=0; i<=10; i++) {
		for(j=0; j<=10;j++) {
			for(k=0; k<=10; k++) {
				int r1 = bmemcmp_s(&a[i], &a[j], 0, 8+k*2);
				int r2 = bmemcmp_s(&a[i], &a[j], 1, 8+k*2);
				int r3 = bmemcmp_s(&a[i], &a[j], 3, 8+k*2);
				if(i == j) {
					sput_fail_unless(r1==0,"");
					sput_fail_unless(r2==0,"");
					sput_fail_unless(r3==0,"");
				} else if(i > j) {
					sput_fail_unless(r1>0,"");
					sput_fail_unless(r2>0,"");
					sput_fail_unless(r3>0,"");
				} else {
					sput_fail_unless(r1<0,"");
					sput_fail_unless(r2<0,"");
					sput_fail_unless(r3<0,"");
				}
			}
		}
	}
}

int main(__unused int argc, __unused char **argv)
{
  openlog("test_bitops", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("bitops"); /* optional */
  //sput_run_test(bmemcmp_s_test);
  sput_run_test(hamming);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
