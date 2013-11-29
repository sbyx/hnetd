/*
 * Author: Pierre Pfister
 *
 * prefix_utils.c unit testing
 *
 */

#include "prefix_utils.h"
#include "sput.h"

#include <stdio.h>
#include <stdbool.h>

struct prefix p_allones_128 = {
		.prefix = { .s6_addr = {
				0xff,0xff, 0xff,0xff,  0xff,0xff, 0xff,0xff,
				0xff,0xff, 0xff,0xff,  0xff,0xff, 0xff,0xff}},
		.plen = 128 };
static const char *p_allones_128_s = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128";

struct prefix p_allones_67 = {
		.prefix = { .s6_addr = {
				0xff,0xff, 0xff,0xff,  0xff,0xff, 0xff,0xff,
				0xff,0xff, 0xff,0xff,  0xff,0xff, 0xff,0xff}},
		.plen = 67 };
static const char *p_allones_67_s = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/67";

struct prefix p_allones_67_can = {
		.prefix = { .s6_addr = {
				0xff,0xff, 0xff,0xff,  0xff,0xff, 0xff,0xff,
				0xe0}},
		.plen = 67 };
static const char *p_allones_67_can_s = "ffff:ffff:ffff:ffff:e000::/67";

static struct prefix p1  = { { .s6_addr = {0x00,0x10}}, 12 };
static const char *p1_s = "10::/12";
static struct prefix p10 = { { .s6_addr = {0x00,0x10}}, 16 };
static struct prefix p11 = { { .s6_addr = {0x00,0x11}}, 16 };
static struct prefix p1f = { { .s6_addr = {0x00,0x1f}}, 16 };
static struct prefix p2  = { { .s6_addr = {0x00,0x20}}, 12 };

static struct prefix px  = { { .s6_addr = {0x00,0x20, 0x01}}, 12 };
static const char *px_s = "20:100::/12";

void bmemcpy(void *dst, const void *src,
		size_t frombit, size_t nbits);

void bmemcpy_t(void)
{
	uint8_t u1[] = {0xff, 0xff, 0xff, 0xff};
	uint8_t u2[] = {0x00, 0x00, 0x00, 0x00};
	uint8_t u3[] = {0xff, 0xff, 0x00, 0x00};
	uint8_t u4[] = {0x07, 0xff, 0xff, 0x00};
	uint8_t u5[] = {0x01, 0xff, 0xff, 0xc0};
	uint8_t dst[4];

	bmemcpy(&dst, &u2, 0, 32);
	sput_fail_if(memcmp(dst, u2, 4), "32bit copy");

	memset(dst, 0, 4);
	bmemcpy(&dst, &u1, 0, 16);
	sput_fail_if(memcmp(dst, u3, 4), "16bit copy");

	memset(dst, 0, 4);
	bmemcpy(&dst, &u1, 5, 19);
	sput_fail_if(memcmp(dst, u4, 4), "5 to 24 bits copy");

	memset(dst, 0, 4);
	bmemcpy(&dst, &u1, 7, 19);
	sput_fail_if(memcmp(dst, u5, 4), "7 to 26 bits copy");

}

void prefix_print_nocan_t(void)
{
	char buff[PREFIX_MAXBUFFLEN];
	const char *ret;

	ret = prefix_ntop(buff, 5, &p_allones_128, false);
	sput_fail_if(ret, "Buffer too short (1)");

	ret = prefix_ntop(buff, 43,
			&p_allones_128, false);
	sput_fail_if(ret, "Buffer too short (2)");

	ret = prefix_ntop_s(buff, 5, &p_allones_128, false);
	sput_fail_if(strcmp(ret, PREFIX_STRERR), "Should return error string");

	ret = prefix_ntop_s(buff, PREFIX_MAXBUFFLEN,
				&p_allones_128, false);
	sput_fail_if(strcmp(ret, p_allones_128_s), "Print all_ones/128");

	ret = prefix_ntop_s(buff, PREFIX_MAXBUFFLEN,
			&p1, false);
	sput_fail_if(strcmp(ret, p1_s), "Print p1");

	ret = prefix_ntop_s(buff, PREFIX_MAXBUFFLEN,
			&px, false);
	sput_fail_if(strcmp(ret, px_s), "Print px");
}

void prefix_equal_t(void)
{
	sput_fail_if(prefix_cmp(&p_allones_67, &p_allones_67),
			"Same prefixes should be equal (1)");
	sput_fail_if(prefix_cmp(&p_allones_67_can, &p_allones_67_can),
			"Same prefixes should be equal (2)");
	sput_fail_if(prefix_cmp(&p1, &p1),
			"Same prefixes should be equal (3)");
	sput_fail_if(prefix_cmp(&p_allones_67, &p_allones_67_can),
			"Canonical prefix should equal non-canonical one");
	sput_fail_unless(prefix_cmp(&p1, &p10),
			"Different prefix length should imply not equal");
	sput_fail_unless(prefix_cmp(&p1, &p_allones_67),
			"Different prefixes should not be equal");
}

void prefix_canonical_t(void)
{
	struct prefix p;
	prefix_canonical(&p, &p_allones_67);

	sput_fail_if(memcmp(&p, &p_allones_67_can, sizeof(struct prefix)),
				"Canonical transform");
}

void prefix_print_can_t(void)
{
	char buff[PREFIX_MAXBUFFLEN];
	const char *ret;

	ret = prefix_ntop(buff, PREFIX_MAXBUFFLEN, &p_allones_67, true);
	sput_fail_if(strcmp(ret, p_allones_67_can_s), "Canonical prefix print");

	ret = prefix_ntop(buff, PREFIX_MAXBUFFLEN, &p_allones_67, false);
	sput_fail_if(strcmp(ret, p_allones_67_s), "Non canonical prefix print");
}

void prefix_contains_t(void)
{
	sput_fail_if(prefix_contains(&p1, &p2),
			"p1 and p2 are disjoint");
	sput_fail_if(prefix_contains(&p2, &p1),
			"p1 and p2 are disjoint");
	sput_fail_unless(prefix_contains(&p1, &p11),
			"p1 contains p11");
	sput_fail_unless(prefix_contains(&p1, &p1f),
			"p1 contains p1f");
	sput_fail_if(prefix_contains(&p2, &p11),
			"p2 do not contain p11");
}

void prefix_cmp_t(void)
{
	sput_fail_unless(prefix_cmp(&p1, &p11) > 0,
			"Prefix compare diff. plen (1)");
	sput_fail_unless(prefix_cmp(&p11, &p1) < 0,
			"Prefix compare diff. plen (2)");
	sput_fail_unless(prefix_cmp(&p_allones_67, &p_allones_128) > 0,
			"Prefix compare diff. plen (3)");

	sput_fail_unless(prefix_cmp(&p2, &p1) > 0,
			"Prefix compare value (1)");
	sput_fail_unless(prefix_cmp(&p10, &p11) < 0,
			"Prefix compare value (2)");
}

void prefix_random_t(void)
{
	int i;
	struct prefix p;

	sput_fail_unless(prefix_random(&p_allones_67, &p, 60),
			"Too short plen for random prefix");

	prefix_random(&p_allones_67_can, &p, 67);
	sput_fail_if(prefix_cmp(&p_allones_67_can, &p),
			"Only one possible random prefix");

	bool success = true;
	for(i = 0; i < 20; i++) {
		prefix_random(&p_allones_67, &p, 70);
		if(!prefix_contains(&p_allones_67, &p)) {
			success = false;
			break;
		}
	}
	sput_fail_unless(success, "Random prefix is in src prefix");
}

int main(__attribute__((unused)) int argc, __attribute__((unused))char **argv)
{
  sput_start_testing();
  sput_enter_suite("prefix_utils"); /* optional */
  sput_run_test(bmemcpy_t);
  sput_run_test(prefix_print_nocan_t);
  sput_run_test(prefix_equal_t);
  sput_run_test(prefix_canonical_t);
  sput_run_test(prefix_print_can_t);
  sput_run_test(prefix_contains_t);
  sput_run_test(prefix_cmp_t);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
