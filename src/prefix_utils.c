/*
 * Author: Pierre Pfister
 *
 * Prefixes manipulation utilities.
 *
 */

#include "prefix_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct prefix ipv4_in_ipv6_prefix = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff }},
		.plen = 96 };

struct prefix ipv6_ula_prefix = {
		.prefix = { .s6_addr = { 0xfc }},
		.plen = 7 };

struct prefix ipv6_ll_prefix = {
		.prefix = { .s6_addr = { 0xfe,0x80 }},
		.plen = 10 };

struct prefix ipv6_global_prefix = {
		.prefix = { .s6_addr = { 0x20 }},
		.plen = 3 };

static int bmemcmp(const void *m1, const void *m2, size_t bitlen)
{
	size_t bytes = bitlen >> 3;
	int r;
	if( (r = memcmp(m1, m2, bytes)) )
		return r;

	uint8_t rembit = bitlen & 0x07;
	if(!rembit)
		return 0;

	uint8_t *p1 = ((uint8_t *) m1) + bytes;
	uint8_t *p2 = ((uint8_t *) m2) + bytes;
	uint8_t mask = (0xff >> (8 - rembit)) << (8 - rembit);

	return ((int) (*p1 & mask)) - ((int) (*p2 & mask));
}

/* Copy nbits from *one* byte to another.
 * @frombit First bit to be copied (0 <= x < 8)
 * @nbits Number of bits to be copied (0 < x <= 8 - frombit)
 */
static void bbytecpy (uint8_t *dst, const uint8_t *src,
		uint8_t frombit, uint8_t nbits) {

	uint8_t mask = 0xff;
	mask <<= frombit;
	mask >>= 8 - nbits;
	mask <<= 8 - nbits - frombit;

	*dst &= ~mask;
	*dst |= (*src & mask);
}

/* Copy bits of memory from src to dst.
 * Starts from bit #frombit and copies nbits.
 */
void bmemcpy(void *dst, const void *src,
		size_t frombit, size_t nbits)
{
	// First bit that should not be copied
	size_t tobit = frombit + nbits;

	size_t frombyte = frombit >> 3;
	size_t tobyte = tobit >> 3;
	uint8_t frombitrem = frombit & 0x07;
	uint8_t tobitrem = tobit & 0x07;

	dst+=frombyte;
	src+=frombyte;

	if(frombyte == tobyte) {
		bbytecpy(dst, src, frombitrem, nbits);
		return;
	}

	if(frombitrem) {
		bbytecpy(dst, src, frombitrem, 8 - frombitrem);
		memcpy(dst + 1, src + 1, tobyte - frombyte - 1);
	} else {
		memcpy(dst, src, tobyte - frombyte);
	}

	if(tobitrem)
		bbytecpy(dst + tobyte, src + tobyte, 0, tobitrem);
}


bool prefix_contains(const struct prefix *p1,
					const struct prefix *p2)
{
	if(p1->plen > p2->plen)
		return 0;

	return !bmemcmp(&p1->prefix, &p2->prefix, p1->plen);
}

int prefix_cmp(const struct prefix *p1,
		const struct prefix *p2)
{
	if(p1->plen != p2->plen)
		return p2->plen - p1->plen;

	return bmemcmp(&p1->prefix, &p2->prefix, p1->plen);
}

void prefix_canonical(struct prefix *dst, const struct prefix *src)
{
	struct in6_addr zero;
	memset(&zero, 0, sizeof(zero));
	if(src != dst)
		memcpy(dst, src, sizeof(struct prefix));
	bmemcpy(&dst->prefix, &zero, dst->plen, 128 - dst->plen);
}

int prefix_random(const struct prefix *p, struct prefix *dst,
		uint8_t plen)
{
	struct in6_addr rand;

	if(plen > 128 || plen < p->plen)
		return -1;

	size_t i;
	for (i = 0; i < sizeof(rand); ++i)
		rand.s6_addr[i] = random();

	dst->plen = plen;
	memcpy(&dst->prefix, &p->prefix, sizeof(struct in6_addr));
	bmemcpy(&dst->prefix, &rand, p->plen, plen - p->plen);
	return 0;
}

char *prefix_ntop(char *dst, size_t dst_len,
		const struct prefix *prefix,
		bool canonical)
{
	struct prefix can;
	const struct prefix *to_use;

	if(canonical) {
		prefix_canonical(&can, prefix);
		to_use = &can;
	} else {
		to_use = prefix;
	}

	const char *res = inet_ntop(AF_INET6, &to_use->prefix, dst, dst_len);

	if(!res)
		return NULL;

	size_t written = strlen(dst);
	size_t remaining = dst_len - written;
	char *end = dst + written;

	if(snprintf(end, remaining, "/%u", to_use->plen) >= (int) remaining)
		return NULL;

	return dst;
}

