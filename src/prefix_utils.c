#include "prefix_utils.h"

#include <string.h>

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

	uint8_t *p1 = (uint8_t *) m1 + bytes;
	uint8_t *p2 = (uint8_t *) m2 + bytes;
	uint8_t mask = (0xff >> (8 - rembit)) << (8 - rembit);

	return ((int) (*p1 & mask)) - ((int) (*p2 & mask));
}

/* Copy nbits from *one* byte to another.
 * @frombit First bit to be copied (0 <= x < 8)
 * @nbits Number of bits to be copied (0 < x <= 8 - frombit)
 * TODO: Test that function
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
 * TODO: Test that function
 */
static void bmemcpy(void *dst, const void *src,
		size_t frombit, size_t nbits)
{
	// First bit that should not be copied
	size_t tobit = frombit + nbits;

	size_t frombyte = frombit >> 3;
	size_t tobyte = tobit >> 3;
	uint8_t frombitrem = frombit &0x07;
	uint8_t tobitrem = tobit &0x07;

	dst+=frombyte;
	src+=frombyte;

	if(frombyte == tobyte) {
		bbytecpy(dst, src, frombitrem, nbits);
		return;
	}

	if(frombitrem) {
		bbytecpy(dst, src, frombitrem, 8 - frombitrem);
		dst++;
		src++;
	}

	memcpy(dst, src, tobyte - frombyte - 1);

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

void prefix_canonical(struct prefix *p)
{
	struct in6_addr zero;
	memset(&zero, 0, sizeof(zero));
	bmemcpy(&p->prefix, &zero, p->plen, 128 - p->plen);
}

int prefix_random(const struct prefix *p, struct prefix *dst,
		uint8_t plen)
{
	struct in6_addr rand;

	if(plen > 128 || plen < p->plen)
		return -1;

	/* TODO: TO BE DEFINED */
	random_read(&rand, sizeof(rand));

	dst->plen = plen;
	memcpy(&dst->prefix, &p->prefix, sizeof(rand));
	bmemcpy(&dst->prefix, &rand, p->plen, plen - p->plen);
	return 0;
}


