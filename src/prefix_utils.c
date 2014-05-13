/*
 * Author: Pierre Pfister
 *
 * Prefixes manipulation utilities.
 *
 */

#include "prefix_utils.h"

#include <libubox/md5.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct prefix ipv4_in_ipv6_prefix = {
		.prefix = { .s6_addr = {
				0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
				0x00,0x00, 0xff,0xff }},
		.plen = 96 };

/* While IETF has assigned fc00::/7 for ULAs, fc00::/8 is 'reserved';
 * we use only fd00::/8 for locally generated ULA /48s. */
struct prefix ipv6_ula_prefix = {
		.prefix = { .s6_addr = { 0xfd }},
		.plen = 8 };

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

void bmemcpy_shift(void *dst, size_t dst_start,
		const void *src, size_t src_start,
		size_t nbits)
{
	dst += dst_start >> 3;
	dst_start &= 0x7;
	src += src_start >> 3;
	src_start &= 0x7;

	if(dst_start == src_start) {
		bmemcpy(dst, src, dst_start, nbits);
	} else {
		while(nbits) {
			uint8_t interm = *((uint8_t *)src);
			uint8_t n;
			int8_t shift = src_start - dst_start;
			if(shift > 0) {
				interm <<= shift;
				n = 8 - src_start;
				if(n > nbits)
					n = nbits;
				bbytecpy(dst, &interm, dst_start, n);
				dst_start += n;
				src_start = 0;
				src++;
			} else {
				interm >>= -shift;
				n = 8 - dst_start;
				if(n > nbits)
					n = nbits;
				bbytecpy(dst, &interm, dst_start, n);
				dst_start = 0;
				dst++;
				src_start += n;
			}
			nbits -= n;
		}
	}
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

void prefix_cpy(struct prefix *dst, const struct prefix *src)
{
	memcpy(dst, src, sizeof(struct prefix));
}

uint8_t prefix_af_length(const struct prefix *p)
{
	if(prefix_is_ipv4(p)) {
		return p->plen - 96;
	}
	return p->plen;
}

void prefix_canonical(struct prefix *dst, const struct prefix *src)
{
	struct in6_addr zero;
	memset(&zero, 0, sizeof(zero));
	if(src != dst)
		*dst = *src;
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
	dst->prefix = p->prefix;
	bmemcpy(&dst->prefix, &rand, p->plen, plen - p->plen);
	return 0;
}

int prefix_prandom(const char *seed, size_t seedlen, uint32_t ctr,
		const struct prefix *p, struct prefix *dst,
		uint8_t plen)
{
	struct in6_addr rand;
	md5_ctx_t ctx;

	if(plen > 128 || plen < p->plen)
		return -1;

	md5_begin(&ctx);
	md5_hash(seed, seedlen, &ctx);
	md5_hash(&ctr, sizeof(ctr), &ctx);
	md5_end(rand.s6_addr, &ctx);

	dst->plen = plen;
	dst->prefix = p->prefix;
	bmemcpy(&dst->prefix, &rand, p->plen, plen - p->plen);
	return 0;
}

int prefix_increment(struct prefix *dst, const struct prefix *p, uint8_t protected_len)
{
	if(p->plen < protected_len || p->plen - protected_len > 32)
		return -1;

	uint8_t blen = p->plen - protected_len;
	uint32_t step = (blen)?(1 << (32 - blen)):0;
	uint32_t current = 0;
	bmemcpy_shift(&current, 0, &p->prefix, protected_len, blen);
	current = ntohl(current);
	current += step;
	current = htonl(current);

	if (dst != p)
		memcpy(dst, p, sizeof(struct prefix));

	bmemcpy_shift(&dst->prefix, protected_len, &current, 0, blen);

	return (current && blen)?0:1;
}

void prefix_number(struct prefix *dst, const struct prefix *src, uint32_t id, uint8_t id_len)
{
	if(id_len > 32)
		id_len = 32;
	if(id_len > src->plen)
		id_len = src->plen;

	uint32_t i = htonl(id);
	prefix_canonical(dst, src);
	bmemcpy_shift(dst, src->plen - id_len, &i, 32 - id_len, id_len);
}

int prefix_last(struct prefix *dst, const struct prefix *p, uint8_t protected_len)
{
	struct prefix mask, res;
	if(p->plen < protected_len)
		return -1;

	memset(&mask, 0xff, sizeof(struct prefix));
	memcpy(&res, p, sizeof(struct prefix));
	bmemcpy(&res.prefix, &mask.prefix, protected_len, p->plen - protected_len);
	memcpy(dst, &res, sizeof(struct prefix));

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

	const char *res;
	uint8_t plen;

	if (!IN6_IS_ADDR_V4MAPPED(&to_use->prefix)) {
		res = inet_ntop(AF_INET6, &to_use->prefix, dst, dst_len);
		plen = to_use->plen;
	} else {
		res = inet_ntop(AF_INET, &to_use->prefix.s6_addr[12], dst, dst_len);
		plen = to_use->plen - 96;
	}

	if(!res)
		return NULL;

	size_t written = strlen(dst);
	size_t remaining = dst_len - written;
	char *end = dst + written;

	if(snprintf(end, remaining, "/%u", plen) >= (int) remaining)
		return NULL;

	return dst;
}

int prefix_pton(const char *addr, struct prefix *p)
{
	char buf[INET6_ADDRSTRLEN];
	char *slash = strchr(addr, '/'), *c;
	uint8_t parsed_len = 128;
	size_t addrlen;
	if(slash) {
		addrlen = strlen(slash + 1);
		if(!addrlen || addrlen > 3)
			return 0;

		/* atoi doesn't return errors, so we check string correctness */
		for(c = slash + 1; *c; c++) {
			if(*c < '0' || *c > '9')
				return 0;
		}
		parsed_len = atoi(slash + 1);
		addrlen = slash - addr;
	} else {
		addrlen = strlen(addr);
	}

	if (addrlen >= INET6_ADDRSTRLEN)
		return 0;

	memcpy(buf, addr, addrlen);
	buf[addrlen] = 0;

	if(!slash)
		p->plen = 128;

	if(inet_pton(AF_INET6, buf, &p->prefix) == 1) {
		if(slash) {
			if(parsed_len > 128)
				return 0;
			p->plen = parsed_len;
		}
	} else if(inet_pton(AF_INET, buf, &p->prefix.s6_addr[12]) == 1) {
		if(slash) {
			if(parsed_len > 32)
				return 0;
			p->plen = parsed_len + 96;
		}
		memset(&p->prefix, 0, 10);
		p->prefix.s6_addr[10] = 0xff;
		p->prefix.s6_addr[11] = 0xff;
	} else {
		return 0;
	}

	return 1;
}
