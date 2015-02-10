/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 */

#include "bitops.h"

#include <string.h>

static uint8_t bbytecpy_masks[9] =
	{0x00, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};

void bbytecpy (uint8_t *dst, const uint8_t *src,
		uint8_t frombit, uint8_t nbits)
{
	uint8_t mask = bbytecpy_masks[nbits] >> frombit;
	uint8_t v = *src & mask;
	*dst = (*dst & ~mask) | v;
}

void bmemcpy(void *dst, const void *src,
		size_t frombit, size_t nbits)
{
	// First bit that should not be copied
	size_t tobit = frombit + nbits;

	size_t frombyte = frombit >> 3;
	size_t tobyte = tobit >> 3;
	size_t nbyte = tobyte - frombyte;
	uint8_t frombitrem = frombit & 0x07;
	uint8_t tobitrem = tobit & 0x07;

	dst+=frombyte;
	src+=frombyte;

	if(!nbyte) {
		bbytecpy(dst, src, frombitrem, nbits);
		return;
	}

	if(frombitrem) {
		bbytecpy(dst, src, frombitrem, 8 - frombitrem);
		dst += 1;
		src += 1;
		nbyte -= 1;
	}

	memcpy(dst, src, nbyte);

	if(tobitrem)
		bbytecpy(dst + nbyte, src + nbyte, 0, tobitrem);
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


int bmemcmp(const void *m1, const void *m2, size_t bitlen)
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
	uint8_t mask = ((uint8_t)0xff) << (8 - rembit);

	return ((int) (*p1 & mask)) - ((int) (*p2 & mask));
}


static const char hexdigits[] = "0123456789abcdef";
static const int8_t hexvals[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

ssize_t unhexlify(uint8_t *dst, size_t len, const char *src)
{
	size_t c;
	for (c = 0; c < len && src[0] && src[1]; ++c) {
		int8_t x = (int8_t)*src++;
		int8_t y = (int8_t)*src++;
		if (x < 0 || (x = hexvals[x]) < 0
				|| y < 0 || (y = hexvals[y]) < 0)
			return -1;
		dst[c] = x << 4 | y;
		while (((int8_t)*src) < 0 ||
				(*src && hexvals[(uint8_t)*src] < 0))
			src++;
	}

	return c;
}

char *hexlify(char *dst, const uint8_t *src, size_t len)
{
	char *ret = dst;
	for (size_t i = 0; i < len; ++i) {
		*dst++ = hexdigits[src[i] >> 4];
		*dst++ = hexdigits[src[i] & 0x0f];
	}
	*dst = 0;
	return ret;
}
