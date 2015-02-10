/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Advanced bitwise operations.
 *
 */

#ifndef BITOPS_H_
#define BITOPS_H_

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

/**
 * Copy bits from one byte to another.
 *
 * Bits are indexed from greatest to lowest significance.
 *
 * @param dst Destination byte.
 * @param src Source byte (Can be equal to dst byte).
 * @parem frombit First copied bit index (From 0 to 7).
 * @param nbits Number of copied bits (From 0 to 8).
 */
void bbytecpy (uint8_t *dst, const uint8_t *src,
		uint8_t frombit, uint8_t nbits);

/**
 * Compare two prefixes of same bit length.
 *
 * @param m1 First compared value.
 * @param m2 Second compared value.
 * @param bitlen Number of bits to be compared.
 *
 * @return
 *   0 if bitlen first bits are equal in m1 and m2.
 *   A positive value if the first different bit is greater in m1.
 *   A negative value if the first different bit is greater in m2.
 */
int bmemcmp(const void *m1, const void *m2, size_t bitlen);

/**
 * Copy bits from one buffer to another.
 *
 * @param dst Buffer to which bits are copied.
 * @param src Buffer from which bits are copied.
 * @param frombit First copied bit index.
 * @param nbits Number of copied bits.
 */
void bmemcpy(void *dst, const void *src,
		size_t frombit, size_t nbits);

/**
 * Copy unaligned bit sequences from one buffer to another.
 *
 * @param dst Buffer to which bits are copied.
 * @param dst_start Bit index of the first replaced bit in dst.
 * @param src Buffer from which bits are copied.
 * @param nbits Number of copied bits.
 */
void bmemcpy_shift(void *dst, size_t dst_start,
		const void *src, size_t src_start,
		size_t nbits);

ssize_t unhexlify(uint8_t *dst, size_t len, const char *src);
char *hexlify(char *dst, const uint8_t *src, size_t len);

#endif
