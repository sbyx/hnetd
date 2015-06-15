/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
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
 * Compares two bit strings starting from an arbitrary position.
 *
 * @param m1 First compared value buffer.
 * @param m2 Second compared value buffer.
 * @param start Starting bit index. Previous bits are ignored.
 * @param nbits Number of bits to be compared.
 *
 * @return
 *   0 if bits from 'start' to 'start + nbits' are equal in m1 and m2.
 *   A positive value if the first different bit is greater in m1.
 *   A negative value if the first different bit is greater in m2.
 */
int bmemcmp_s(const uint8_t *m1, const uint8_t *m2, size_t start, size_t nbits);

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

/**
 * Computes the Hamming distance between char arrays.
 *
 * @param m1 First array
 * @param m2 Second array
 * @param nbits Number of considered bits for the distance computation.
 */
size_t hamming_distance_64(const uint64_t *m1, const uint64_t *m2, size_t nbits);

/**
 * Provides the value  and distance which minimizes the Hamming distance with a given
 * target value, while remaining lower than the maximum value.
 * Bits which index is under start_len are ignored and not modified.
 *
 * @param max Array representing the maximum value.
 * @param target The array with respect to which the hamming distance is computed.
 * @param dst Where the resulting array is written.
 * @param start_len First considered bit.
 *                  Previous bits from all arays are just ignored and left unmodified.
 * @param nbits The number of considered bits.
 * @return The Hamming distance between the returned dst and target.
 */
size_t hamming_minimize(const uint8_t *max, const uint8_t *target,
		uint8_t *dst, size_t start_len, size_t nbits);

ssize_t unhexlify(uint8_t *dst, size_t len, const char *src);
char *hexlify(char *dst, const uint8_t *src, size_t len);

#endif
