/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * IPv4 and IPv6 prefix parsing functions.
 *
 * IPv4 prefixes are stored as IPv4 in IPv6 mapped address with shifted prefix
 * length.
 * For instance, 1.2.3.0/24 is stored as ::ffff:1.2.3.0/120.
 *
 */

#ifndef PREFIX_H_
#define PREFIX_H_

#include <netinet/in.h>

/**
 * Maximum required space to print a prefix.
 */
#define PREFIX_MAXBUFFLEN (INET6_ADDRSTRLEN + 4)

/**
 * Format helper for address representation.
 *
 * IPv4 in IPv6 mapped address are represented as IPv4 addresses.
 *
 * @param addr The IPv6 address in binary form.
 * @return A string representing the IPv6 or IPv4 address.
 */
#define ADDR_REPR(addr) \
		(IN6_IS_ADDR_V4MAPPED(addr))?\
				inet_ntop(AF_INET, &(addr)->s6_addr[12], alloca(INET_ADDRSTRLEN), INET_ADDRSTRLEN):\
				inet_ntop(AF_INET6, addr, alloca(INET6_ADDRSTRLEN), INET6_ADDRSTRLEN)

/**
 * Converts an IPv6 prefix from binary to text form.
 *
 * Non-significant bits from the prefix are considered.
 * IPv4 in IPv6 mapped prefixes are represented in their
 * IPv4 form.
 *
 * @param dst The destination buffer.
 * @param bufflen The destination buffer length.
 * @param addr The address to be displayed.
 * @param plen The prefix length.
 * @return dst on success or NULL on otherwise.
 */
const char *prefix_ntop(char *dst, size_t bufflen, const struct in6_addr *addr,
		uint8_t plen);

/**
 * Converts an IPv6 prefix from binary to text form.
 *
 * Similar to prefix_ntop, but only significant bits
 * from the prefix are displayed.
 *
 * @param dst The destination buffer.
 * @param bufflen The destination buffer length.
 * @param addr The address to be displayed.
 * @param plen The prefix length.
 * @return dst on success or NULL on otherwise.
 */
const char *prefix_ntopc(char *dst, size_t bufflen,
		const struct in6_addr *prefix, uint8_t plen);

/**
 * Converts an IPv4 or IPv6 prefix from text to binary form.
 *
 * Non-significant bits are converted too.
 *
 * @param src The string representing an IPv4 or IPv6 prefix.
 * @param addr The address destination pointer.
 * @param plen The prefix length destination pointer.
 * @return 1 upon **success** or 0 otherwise (Because this what inet_pton does).
 */
int prefix_pton(const char *src, struct in6_addr *addr, uint8_t *plen);

#endif
