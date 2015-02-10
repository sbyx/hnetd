/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Prefixes manipulation utilities.
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "prefix.h"
#include "bitops.h"

/* Prefix structure.
 * All bits following the plen first are ignored. */
struct prefix {
	struct in6_addr prefix;
	uint8_t plen;
};

extern struct prefix ipv4_in_ipv6_prefix;
extern struct prefix ipv6_ula_prefix;
extern struct prefix ipv6_ll_prefix;
extern struct prefix ipv6_global_prefix;

#define prefix_contains(p1, p2) ( ((p2)->plen >= (p1)->plen) && \
		!bmemcmp(&(p1)->prefix, &(p2)->prefix, (p1)->plen) )

#define prefix_is_ipv4(prefix) \
	prefix_contains(&ipv4_in_ipv6_prefix, prefix)

#define prefix_is_ipv6_ula(prefix) \
	prefix_contains(&ipv6_ula_prefix, prefix)

#define prefix_is_ll(prefix) \
	prefix_contains(&ipv6_ll_prefix, prefix)

#define prefix_is_global(prefix) \
	prefix_contains(&ipv6_global_prefix, prefix)

static inline int prefix_cmp(const struct prefix *p1, const struct prefix *p2) {
	int i;
	if((i = (int)p2->plen - (int)p1->plen))
		return i;

	return bmemcmp(&p1->prefix, &p2->prefix, p1->plen);
}

/*#define prefix_cmp(p1, p2) (((p1)->plen != (p2)->plen)?((p2)->plen - (p1)->plen):\
		bmemcmp(&(p1)->prefix, &(p2)->prefix, (p1)->plen))*/

#define prefix_af_length(p) prefix_is_ipv4(p)?(p)->plen - 96:(p)->plen

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
 * Format helper to represent a prefix in its canonical form.
 *
 * @param p The prefix.
 * @param len The prefix length.
 * @return A canonical string representation of the prefix.
 */
#define PREFIX_REPR_C(p) \
	prefix_ntopc(alloca(PREFIX_MAXBUFFLEN), PREFIX_MAXBUFFLEN, &(p)->prefix, (p)->plen)

/**
 * Format helper to represent a prefix.
 *
 * @param p The prefix.
 * @param len The prefix length.
 * @return A string representation of the address and prefix length.
 */
#define PREFIX_REPR(p) \
	prefix_ntop(alloca(PREFIX_MAXBUFFLEN), PREFIX_MAXBUFFLEN, &(p)->prefix, (p)->plen)


#endif
