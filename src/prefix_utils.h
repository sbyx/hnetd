/*
 * Author: Pierre Pfister
 *
 * Prefixes manipulation utilities.
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include <netinet/in.h>
#include <stdbool.h>

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

/* Tests whether p1 contains p2 */
bool prefix_contains(const struct prefix *p1,
					const struct prefix *p2);

#define prefix_is_ipv4(prefix) \
	prefix_contains(&ipv4_in_ipv6_prefix, prefix)

#define prefix_is_ipv6_ula(prefix) \
	prefix_contains(&ipv6_ula_prefix, prefix)

#define prefix_is_ll(prefix) \
	prefix_contains(&ipv6_ll_prefix, prefix)

#define prefix_is_global(prefix) \
	prefix_contains(&ipv6_global_prefix, prefix)

/* Compare two prefixes according to a complete order definition.
 * Will be used in trees.
 * Returns zero if equals, positive if p1 > p2,
 * negative value otherwise.
 * A prefix with longer prefix length is always smaller.
 * When prefix length is the same, bigger prefix value is bigger. */
int prefix_cmp(const struct prefix *p1,
		const struct prefix *p2);


/* Choose a random prefix of length plen, inside p, and returns 0.
 * Or returns -1 if there is not enaugh space in p for a prefix of
 * length plen. */
int prefix_random(const struct prefix *p, struct prefix *dst,
		uint8_t plen);


/* Sets prefix's last bits to zero.
 * May be useful when printing the prefix.
 * src and dst can be the same pointer. */
void prefix_canonical(struct prefix *dst, const struct prefix *src);

/* Maximum needed space to print a prefix */
#define PREFIX_MAXBUFFLEN (INET6_ADDRSTRLEN + 4)

/* Writes the prefix into the specified buffer of length dst_len.
 * Returns dst upon success and NULL if buffer size is too small.
 * Canonical means the last bits of the prefix are considered as
 * zeros. */
char *prefix_ntop(char *dst, size_t dst_len,
		const struct prefix *prefix,
		bool canonical);

/* This is provided as an option, to have prefix_ntop with
 * heap-allocated destination buffer (if we run out of heap, we have
 * lot bigger problems too so little need to worry here). */
#define PREFIX_NTOP(p, canonical)  \
	prefix_ntop(alloca(PREFIX_MAXBUFFLEN), PREFIX_MAXBUFFLEN, p, canonical)

/* Convenience variant of PREFIX_NTOP, which just chooses to
 * canonicalize the prefix. */
#define PREFIX_REPR(p) PREFIX_NTOP(p, true)

#endif
