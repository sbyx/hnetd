/*
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 * Copyright (c) 2014-2015 Cisco Systems, Inc.
 *
 */

#include "prefix.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *addr_ntop(char *dst, size_t bufflen, const struct in6_addr *addr)
{
	if (IN6_IS_ADDR_V4MAPPED(addr)) {
		return inet_ntop(AF_INET, &addr->s6_addr[12], dst, bufflen);
	} else {
		return inet_ntop(AF_INET6, addr, dst, bufflen);
	}
}

const char *prefix_ntop(char *dst, size_t bufflen, const struct in6_addr *addr,
		uint8_t plen)
{
	if (bufflen < 4 || !addr_ntop(dst, bufflen - 4, addr))
		return NULL ;

	char *str = dst + strlen(dst);
	if (plen >= 96 && IN6_IS_ADDR_V4MAPPED(addr)) {
		sprintf(str, "/%d", plen - 96);
	} else {
		sprintf(str, "/%d", plen);
	}
	return dst;
}

const char *prefix_ntopc(char *dst, size_t bufflen, const struct in6_addr *addr,
		uint8_t plen)
{
	struct in6_addr p = { .s6_addr = { } };
	size_t bytes = plen >> 3;
	memcpy(&p, addr, bytes);
	uint8_t rembit = plen & 0x07;
	if (rembit)
		p.s6_addr[bytes] = (0xff << (8 - rembit)) & addr->s6_addr[bytes];

	return prefix_ntop(dst, bufflen, &p, plen);
}

int prefix_pton(const char *src, struct in6_addr *addr, uint8_t *plen)
{
	char buf[INET6_ADDRSTRLEN];
	char *slash = strchr(src, '/'), *c;
	uint8_t parsed_len = 128;
	size_t addrlen;
	if (slash) {
		addrlen = strlen(slash + 1);
		if (!addrlen || addrlen > 3)
			return 0;

		/* atoi doesn't return errors, so we check string correctness */
		for (c = slash + 1; *c; c++) {
			if (*c < '0' || *c > '9')
				return 0;
		}
		parsed_len = atoi(slash + 1);
		addrlen = slash - src;
	} else {
		addrlen = strlen(src);
	}

	if (addrlen >= INET6_ADDRSTRLEN)
		return 0;

	memcpy(buf, src, addrlen);
	buf[addrlen] = 0;

	if (!slash)
		*plen = 128;

	if (inet_pton(AF_INET6, buf, addr) == 1) {
		if (slash) {
			if (parsed_len > 128)
				return 0;
			*plen = parsed_len;
		}
	} else if (inet_pton(AF_INET, buf, &addr->s6_addr[12]) == 1) {
		if (slash) {
			if (parsed_len > 32)
				return 0;
			*plen = parsed_len + 96;
		}
		memset(addr, 0, 10);
		addr->s6_addr[10] = 0xff;
		addr->s6_addr[11] = 0xff;
	} else {
		return 0;
	}

	return 1;
}
