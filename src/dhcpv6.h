#ifndef DHCPV6_H_
#define DHCPV6_H_

#include <stdint.h>
#include <arpa/inet.h>

enum dhcvp6_opt {
	DHCPV6_OPT_DNS_SERVERS = 23,
	DHCPV6_OPT_DNS_DOMAIN = 24,
#ifdef EXT_PREFIX_CLASS
        /* draft-bhandari-dhc-class-based-prefix, not yet standardized */
	DHCPV6_OPT_PREFIX_CLASS = EXT_PREFIX_CLASS,
#endif
};

#ifdef EXT_PREFIX_CLASS
struct dhcpv6_prefix_class {
	uint16_t type;
	uint16_t len;
	uint16_t class;
};
#endif

#define dhcpv6_for_each_option(start, end, otype, olen, odata)\
	for (uint8_t *_o = (uint8_t*)(start); _o + 4 <= (uint8_t*)(end) &&\
		((otype) = _o[0] << 8 | _o[1]) && ((odata) = (void*)&_o[4]) &&\
		((olen) = _o[2] << 8 | _o[3]) + (odata) <= (uint8_t*)(end); \
		_o += 4 + (_o[2] << 8 | _o[3]))


#endif
