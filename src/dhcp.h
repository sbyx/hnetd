/*
 * Copyright (c) 2015 Cisco Systems, Inc.
 */
#ifndef DHCP_H_
#define DHCP_H_

enum dhcpv4_opt {
	DHCPV4_OPT_NETMASK = 1,
	DHCPV4_OPT_ROUTER = 3,
	DHCPV4_OPT_DNSSERVER = 6,
	DHCPV4_OPT_DOMAIN = 15,
	DHCPV4_OPT_MTU = 26,
	DHCPV4_OPT_BROADCAST = 28,
	DHCPV4_OPT_NTPSERVER = 42,
	DHCPV4_OPT_LEASETIME = 51,
	DHCPV4_OPT_MESSAGE = 53,
	DHCPV4_OPT_SERVERID = 54,
	DHCPV4_OPT_RENEW = 58,
	DHCPV4_OPT_REBIND = 59,
	DHCPV4_OPT_IPADDRESS = 50,
	DHCPV4_OPT_HOSTNAME = 10,
	DHCPV4_OPT_REQUEST = 17,
	DHCPV4_OPT_VENDOR_SPECIFIC_INFORMATION = 125,
	DHCPV4_OPT_END = 255,
};


struct dhcpv4_option {
	uint8_t type;
	uint8_t len;
	uint8_t data[];
};


#define dhcpv4_for_each_option(start, end, opt)\
	for (opt = (struct dhcpv4_option*)(start); \
		&opt[1] <= (struct dhcpv4_option*)(end) && \
			&opt->data[opt->len] <= (end); \
		opt = (struct dhcpv4_option*)&opt->data[opt->len])


#endif /* DHCP_H_ */
