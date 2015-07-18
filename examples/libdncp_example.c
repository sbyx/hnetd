/*
 * Copyright (c) 2015 Cisco Systems, Inc.
 */
#include "dncp.h"

/*
 * You can compile a static library implementing basic dncp API.
 * This library will require the program to be linked with it to
 * implement the functions defined in dncp_profile.h
 *
 * In this example, we just include code from hncp, where these functions
 * are implemented.
 */

int log_level = 7;

#include <stdarg.h>
static void example_log(__unused int priority, const char *format, ...) {
	va_list myargs;
	va_start(myargs, format);
	vprintf(format, myargs);
	printf("\n");
	va_end(myargs);
}

void (*hnetd_log)(int priority, const char *format, ...) = example_log;

/* In this example, we just use hncp's functions */
#include "udp46.c"
#include "hncp_io.c"
#include "hncp.c"

int main (int argc, char **argv)
{
	hncp hncp;

	uloop_init();
	if(!(hncp = hncp_create())) {
		L_ERR("hncp_create error");
		return -1;
	}

	argc--;
	argv++;
	while(argc) {
		if(!hncp_io_set_ifname_enabled(hncp, argv[0], 1)) {
			L_ERR("Could not enable iface %s", argv[0]);
			return -1;
		}
		argc--;
		argv++;
	}

	char *data = "The answer";
	dncp_tlv tlv = dncp_add_tlv(hncp->dncp, 42, data, strlen(data), 0);
	if(!(tlv)) {
		L_ERR("Could not publish TLV");
	}

	uloop_run();
	return 0;
}
