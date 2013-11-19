/**
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License v2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>

#include <libubox/uloop.h>

#include "ipc.h"
#include "prefix.h"
#include "platform.h"


int main(__unused int argc, char* const argv[])
{
	if (strstr(argv[0], "hnet-call"))
		return ipc_client(argv[1]);

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		syslog(LOG_ERR, "Must be run as root!");
		return 2;
	}

	if (platform_init()) {
		syslog(LOG_ERR, "Failed to init platform: %s", strerror(errno));
		return 3;
	}

	if (prefix_init()) {
		syslog(LOG_ERR, "Failed to init prefix: %s", strerror(errno));
		return 4;
	}

	if (ipc_init()) {
		syslog(LOG_ERR, "Failed to init IPC: %s", strerror(errno));
		return 5;
	}

	uloop_run();
	return 0;
}
