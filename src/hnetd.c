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
#include <stdlib.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <fcntl.h>

#include <libubox/uloop.h>

#include "hcp.h"
#include "ipc.h"
#include "platform.h"

int main(__unused int argc, char* const argv[])
{
	hcp h;
	int c;

	if (strstr(argv[0], "hnet-call"))
		return ipc_client(argv[1]);

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		L_ERR("Must be run as root!");
		return 2;
	}

	if (iface_init()) {
		L_ERR("Failed to init platform: %s", strerror(errno));
		return 3;
	}

	if (ipc_init()) {
		L_ERR("Failed to init IPC: %s", strerror(errno));
		return 5;
	}

	int urandom_fd;
	if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) >= 0) {
		unsigned int seed;
		read(urandom_fd, &seed, sizeof(seed));
		close(urandom_fd);
		srandom(seed);
	}

	h = hcp_create();
	if (!h) {
		L_ERR("Unable to initialize HCP");
		return 42;
	}

	/* XXX - add real command line parsing at some point. For the
	 * time being, I've added just this utility to get hcp up and
	 * running ;) -MSt. */
	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			/* internal interface */
			(void)hcp_set_link_enabled(h, optarg, true);
			break;
		}
	}

	uloop_run();
	return 0;
}
