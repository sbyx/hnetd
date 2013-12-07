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

#include "hcp_pa.h"
#include "ipc.h"
#include "platform.h"

typedef struct {
	struct iface_user iu;
	hcp hcp;
} hcp_iface_user_s, *hcp_iface_user;


void hcp_iface_intiface_callback(struct iface_user *u,
				 const char *ifname, bool enabled)
{
	hcp_iface_user hiu = container_of(u, hcp_iface_user_s, iu);

	hcp_set_link_enabled(hiu->hcp, ifname, enabled);
}

void hcp_iface_glue(hcp_iface_user hiu, hcp h)
{
	/* Initialize hiu appropriately */
	memset(hiu, 0, sizeof(*hiu));
	hiu->iu.cb_intiface = hcp_iface_intiface_callback;
	hiu->hcp = h;

	/* We don't care about other callbacks for now. */
	iface_register_user(&hiu->iu);
}

int main(__unused int argc, char* const argv[])
{
	hcp h;
	struct pa_conf pa_conf;
	pa_t pa;
	int c;
	hcp_iface_user_s hiu;

	if (strstr(argv[0], "hnet-call"))
		return ipc_client(argv[1]);

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		L_ERR("Must be run as root!");
		return 2;
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

	pa_conf_default(&pa_conf);
	pa = pa_create(&pa_conf);
	if (!pa) {
		L_ERR("Unable to initialize PA");
		return 13;
	}

	h = hcp_create();
	if (!h) {
		L_ERR("Unable to initialize HCP");
		return 42;
	}

	if (!hcp_pa_glue_create(h, pa)) {
		L_ERR("Unable to connect hcp and pa");
		return 17;
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

	/* Init ipc */
	iface_init(pa);

	/* Glue together HCP and iface */
	hcp_iface_glue(&hiu, h);

	/* Fire up the prefix assignment code. */
	pa_start(pa);

	uloop_run();
	return 0;
}
