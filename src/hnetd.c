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
#include "hcp_sd.h"
#include "hcp_bfs.h"
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
	else if ((strstr(argv[0], "hnet-ifup") || strstr(argv[0], "hnet-ifdown")) && argc >= 2)
		return ipc_ifupdown(argv[0], argv[1], argv[2]);

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

	hcp_bfs_create(h);

	const char *dnsmasq_script = NULL;
	const char *dnsmasq_bonus_file = NULL;
	const char *ohp_script = NULL;
	const char *router_name = NULL;

	while ((c = getopt(argc, argv, "d:b:o:n:")) != -1) {
		switch (c) {
		case 'd':
			dnsmasq_script = optarg;
			break;
		case 'b':
			dnsmasq_bonus_file = optarg;
			break;
		case 'o':
			ohp_script = optarg;
			break;
		case 'n':
			router_name = optarg;
			break;
		}
	}

	/* At some point should think of subset of these options is
	 * meaningful; if not, should combine them to single option,
	 * perhaps? */
	if (dnsmasq_script && ohp_script && dnsmasq_bonus_file) {
		if (!hcp_sd_create(h,
						   dnsmasq_script, dnsmasq_bonus_file,
						   ohp_script, router_name)) {
			L_ERR("unable to initialize rd, exiting");
			return 71;
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
