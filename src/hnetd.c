/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 * Author: Pierre Pfister
 *
 * Copyright (c) 2014 cisco Systems, Inc.
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

#include "hncp_pa.h"
#include "hncp_sd.h"
#include "hncp_routing.h"
#include "ipc.h"
#include "platform.h"
#include "pa.h"
#include "pd.h"

#define FLOODING_DELAY 2 * HNETD_TIME_PER_SECOND

typedef struct {
	struct iface_user iu;
	hncp hncp;
	hncp_glue glue;
} hncp_iface_user_s, *hncp_iface_user;


void hncp_iface_intaddr_callback(struct iface_user *u, const char *ifname,
								 const struct prefix *addr6,
								 const struct prefix *addr4 __unused)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);

	hncp_set_ipv6_address(hiu->hncp, ifname, addr6 ? &addr6->prefix : NULL);
}


void hncp_iface_intiface_callback(struct iface_user *u,
								  const char *ifname, bool enabled)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);
	struct iface *c = iface_get(ifname);
	hncp_set_link_enabled(hiu->hncp, ifname, enabled && !(c->flags & IFACE_FLAG_GUEST));
}


void hncp_iface_extdata_callback(struct iface_user *u,
								 const char *ifname __unused,
								 const void *dhcpv6_data __unused,
								 size_t dhcpv6_len __unused)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);

	hncp_pa_set_dhcpv6_data_in_dirty(hiu->glue);
}


void hncp_iface_glue(hncp_iface_user hiu, hncp h, hncp_glue g)
{
	/* Initialize hiu appropriately */
	memset(hiu, 0, sizeof(*hiu));
	hiu->iu.cb_intiface = hncp_iface_intiface_callback;
	hiu->iu.cb_intaddr = hncp_iface_intaddr_callback;
	hiu->iu.cb_extdata = hncp_iface_extdata_callback;
	hiu->iu.cb_ext4data = hncp_iface_extdata_callback;
	hiu->hncp = h;
	hiu->glue = g;

	/* We don't care about other callbacks for now. */
	iface_register_user(&hiu->iu);
}

int main(__unused int argc, char *argv[])
{
	hncp h;
	struct pa pa;
	int c;
	hncp_iface_user_s hiu;
	hncp_glue hg;
	hncp_sd_params_s sd_params = {};

#ifdef WITH_IPC
	if (strstr(argv[0], "hnet-call"))
		return ipc_client(argv[1]);
	else if ((strstr(argv[0], "hnet-ifup") || strstr(argv[0], "hnet-ifdown")) && argc >= 2)
		return ipc_ifupdown(argc, argv);
#endif

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		L_ERR("Must be run as root!");
		return 2;
	}

#ifdef WITH_IPC
	if (ipc_init()) {
		L_ERR("Failed to init IPC: %s", strerror(errno));
		return 5;
	}
#endif

	int urandom_fd;
	if ((urandom_fd = open("/dev/urandom", O_CLOEXEC | O_RDONLY)) >= 0) {
		unsigned int seed;
		read(urandom_fd, &seed, sizeof(seed));
		close(urandom_fd);
		srandom(seed);
	}

	const char *routing_script = NULL;
	const char *pa_store_file = NULL;
	const char *pd_socket_path = "/var/run/hnetd_pd";

	while ((c = getopt(argc, argv, "d:f:o:n:r:s:p:m:")) != -1) {
		switch (c) {
		case 'd':
			sd_params.dnsmasq_script = optarg;
			break;
		case 'f':
			sd_params.dnsmasq_bonus_file = optarg;
			break;
		case 'o':
			sd_params.ohp_script = optarg;
			break;
		case 'n':
			sd_params.router_name = optarg;
			break;
		case 'm':
			sd_params.domain_name = optarg;
			break;
		case 'r':
			routing_script = optarg;
			break;
		case 's':
			pa_store_file = optarg;
			break;
		case 'p':
			pd_socket_path = optarg;
			break;
		}
	}

	pa_init(&pa, NULL);
	if(pa_store_file)
		pa_store_setfile(&pa.store, pa_store_file);

	h = hncp_create();
	if (!h) {
		L_ERR("Unable to initialize HNCP");
		return 42;
	}

	if (!(hg = hncp_pa_glue_create(h, &pa.data))) {
		L_ERR("Unable to connect hncp and pa");
		return 17;
	}

	if (!hncp_sd_create(h, &sd_params)) {
		L_ERR("unable to initialize rd, exiting");
		return 71;
	}

	if (routing_script)
		hncp_routing_create(h, routing_script);

	/* Init ipc */
	iface_init(&pa, pd_socket_path);

	/* Glue together HNCP, PA-glue and and iface */
	hncp_iface_glue(&hiu, h, hg);

	/* PA */
	pd_create(&pa.pd, pd_socket_path);

	/* Fire up the prefix assignment code. */
	pa_start(&pa);

	uloop_run();
	return 0;
}
