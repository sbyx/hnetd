/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 * Author: Pierre Pfister
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <time.h>
#include <errno.h>
#include <getopt.h>
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

int log_level = LOG_INFO;

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

	hncp_if_set_ipv6_address(hiu->hncp, ifname, addr6 ? &addr6->prefix : NULL);
}


void hncp_iface_intiface_callback(struct iface_user *u,
								  const char *ifname, bool enabled)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);
	struct iface *c = iface_get(ifname);
	hncp_if_set_enabled(hiu->hncp, ifname, enabled && !(c->flags & IFACE_FLAG_GUEST));
}


void hncp_iface_extdata_callback(struct iface_user *u,
								 const char *ifname,
								 const void *dhcpv6_data,
								 size_t dhcpv6_len)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);

	hncp_pa_set_external_link(hiu->glue, ifname, dhcpv6_data, dhcpv6_len,
							  HNCP_PA_EXTDATA_IPV6);
}

void hncp_iface_ext4data_callback(struct iface_user *u,
								  const char *ifname,
								  const void *dhcpv4_data,
								  size_t dhcpv4_len)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);

	hncp_pa_set_external_link(hiu->glue, ifname, dhcpv4_data, dhcpv4_len,
							  HNCP_PA_EXTDATA_IPV4);
}


void hncp_iface_glue(hncp_iface_user hiu, hncp h, hncp_glue g)
{
	/* Initialize hiu appropriately */
	memset(hiu, 0, sizeof(*hiu));
	hiu->iu.cb_intiface = hncp_iface_intiface_callback;
	hiu->iu.cb_intaddr = hncp_iface_intaddr_callback;
	hiu->iu.cb_extdata = hncp_iface_extdata_callback;
	hiu->iu.cb_ext4data = hncp_iface_ext4data_callback;
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
	hncp_sd_params_s sd_params;

	memset(&sd_params, 0, sizeof(sd_params));
	if (strstr(argv[0], "hnet-ifresolve")) {
		if (!argv[1])
			return 1;

		int ifindex = if_nametoindex(argv[1]);
		if (ifindex) {
			printf("%i\n", ifindex);
			return 0;
		} else {
			return 2;
		}
	}
#ifdef WITH_IPC
	else if (strstr(argv[0], "hnet-call")) {
		if(argc < 2)
			return 3;
		return ipc_client(argv[1]);
	} else if (strstr(argv[0], "hnet-dump")) {
		return ipc_dump();
	} else if ((strstr(argv[0], "hnet-ifup") || strstr(argv[0], "hnet-ifdown"))) {
		if(argc < 2)
			return 3;
		return ipc_ifupdown(argc, argv);
	}
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
	const char *pa_ip4prefix = NULL;
	const char *pa_ulaprefix = NULL;

	enum {
		GOL_IPPREFIX = 1000,
		GOL_ULAPREFIX,
		GOL_LOGLEVEL,
	};

	struct option longopts[] = {
			//Can use no_argument, required_argument or optional_argument
			{ "ip4prefix",   required_argument,      NULL,           GOL_IPPREFIX },
			{ "ulaprefix",   required_argument,      NULL,           GOL_ULAPREFIX },
			{ "loglevel",    required_argument,      NULL,           GOL_LOGLEVEL },
			{ NULL,          0,                      NULL,           0 }
	};

	while ((c = getopt_long(argc, argv, "d:f:o:n:r:s:p:m:c:", longopts, NULL)) != -1) {
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
		case 'c':
			sd_params.pcp_script = optarg;
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
		case GOL_IPPREFIX:
			pa_ip4prefix = optarg;
			break;
		case GOL_ULAPREFIX:
			pa_ulaprefix = optarg;
			break;
		case GOL_LOGLEVEL:
			log_level = atoi(optarg);
			break;
		case '?':
			L_ERR("Unrecognized option");
			return 3;
		}
	}

	pa_init(&pa, NULL);
	if(pa_store_file)
		pa_store_setfile(&pa.store, pa_store_file);

	if(pa_ip4prefix) {
		if(!prefix_pton(pa_ip4prefix, &pa.local.conf.v4_prefix)) {
			L_ERR("Unable to parse ipv4 prefix option '%s'", pa_ip4prefix);
			return 40;
		} else if (!prefix_is_ipv4(&pa.local.conf.v4_prefix)) {
			L_ERR("The ip4prefix option '%s' is not an IPv4 prefix", pa_ip4prefix);
			return 41;
		} else {
			L_INFO("Setting %s as IPv4 prefix", PREFIX_REPR(&pa.local.conf.v4_prefix));
		}
	}

	if(pa_ulaprefix) {
		if(!prefix_pton(pa_ulaprefix, &pa.local.conf.ula_prefix)) {
			L_ERR("Unable to parse ula prefix option '%s'", pa_ulaprefix);
			return 40;
		} else if (prefix_is_ipv4(&pa.local.conf.ula_prefix)) {
			L_ERR("The ulaprefix option '%s' is an IPv4 prefix", pa_ulaprefix);
			return 41;
		} else {
			if (!prefix_is_ipv6_ula(&pa.local.conf.ula_prefix)) {
				L_WARN("The provided ULA prefix %s is not an ULA. I hope you know what you are doing.",
						PREFIX_REPR(&pa.local.conf.ula_prefix));
			}
			pa.local.conf.use_random_ula = false;
			L_INFO("Setting %s as ULA prefix", PREFIX_REPR(&pa.local.conf.ula_prefix));
		}
	}

	h = hncp_create();
	if (!h) {
		L_ERR("Unable to initialize HNCP");
		return 42;
	}

	if (!(hg = hncp_pa_glue_create(h, &pa.data))) {
		L_ERR("Unable to connect hncp and pa");
		return 17;
	}

	hncp_sd sd = hncp_sd_create(h, &sd_params);
	if (!sd) {
		L_ERR("unable to initialize sd, exiting");
		return 71;
	}

	if (routing_script)
		hncp_routing_create(h, routing_script);

	/* Init ipc */
	iface_init(h, sd, &pa, pd_socket_path);

	/* Glue together HNCP, PA-glue and and iface */
	hncp_iface_glue(&hiu, h, hg);

	/* PA */
	pd_create(&pa.pd, pd_socket_path);
	pa_set_hncp(&pa, h);

	/* Fire up the prefix assignment code. */
	pa_start(&pa);

#ifdef WITH_IPC
	/* Configure ipc */
	ipc_conf(h);
#endif

	uloop_run();
	return 0;
}
