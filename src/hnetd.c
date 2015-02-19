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
#include "hncp_proto.h"
#include "hncp_link.h"
#include "hncp_dump.h"
#include "platform.h"
#include "pa.h"
#include "pd.h"
#include "dncp_trust.h"

#ifdef DTLS
#include "dtls.h"
#endif /* DTLS */

#define FLOODING_DELAY 2 * HNETD_TIME_PER_SECOND

int log_level = LOG_INFO;

typedef struct {
	struct iface_user iu;
	dncp hncp;
	hncp_glue glue;
} hncp_iface_user_s, *hncp_iface_user;


void hncp_iface_intaddr_callback(struct iface_user *u, const char *ifname,
								 const struct prefix *addr6,
								 const struct prefix *addr4 __unused)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);

	dncp_if_set_ipv6_address(hiu->hncp, ifname, addr6 ? &addr6->prefix : NULL);
}


void hncp_iface_intiface_callback(struct iface_user *u,
								  const char *ifname, bool enabled)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);
	struct iface *c = iface_get(ifname);
	dncp_if_set_enabled(hiu->hncp, ifname, enabled &&
			(c->flags & IFACE_FLAG_LEAF) != IFACE_FLAG_LEAF);
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


void hncp_iface_glue(hncp_iface_user hiu, dncp h, hncp_glue g)
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

int usage() {
  L_ERR( "Valid options are:\n"
	 "\t-d dnsmasq_script\n"
	 "\t-f dnsmasq_bonus_file\n"
	 "\t-o odhcp_script\n"
	 "\t-c pcp_script\n"
	 "\t-n router_name\n"
	 "\t-m domain_name\n"
	 "\t-s pa_store file\n"
	 "\t-p socket path\n"
	 "\t--ip4prefix v.x.y.z/prefix\n"
	 "\t--ulaprefix v:x:y:z::/prefix\n"
	 "\t--ulamode [on,off,ifnov6]\n"
	 "\t--loglevel [0-9]\n"
	 "\t--password <DTLS password for auth>\n"
	 "\t--certificate <(DTLS) path to local certificate>\n"
	 "\t--privatekey <(DTLS) path to local private key>\n"
	 "\t--trust <(DTLS) path to trust consensus store file>\n"
	 "\t--verify-path <(DTLS) path to trusted cert file>\n"
	 "\t--verify-dir <(DTLS) path to trusted cert directory>\n"
	 );
    return(3);
}

int main(__unused int argc, char *argv[])
{
	dncp h;
	struct pa pa;
	int c;
	hncp_iface_user_s hiu;
	hncp_glue hg;
	hncp_sd_params_s sd_params;
	dncp_trust dt = NULL;
	struct hncp_link_config link_config = {HNCP_VERSION, 0, 0, 0, 0, ""};

	memset(&sd_params, 0, sizeof(sd_params));

	openlog("hnetd", LOG_PERROR | LOG_PID, LOG_DAEMON);
	uloop_init();

	if (getuid() != 0) {
		L_ERR("Must be run as root!");
		return 2;
	}

	// Register multicalls
	hd_register_rpc();
#ifdef DTLS
	dncp_trust_register_multicall();
#endif

	int ret = platform_rpc_multicall(argc, argv);
	if (ret >= 0)
		return ret;

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
	const char *pa_ulamode = NULL;
	const char *dtls_password = NULL;
	const char *dtls_trust = NULL;
	const char *dtls_cert = NULL;
	const char *dtls_key = NULL;
	const char *dtls_path = NULL;
	const char *dtls_dir = NULL;
	const char *pidfile = NULL;

	enum {
		GOL_IPPREFIX = 1000,
		GOL_ULAPREFIX,
		GOL_ULAMODE,
		GOL_LOGLEVEL,
		GOL_PASSWORD, /* DTLS password */
		GOL_CERT, /* DTLS certificate */
		GOL_KEY, /* DTLS (private) key */
		GOL_TRUST, /* DTLS trust cache filename */
		GOL_DIR, /* DTLS trusted cert dir */
		GOL_PATH, /* DTLS trusted cert file path */
	};

	struct option longopts[] = {
			//Can use no_argument, required_argument or optional_argument
			{ "ip4prefix",   required_argument,      NULL,           GOL_IPPREFIX },
			{ "ulaprefix",   required_argument,      NULL,           GOL_ULAPREFIX },
			{ "ulamode",     required_argument,      NULL,           GOL_ULAMODE },
			{ "loglevel",    required_argument,      NULL,           GOL_LOGLEVEL },
			{ "password",    required_argument,      NULL,           GOL_PASSWORD },
			{ "trust",    required_argument,      NULL,           GOL_TRUST },
			{ "certificate",    required_argument,      NULL,           GOL_CERT },
			{ "privatekey",    required_argument,      NULL,           GOL_KEY },
			{ "verifydir",    required_argument,      NULL,           GOL_DIR },
			{ "verifypath",    required_argument,      NULL,           GOL_PATH },
			{ "help",	 no_argument,		 NULL,           '?' },
			{ NULL,          0,                      NULL,           0 }
	};

	while ((c = getopt_long(argc, argv, "?b::d:f:o:n:r:s:p:m:c:", longopts, NULL)) != -1) {
		switch (c) {
		case 'b':
			pidfile = (optarg && optarg[0]) ? optarg : "/var/run/hnetd.pid";
			break;
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
		case GOL_ULAMODE:
			pa_ulamode = optarg;
			break;
		case GOL_LOGLEVEL:
			log_level = atoi(optarg);
			break;
		case GOL_PASSWORD:
			dtls_password = optarg;
			break;
		case GOL_TRUST:
			dtls_trust = optarg;
			break;
		case GOL_DIR:
			dtls_dir = optarg;
			break;
		case GOL_PATH:
			dtls_path = optarg;
			break;
		case GOL_KEY:
			dtls_key = optarg;
			break;
		case GOL_CERT:
			dtls_cert = optarg;
			break;
		default:
			L_ERR("Unrecognized option");
		case '?':
			return usage();
			break;
		}
	}

	h = hncp_create();
	if (!h) {
		L_ERR("Unable to initialize HNCP");
		return 42;
	}

	hd_init(h);
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

	if(pa_ulamode) {
		if(!strcmp(pa_ulamode, "off")) {
			pa.local.conf.use_ula = 0;
		} else if(!strcmp(pa_ulamode, "ifnov6")) {
			pa.local.conf.use_ula = 1;
			pa.local.conf.no_ula_if_glb_ipv6 = 1;
		} else if(!strcmp(pa_ulamode, "on")) {
			pa.local.conf.use_ula = 1;
			pa.local.conf.no_ula_if_glb_ipv6 = 0;
		} else {
			L_ERR("Invalid ulamode option (Can be on, off or ifnov6)");
			return 43;
		}
	}

	if (sd_params.dnsmasq_script && sd_params.dnsmasq_bonus_file && sd_params.ohp_script)
		link_config.cap_mdnsproxy = 4;

	link_config.cap_prefixdel = link_config.cap_hostnames = link_config.cap_legacy = 4;
	snprintf(link_config.agent, sizeof(link_config.agent), "hnetd/%s", STR(HNETD_VERSION));

	if (dtls_password || dtls_trust || dtls_dir || dtls_path) {
#ifdef DTLS
		dtls d;
		if (!(d = dtls_create(HNCP_DTLS_SERVER_PORT))) {
			L_ERR("Unable to create dtls");
			return 13;
		}
		if (dtls_key && dtls_cert) {
				if (!dtls_set_local_cert(d, dtls_cert, dtls_key)) {
						L_ERR("Unable to set certificate+key");
						return 13;
				}
		}
		if (dtls_dir || dtls_path) {
				if (!dtls_set_verify_locations(d, dtls_path, dtls_dir)) {
						L_ERR("Unable to set verify locations");
						return 13;
				}
		}
		hncp_set_dtls(h, d);
		if (dtls_password) {
				if (!(dtls_set_psk(d,
								   dtls_password, strlen(dtls_password)))) {
						L_ERR("Unable to set dtls password");
						return 13;
				}
		} else if (dtls_trust) {
				dt = dncp_trust_create(h, dtls_trust);
				if (!dt) {
						L_ERR("Unable to create dncp trust module");
						return 13;
				}
		}
		dtls_start(d);
#endif /* DTLS */
	}

	if (!(hg = hncp_pa_glue_create(h, &pa.data))) {
		L_ERR("Unable to connect hncp and pa");
		return 17;
	}

	struct hncp_link *link = hncp_link_create(h, &link_config);

	hncp_sd sd = hncp_sd_create(h, &sd_params, link);
	if (!sd) {
		L_ERR("unable to initialize sd, exiting");
		return 71;
	}

	if (routing_script)
		hncp_routing_create(h, routing_script);

	/* Init ipc (no RPC-registrations after this point!) */
	iface_init(h, sd, &pa, link, pd_socket_path);

	/* Glue together HNCP, PA-glue and and iface */
	hncp_iface_glue(&hiu, h, hg);

	/* PA */
	pd_create(&pa.pd, pd_socket_path);
	pa_set_hncp(&pa, h);

	/* Fire up the prefix assignment code. */
	pa_start(&pa);

	if (pidfile && !daemon(0, 0)) {
		FILE *fp = fopen(pidfile, "w");
		if (fp) {
			fprintf(fp, "%d\n", getpid());
			fclose(fp);
		}

		closelog();
		openlog("hnetd", LOG_PID, LOG_DAEMON);
	}

	uloop_run();

	if (pidfile)
		unlink(pidfile);
	return 0;
}
