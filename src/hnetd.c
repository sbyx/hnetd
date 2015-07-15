/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 * Author: Pierre Pfister
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
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

#include "hnetd_time.h"
#include "hncp_pa.h"
#include "hncp_sd.h"
#include "hncp_multicast.h"
#include "hncp_routing.h"
#include "hncp_tunnel.h"
#include "hncp_proto.h"
#include "hncp_link.h"
#include "hncp_dump.h"
#include "platform.h"
#include "pd.h"
#include "dncp_trust.h"

#ifdef DTLS
#include "dtls.h"
#endif /* DTLS */

#define FLOODING_DELAY 2 * HNETD_TIME_PER_SECOND

int log_level = LOG_INFO;
void (*hnetd_log)(int priority, const char *format, ...) = syslog;

typedef struct {
	struct iface_user iu;
	hncp hncp;
} hncp_iface_user_s, *hncp_iface_user;

void hncp_iface_intaddr_cb(struct iface_user *u, const char *ifname,
								 const struct prefix *addr6,
								 const struct prefix *addr4 __unused)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);
	hncp_set_ipv6_address(hiu->hncp, ifname, addr6 ? &addr6->prefix : NULL);
}


void hncp_iface_intiface_cb(struct iface_user *u,
								  const char *ifname, bool enabled)
{
	hncp_iface_user hiu = container_of(u, hncp_iface_user_s, iu);
	struct iface *c = iface_get(ifname);
	hncp_set_enabled(hiu->hncp, ifname, enabled && (c->flags & IFACE_FLAG_LEAF) != IFACE_FLAG_LEAF);
}

void hncp_iface_glue(hncp_iface_user hiu, hncp h)
{
	/* Initialize hiu appropriately */
	memset(hiu, 0, sizeof(*hiu));
	hiu->iu.cb_intiface = hncp_iface_intiface_cb;
	hiu->iu.cb_intaddr = hncp_iface_intaddr_cb;
	hiu->hncp = h;
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
	 "\t-M multicast_script (enables draft-pfister-homenet-multicast support)\n"
	 );
    return(3);
}

int main(__unused int argc, char *argv[])
{
	hncp h;
	int c;
	hncp_iface_user_s hiu;
	hncp_pa hncp_pa;
	hncp_sd_params_s sd_params;
	hncp_multicast_params_s multicast_params;
#ifdef DTLS
	dncp_trust dt = NULL;
#endif /* DTLS */
	struct hncp_link_config link_config = {HNCP_VERSION, 0, 0, 0, 0, ""};

	memset(&sd_params, 0, sizeof(sd_params));
	memset(&multicast_params, 0, sizeof(multicast_params));

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
	const char *tunnel_script = NULL;
	const char *pa_store_file = NULL;
	const char *pd_socket_path = "/var/run/hnetd_pd";
	const char *pa_ip4prefix = NULL;
	const char *pa_ulaprefix = NULL;
	const char *pa_ulamode = NULL;
	const char *dtls_password = NULL;
	const char *dtls_trust = NULL;
#ifdef DTLS
	const char *dtls_cert = NULL;
	const char *dtls_key = NULL;
#endif
	const char *dtls_path = NULL;
	const char *dtls_dir = NULL;
	const char *pidfile = NULL;
	bool strict = false;

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

	while ((c = getopt_long(argc, argv, "?b::d:f:o:n:r:t:s:p:m:c:M:S", longopts, NULL)) != -1) {
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
		case 'M':
			multicast_params.multicast_script = optarg;
			break;
		case 'S':
			strict = true;
			break;
		case 'r':
			routing_script = optarg;
			break;
		case 't':
			tunnel_script = optarg;
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
#ifdef DTLS
			dtls_key = optarg;
#endif
			break;
#ifdef DTLS
		case GOL_CERT:
			dtls_cert = optarg;
#endif
			break;
		default:
			L_ERR("Unrecognized option");
			//no break
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

	hd_init(hncp_get_dncp(h));

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
				dt = dncp_trust_create(hncp_get_dncp(h), dtls_trust);
				if (!dt) {
						L_ERR("Unable to create dncp trust module");
						return 13;
				}
				dtls_set_unknown_cert_cb(d, dncp_trust_dtls_unknown_cb, dt);
		}
		dtls_start(d);
#endif /* DTLS */
	}

	struct hncp_link *link = hncp_link_create(hncp_get_dncp(h), &link_config);

	hncp_sd sd = hncp_sd_create(h, &sd_params, link);
	if (!sd) {
		L_ERR("unable to initialize sd, exiting");
		return 71;
	}

	if (multicast_params.multicast_script) {
			hncp_multicast m = hncp_multicast_create(h, &multicast_params);
			if (!m) {
					L_ERR("unable to initialize multicast, exiting");
					return 123;
			}
	}
	if (routing_script)
		hncp_routing_create(h, routing_script, !strict);

	if (tunnel_script)
		hncp_tunnel_create(hncp_get_dncp(h), tunnel_script);

	//Note that pa subscribes to iface. Which is possible before iface init.
	if(!(hncp_pa = hncp_pa_create(h, link))) {
		L_ERR("Unable to initialize PA");
		return 17;
	}

	//PA configuration

	if(pa_store_file && hncp_pa_storage_set(hncp_pa, pa_store_file)) {
		L_ERR("Could not set prefix storage file (%s): %s",
				pa_store_file, strerror(errno));
		return 18;
	}

	struct hncp_pa_ula_conf ula_conf;
	hncp_pa_ula_conf_default(&ula_conf);
	if(pa_ip4prefix) {
		if(!prefix_pton(pa_ip4prefix, &ula_conf.v4_prefix.prefix, &ula_conf.v4_prefix.plen)) {
			L_ERR("Unable to parse ipv4 prefix option '%s'", pa_ip4prefix);
			return 40;
		} else if (!prefix_is_ipv4(&ula_conf.v4_prefix)) {
			L_ERR("The ip4prefix option '%s' is not an IPv4 prefix", pa_ip4prefix);
			return 41;
		} else {
			L_INFO("Setting %s as IPv4 prefix", PREFIX_REPR(&ula_conf.v4_prefix));
		}
	}

	if(pa_ulaprefix) {
		if(!prefix_pton(pa_ulaprefix, &ula_conf.ula_prefix.prefix, &ula_conf.ula_prefix.plen)) {
			L_ERR("Unable to parse ula prefix option '%s'", pa_ulaprefix);
			return 40;
		} else if (prefix_is_ipv4(&ula_conf.ula_prefix)) {
			L_ERR("The ulaprefix option '%s' is an IPv4 prefix", pa_ulaprefix);
			return 41;
		} else {
			if (!prefix_is_ipv6_ula(&ula_conf.ula_prefix)) {
				L_WARN("The provided ULA prefix %s is not an ULA. I hope you know what you are doing.",
						PREFIX_REPR(&ula_conf.ula_prefix));
			}
			ula_conf.use_random_ula = false;
			L_INFO("Setting %s as ULA prefix", PREFIX_REPR(&ula_conf.ula_prefix));
		}
	}

	if(pa_ulamode) {
		if(!strcmp(pa_ulamode, "off")) {
			ula_conf.use_ula = 0;
		} else if(!strcmp(pa_ulamode, "ifnov6")) {
			ula_conf.use_ula = 1;
			ula_conf.no_ula_if_glb_ipv6 = 1;
		} else if(!strcmp(pa_ulamode, "on")) {
			ula_conf.use_ula = 1;
			ula_conf.no_ula_if_glb_ipv6 = 0;
		} else {
			L_ERR("Invalid ulamode option (Can be on, off or ifnov6)");
			return 43;
		}
	}

	hncp_pa_ula_conf_set(hncp_pa, &ula_conf);

	//End of PA conf

	/* Init ipc (no RPC-registrations after this point!)*/
	iface_init(h, sd, hncp_pa, link, pd_socket_path);

	/* Glue together HNCP, PA-glue and and iface */
	hncp_iface_glue(&hiu, h);

	/* Sub PD */
	pd_create(hncp_pa, pd_socket_path);

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
