#include <syslog.h>
#include <errno.h>
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "dhcpv6.h"
#include "platform.h"
#include "iface.h"
#include "prefix_utils.h"

static char backend[] = "/usr/sbin/hnetd-backend";


struct platform_iface {
	pid_t dhcpv4;
	pid_t dhcpv6;
};

int platform_init(void)
{
	return 0;
}

// Run platform script
static pid_t platform_run(char *argv[])
{
	pid_t pid = vfork();
	if (pid == 0) {
		execv(argv[0], argv);
		_exit(128);
	}
	return pid;
}

//
static void platform_call(char *argv[])
{
	pid_t pid = platform_run(argv);
	waitpid(pid, NULL, 0);
}

// Constructor for openwrt-specific interface part
void platform_iface_new(struct iface *c, __unused const char *handle)
{
	char *argv_dhcpv4[] = {backend, "dhcpv4client", c->ifname, NULL};
	char *argv_dhcpv6[] = {backend, "dhcpv6client", c->ifname, NULL};
	assert(c->platform == NULL);

	struct platform_iface *iface = calloc(1, sizeof(*iface));
	iface->dhcpv4 = platform_run(argv_dhcpv4);
	iface->dhcpv6 = platform_run(argv_dhcpv6);

	c->platform = iface;
}

// Destructor for openwrt-specific interface part
void platform_iface_free(struct iface *c)
{
	struct platform_iface *iface = c->platform;
	if (iface) {
		kill(iface->dhcpv4, SIGTERM);
		kill(iface->dhcpv6, SIGTERM);

		free(iface);
		c->platform = NULL;
	}
}


void platform_set_internal(struct iface *c, bool internal)
{
	char *argv[] = {backend, (internal) ? "setfilter" : "unsetfilter",
			c->ifname, NULL};
	platform_call(argv);
}


void platform_set_address(struct iface *c, struct iface_addr *a, bool enable)
{
	hnetd_time_t now = hnetd_time();
	char abuf[PREFIX_MAXBUFFLEN], pbuf[10], vbuf[10], cbuf[10] = "";
	prefix_ntop(abuf, sizeof(abuf), &a->prefix, false);

	if (!IN6_IS_ADDR_V4MAPPED(&a->prefix.prefix)) {
		hnetd_time_t valid = (a->valid_until - now) / HNETD_TIME_PER_SECOND;
		if (valid <= 0)
			enable = false;
		else if (valid > UINT32_MAX)
			valid = UINT32_MAX;

		hnetd_time_t preferred = (a->preferred_until - now) / HNETD_TIME_PER_SECOND;
		if (preferred < 0)
			preferred = 0;
		else if (preferred > UINT32_MAX)
			preferred = UINT32_MAX;

		snprintf(pbuf, sizeof(pbuf), "%u", (unsigned)preferred);
		snprintf(vbuf, sizeof(vbuf), "%u", (unsigned)valid);
	}

	uint8_t *oend = &a->dhcpv6_data[a->dhcpv6_len], *odata;
	uint16_t olen, otype;
	dhcpv6_for_each_option(a->dhcpv6_data, oend, otype, olen, odata) {
#ifdef EXT_PREFIX_CLASS
		if (otype == DHCPV6_OPT_PREFIX_CLASS && olen == 2) {
			uint16_t class = (uint16_t)odata[0] << 8 | (uint16_t)odata[1];
			snprintf(cbuf, sizeof(cbuf), "%u", (unsigned)class);
		}
#endif
	}

	char *argv[] = {backend, (enable) ? "newaddr" : "deladdr",
			c->ifname, abuf, pbuf, vbuf, cbuf, NULL};
	platform_call(argv);
}


void platform_set_route(struct iface *c, struct iface_route *route, bool enable)
{
	char from[PREFIX_MAXBUFFLEN];
	char to[PREFIX_MAXBUFFLEN];
	char via[INET6_ADDRSTRLEN];

	prefix_ntop(from, sizeof(from), &route->from, true);
	prefix_ntop(to, sizeof(to), &route->to, true);
	inet_ntop(AF_INET6, &route->via, via, sizeof(via));

	char *argv[] = {backend, (enable) ? "newroute" : "delroute",
			c->ifname, to, via, from, NULL};
	platform_call(argv);
}


void platform_set_owner(struct iface *c, bool enable)
{
	char *argv[] = {backend, (enable) ? "startdhcp" : "stopdhcp", c->ifname, NULL};
	platform_call(argv);
}


void platform_set_dhcpv6_send(struct iface *c, const void *dhcpv6_data, size_t len)
{
	// DNS options
	const size_t dns_max = 4;
	size_t dns_cnt = 0;
	struct in6_addr dns[dns_max];

	// Add per interface DHCPv6 options
	uint8_t *oend = ((uint8_t*)dhcpv6_data) + len, *odata;
	uint16_t olen, otype;
	dhcpv6_for_each_option(dhcpv6_data, oend, otype, olen, odata) {
		if (otype == DHCPV6_OPT_DNS_SERVERS) {
			size_t cnt = olen / sizeof(*dns);
			if (cnt + dns_cnt > dns_max)
				cnt = dns_max - dns_cnt;

			memcpy(&dns[dns_cnt], odata, cnt * sizeof(*dns));
			dns_cnt += cnt;
		}
	}

	pid_t pid = fork();
	if (pid == 0) {
		char *argv[] = {backend, "setdhcpv6", c->ifname, NULL};

		char *dnsbuf = malloc(dns_cnt * INET6_ADDRSTRLEN + 5);
		strcpy(dnsbuf, "DNS=");
		for (size_t i = 0; i < dns_cnt; ++i)
			inet_ntop(AF_INET6, &dns[i], dnsbuf + strlen(dnsbuf), INET6_ADDRSTRLEN);
		putenv(dnsbuf);

		execv(argv[0], argv);
		_exit(128);
	}
	waitpid(pid, NULL, 0);
}