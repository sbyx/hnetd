/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <stdio.h>
#include <unistd.h>
#include <getopt.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "ipc.h"
#include "iface.h"
#include "dhcp.h"
#include "dhcpv6.h"

static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events);
static struct uloop_fd ipcsock = { .cb = ipc_handle };
static const char *ipcpath = "/var/run/hnetd.sock";

enum ipc_option {
	OPT_COMMAND,
	OPT_IFNAME,
	OPT_HANDLE,
	OPT_PREFIX,
	OPT_DNS,
	OPT_ACCEPT_CERID,
	OPT_CERID,
	OPT_GUEST,
	OPT_LINK_ID,
	OPT_IFACE_ID,
	OPT_MAX
};

struct blobmsg_policy ipc_policy[] = {
	[OPT_COMMAND] = {"command", BLOBMSG_TYPE_STRING},
	[OPT_IFNAME] = {"ifname", BLOBMSG_TYPE_STRING},
	[OPT_HANDLE] = {"handle", BLOBMSG_TYPE_STRING},
	[OPT_PREFIX] = {"prefix", BLOBMSG_TYPE_ARRAY},
	[OPT_DNS] = {"dns", BLOBMSG_TYPE_ARRAY},
	[OPT_ACCEPT_CERID] = {"accept_cerid", BLOBMSG_TYPE_BOOL},
	[OPT_CERID] = {"cerid", BLOBMSG_TYPE_STRING},
	[OPT_GUEST] = {"guest", BLOBMSG_TYPE_BOOL},
	[OPT_LINK_ID] = {"link_id", BLOBMSG_TYPE_STRING},
	[OPT_IFACE_ID] = {"iface_id", BLOBMSG_TYPE_ARRAY},
};

enum ipc_prefix_option {
	PREFIX_ADDRESS,
	PREFIX_EXCLUDED,
	PREFIX_PREFERRED,
	PREFIX_VALID,
	PREFIX_CLASS,
	PREFIX_MAX
};

struct blobmsg_policy ipc_prefix_policy[] = {
	[PREFIX_ADDRESS] = {"address", BLOBMSG_TYPE_STRING},
	[PREFIX_EXCLUDED] = {"excluded", BLOBMSG_TYPE_STRING},
	[PREFIX_PREFERRED] = {"preferred", BLOBMSG_TYPE_INT32},
	[PREFIX_VALID] = {"valid", BLOBMSG_TYPE_INT32},
	[PREFIX_CLASS] = {"class", BLOBMSG_TYPE_INT32}
};


int ipc_init(void)
{
	unlink(ipcpath);
	ipcsock.fd = usock(USOCK_UNIX | USOCK_SERVER | USOCK_UDP, ipcpath, NULL);
	if (ipcsock.fd < 0) {
		L_ERR("Unable to create IPC socket");
		return 3;
	}
	uloop_fd_add(&ipcsock, ULOOP_EDGE_TRIGGER | ULOOP_READ);
	return 0;
}


// CLI JSON->IPC TLV converter for 3rd party dhcp client integration
int ipc_client(const char *buffer)
{
	struct blob_buf b = {NULL, NULL, 0, NULL};
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_string(&b, buffer)) {
		fprintf(stderr, "Failed to parse input data: %s\n", buffer);
		return 1;
	}

	for (ssize_t len = blob_len(b.head); true; sleep(1)) {
		int sock = usock(USOCK_UNIX | USOCK_UDP, ipcpath, NULL);
		if (sock < 0)
			perror("Failed to open socket");

		if (send(sock, blob_data(b.head), len, 0) == len)
			break;

		perror("Failed to talk to hnetd");
		close(sock);
	}
	return 0;
}


// Multicall handler for hnet-ifup/hnet-ifdown
int ipc_ifupdown(int argc, char *argv[])
{
	struct blob_buf b = {NULL, NULL, 0, NULL};
	blob_buf_init(&b, 0);

	bool external = false;
	void *p;
	char *buf;
	char *entry;

	int c;
	while ((c = getopt(argc, argv, "ecgp:l:i:")) > 0) {
		switch(c) {
		case 'e':
			external = true;
			break;

		case 'c':
			blobmsg_add_u8(&b, "accept_cerid", 1);
			break;

		case 'g':
			blobmsg_add_u8(&b, "guest", 1);
			break;

		case 'p':
			buf = strdup(optarg);
			p = blobmsg_open_array(&b, "prefix");
			for (entry = strtok(buf, ", "); entry; entry = strtok(NULL, ", "))
				blobmsg_add_string(&b, NULL, entry);
			blobmsg_close_array(&b, p);
			free(buf);
			break;

		case 'l':
			blobmsg_add_string(&b, "link_id", optarg);
			break;

		case 'i':
			buf = strdup(optarg);
			p = blobmsg_open_array(&b, "iface_id");
			for (entry = strtok(buf, ","); entry; entry = strtok(NULL, ","))
				blobmsg_add_string(&b, NULL, entry);
			blobmsg_close_array(&b, p);
			free(buf);
			break;
		}
	}


	blobmsg_add_string(&b, "command", strstr(argv[0], "ifup") ? "ifup" : "ifdown");
	blobmsg_add_string(&b, "ifname", argv[optind]);

	if (!external)
		blobmsg_add_string(&b, "handle", argv[optind]);

	return ipc_client(blobmsg_format_json(b.head, true));
}


// Handle internal IPC message
static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events)
{
	uint8_t buf[4096];
	ssize_t len;
	struct sockaddr_un sender;
	socklen_t sender_len = sizeof(sender);
	struct blob_attr *tb[OPT_MAX];

	while ((len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr*)&sender, &sender_len)) >= 0) {
		blobmsg_parse(ipc_policy, OPT_MAX, tb, buf, len);
		if (!tb[OPT_COMMAND] || !tb[OPT_IFNAME])
			continue;

		const char *ifname = blobmsg_get_string(tb[OPT_IFNAME]);
		struct iface *c = iface_get(ifname);

		const char *cmd = blobmsg_get_string(tb[OPT_COMMAND]);
		L_DEBUG("Handling ipc command %s", cmd);
		if (!strcmp(cmd, "ifup")) {
			enum iface_flags flags = 0;

			if (tb[OPT_ACCEPT_CERID] && blobmsg_get_bool(tb[OPT_ACCEPT_CERID]))
				flags |= IFACE_FLAG_ACCEPT_CERID;

			if (tb[OPT_GUEST] && blobmsg_get_bool(tb[OPT_GUEST]))
				flags |= IFACE_FLAG_GUEST;

			struct iface *iface = iface_create(ifname, tb[OPT_HANDLE] == NULL ? NULL :
					blobmsg_get_string(tb[OPT_HANDLE]), flags);

			if (iface && tb[OPT_PREFIX]) {
				struct blob_attr *k;
				unsigned rem;

				blobmsg_for_each_attr(k, tb[OPT_PREFIX], rem) {
					struct prefix p;
					if (blobmsg_type(k) == BLOBMSG_TYPE_STRING &&
							prefix_pton(blobmsg_get_string(k), &p) == 1)
						iface_add_chosen_prefix(iface, &p);
				}
			}

			unsigned link_id, link_mask;
			if (iface && tb[OPT_LINK_ID] && sscanf(
						blobmsg_get_string(tb[OPT_LINK_ID]),
						"%x/%u", &link_id, &link_mask) == 2)
					iface_set_link_id(iface, link_id, link_mask);

			if (iface && tb[OPT_IFACE_ID]) {
				struct blob_attr *k;
				unsigned rem;

				blobmsg_for_each_attr(k, tb[OPT_IFACE_ID], rem) {
					if (blobmsg_type(k) == BLOBMSG_TYPE_STRING) {
						char astr[55], fstr[55];
						struct prefix filter, addr;
						int res = sscanf(blobmsg_get_string(k), "%54s %54s", astr, fstr);
						if(!res || !prefix_pton(astr, &addr) || (res > 1 && !prefix_pton(fstr, &filter))) {
							L_ERR("Incorrect iface_id syntax %s", blobmsg_get_string(k));
							continue;
						}
						if(addr.plen == 128 && !addr.prefix.s6_addr32[0] && !addr.prefix.s6_addr32[1])
							addr.plen = 64;
						if(res == 1)
							filter.plen = 0;
						iface_add_addrconf(iface, &addr.prefix, 128 - addr.plen, &filter);
					}
				}
			}
		} else if (!strcmp(cmd, "ifdown")) {
			iface_remove(c);
		} else if (!strcmp(cmd, "enable_ipv4_uplink")) {
			const size_t dns_max = 4;
			size_t dns_cnt = 0;
			struct {
				uint8_t type;
				uint8_t len;
				struct in_addr addr[dns_max];
			} dns;

			if (tb[OPT_DNS]) {
				struct blob_attr *k;
				unsigned rem;

				blobmsg_for_each_attr(k, tb[OPT_DNS], rem) {
					if (dns_cnt >= dns_max || blobmsg_type(k) != BLOBMSG_TYPE_STRING ||
							inet_pton(AF_INET, blobmsg_data(k), &dns.addr[dns_cnt]) < 1)
						continue;

					++dns_cnt;
				}
			}

			if (dns_cnt) {
				dns.type = DHCPV4_OPT_DNSSERVER;
				dns.len = 4 * dns_cnt;
			}

			iface_update_ipv4_uplink(c);
			iface_add_dhcp_received(c, &dns, ((uint8_t*)&dns.addr[dns_cnt]) - ((uint8_t*)&dns));
			iface_set_ipv4_uplink(c);
			iface_commit_ipv4_uplink(c);
		} else if (!strcmp(cmd, "disable_ipv4_uplink")) {
			iface_update_ipv4_uplink(c);
			iface_commit_ipv4_uplink(c);

			if (avl_is_empty(&c->delegated.avl))
				iface_remove(c);
		} else if (!strcmp(cmd, "enable_ipv6_uplink")) {
			hnetd_time_t now = hnetd_time();
			iface_update_ipv6_uplink(c);

			struct blob_attr *k;
			unsigned rem;
			blobmsg_for_each_attr(k, tb[OPT_PREFIX], rem) {
				hnetd_time_t valid = HNETD_TIME_MAX, preferred = HNETD_TIME_MAX;

				struct prefix addr = {IN6ADDR_ANY_INIT, 0};
				struct prefix ex = {IN6ADDR_ANY_INIT, 0};
				struct blob_attr *tb[PREFIX_MAX];
				blobmsg_parse(ipc_prefix_policy, PREFIX_MAX, tb,
						blobmsg_data(k), blobmsg_data_len(k));

				if (!tb[PREFIX_ADDRESS] || !prefix_pton(blobmsg_get_string(tb[PREFIX_ADDRESS]), &addr))
					continue;

				if (tb[PREFIX_EXCLUDED])
					prefix_pton(blobmsg_get_string(tb[PREFIX_EXCLUDED]), &ex);

				if (tb[PREFIX_PREFERRED])
					preferred = now + blobmsg_get_u32(tb[PREFIX_PREFERRED]) * HNETD_TIME_PER_SECOND;

				if (tb[PREFIX_VALID])
					valid = now + blobmsg_get_u32(tb[PREFIX_VALID]) * HNETD_TIME_PER_SECOND;

				void *data = NULL;
				size_t len = 0;

#ifdef EXT_PREFIX_CLASS
				struct dhcpv6_prefix_class pclass = {
					.type = htons(DHCPV6_OPT_PREFIX_CLASS),
					.len = htons(2),
					.class = htons(atoi(blobmsg_get_string(a)))
				};

				if ((a = tb[PREFIX_CLASS])) {
					data = &pclass;
					len = sizeof(pclass);
				}
#endif
				iface_add_delegated(c, &addr, (ex.plen) ? &ex : NULL, valid, preferred, data, len);
			}


			const size_t dns_max = 4;
			size_t dns_cnt = 0;
			struct {
				uint16_t type;
				uint16_t len;
				struct in6_addr addr[dns_max];
			} dns;

			if (tb[OPT_DNS]) {
				struct blob_attr *k;
				unsigned rem;

				blobmsg_for_each_attr(k, tb[OPT_DNS], rem) {
					if (dns_cnt >= dns_max || blobmsg_type(k) != BLOBMSG_TYPE_STRING ||
							inet_pton(AF_INET6, blobmsg_data(k), &dns.addr[dns_cnt]) < 1)
						continue;

					++dns_cnt;
				}
			}

			if (dns_cnt) {
				dns.type = htons(DHCPV6_OPT_DNS_SERVERS);
				dns.len = htons(dns_cnt * sizeof(struct in6_addr));
				iface_add_dhcpv6_received(c, &dns, ((uint8_t*)&dns.addr[dns_cnt]) - ((uint8_t*)&dns));
			}

			if (tb[OPT_CERID])
				inet_pton(AF_INET6, blobmsg_get_string(tb[OPT_CERID]), &c->cer);

			iface_commit_ipv6_uplink(c);
		} else if (!strcmp(cmd, "disable_ipv6_uplink")) {
			iface_update_ipv6_uplink(c);
			iface_commit_ipv6_uplink(c);

			if (!c->v4uplink)
				iface_remove(c);
		}
	}
}
