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
#include "prefix_utils.h"
#include "hncp_dump.h"

static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events);
static struct uloop_fd ipcsock = { .cb = ipc_handle };
static const char *ipcpath = "/var/run/hnetd.sock";
static const char *ipcpath_client = "/var/run/hnetd-client%d.sock";
static hncp ipchncp = NULL;

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
	OPT_IP6_PLEN,
	OPT_ADHOC,
	OPT_DISABLE_PA,
	OPT_PASSTHRU,
	OPT_ULA_DEFAULT_ROUTER,
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
	[OPT_IP6_PLEN] = {"ip6_plen", BLOBMSG_TYPE_STRING},
	[OPT_ADHOC] = {"adhoc", BLOBMSG_TYPE_BOOL},
	[OPT_DISABLE_PA] = {"disable_pa", BLOBMSG_TYPE_BOOL},
	[OPT_PASSTHRU] = {"passthru", BLOBMSG_TYPE_STRING},
	[OPT_ULA_DEFAULT_ROUTER] = {"ula_default_router", BLOBMSG_TYPE_BOOL},
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

void ipc_conf(hncp hncp)
{
	ipchncp = hncp;
}

// CLI JSON->IPC TLV converter for 3rd party dhcp client integration
int ipc_client(const char *buffer)
{
	char sockaddr[108]; //Client address
	struct sockaddr_un serveraddr; //Server sockaddr
	struct blob_buf b = {NULL, NULL, 0, NULL};
	blob_buf_init(&b, 0);

	if (!blobmsg_add_json_from_string(&b, buffer)) {
		fprintf(stderr, "Failed to parse input data: %s\n", buffer);
		return 1;
	}


	serveraddr.sun_family = AF_UNIX;
	strcpy(serveraddr.sun_path, ipcpath);
	for (ssize_t len = blob_len(b.head); true; sleep(1)) {
		snprintf(sockaddr, 107, ipcpath_client, random() % 1000);
		unlink(sockaddr);
		int sock = usock(USOCK_UNIX | USOCK_SERVER | USOCK_UDP, sockaddr, NULL);
		if (sock < 0) {
			perror("Failed to open socket");
			continue;
		}

		if (sendto(sock, blob_data(b.head), len, 0, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) == len) {
			char buff[1024 * 128]; //It's big, but datagrams can't be received in pieces.
			struct timeval tv = {.tv_sec = 2, .tv_usec = 0};
			if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval)))
				perror("Failed to set socket read timeout");

			ssize_t rcvlen;
			while((rcvlen = recv(sock, buff, 1024 * 128 - 1, 0)) > 0) {
				if(buff[rcvlen - 1] == '\0') {
					printf("%s", buff);
					break;
				} else {
					buff[rcvlen] = '\0';
					printf("%s", buff);
				}
			}
			if(rcvlen < 0)
				perror("Receive error");

			close(sock);
			unlink(sockaddr);
			break;
		}
		perror("Failed to talk to hnetd");
		close(sock);
		unlink(sockaddr);
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
	while ((c = getopt(argc, argv, "ecgadp:l:i:m:u")) > 0) {
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

		case 'm':
			blobmsg_add_string(&b, "ip6_plen", optarg);
			break;

		case 'd':
			blobmsg_add_u8(&b, "disable_pa", 1);
			break;

		case 'a':
			blobmsg_add_u8(&b, "adhoc", 1);
			break;

		case 'u':
			blobmsg_add_u8(&b, "ula_default_router", 1);
			break;
		}
	}


	blobmsg_add_string(&b, "command", strstr(argv[0], "ifup") ? "ifup" : "ifdown");
	blobmsg_add_string(&b, "ifname", argv[optind]);

	if (!external)
		blobmsg_add_string(&b, "handle", argv[optind]);

	return ipc_client(blobmsg_format_json(b.head, true));
}

struct prefix zeros_64_prefix = { .prefix = { .s6_addr = {}}, .plen = 64 } ;

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
		if(!tb[OPT_COMMAND])
			continue;

		const char *cmd = blobmsg_get_string(tb[OPT_COMMAND]);
		L_DEBUG("Handling ipc command %s", cmd);
		if (!strcmp(cmd, "hncp_dump")) {
			struct blob_buf *b;
			if(!ipchncp || !(b = hncp_dump(ipchncp))) {
				const char *message = "Error\n";
				sendto(fd->fd, message, strlen(message) + 1, MSG_DONTWAIT, (struct sockaddr *)&sender, sender_len);
			} else {
				char *buff = blobmsg_format_json_indent(b->head, true, 1);
				sendto(fd->fd, buff, strlen(buff), MSG_DONTWAIT, (struct sockaddr *)&sender, sender_len);
				sendto(fd->fd, "\n", 2, MSG_DONTWAIT, (struct sockaddr *)&sender, sender_len);
				free(buff);
				hncp_dump_free(b);
			}
		}


		if (!tb[OPT_IFNAME]) {
			const char *message = "No ifname\n";
			sendto(fd->fd, message, strlen(message) + 1, MSG_DONTWAIT, (struct sockaddr *)&sender, sender_len);
			continue;
		}

		const char *ifname = blobmsg_get_string(tb[OPT_IFNAME]);
		struct iface *c = iface_get(ifname);
		if (!strcmp(cmd, "ifup")) {
			iface_flags flags = 0;

			if (tb[OPT_ACCEPT_CERID] && blobmsg_get_bool(tb[OPT_ACCEPT_CERID]))
				flags |= IFACE_FLAG_ACCEPT_CERID;

			if (tb[OPT_GUEST] && blobmsg_get_bool(tb[OPT_GUEST]))
				flags |= IFACE_FLAG_GUEST;

			if (tb[OPT_ADHOC] && blobmsg_get_bool(tb[OPT_ADHOC]))
				flags |= IFACE_FLAG_ADHOC;

			if (tb[OPT_DISABLE_PA] && blobmsg_get_bool(tb[OPT_DISABLE_PA]))
				flags |= IFACE_FLAG_DISABLE_PA;

			if (tb[OPT_ULA_DEFAULT_ROUTER] && blobmsg_get_bool(tb[OPT_ULA_DEFAULT_ROUTER]))
				flags |= IFACE_FLAG_ULA_DEFAULT;

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

			unsigned link_id, link_mask = 8;
			if (iface && tb[OPT_LINK_ID] && sscanf(
						blobmsg_get_string(tb[OPT_LINK_ID]),
						"%x/%u", &link_id, &link_mask) >= 1)
					iface_set_link_id(iface, link_id, link_mask);

			if (iface && tb[OPT_IFACE_ID]) {
				struct blob_attr *k;
				unsigned rem;

				blobmsg_for_each_attr(k, tb[OPT_IFACE_ID], rem) {
					if (blobmsg_type(k) == BLOBMSG_TYPE_STRING) {
						char astr[55], fstr[55];
						struct prefix filter, addr;
						int res = sscanf(blobmsg_get_string(k), "%54s %54s", astr, fstr);
						if(res <= 0 || !prefix_pton(astr, &addr) || (res > 1 && !prefix_pton(fstr, &filter))) {
							L_ERR("Incorrect iface_id syntax %s", blobmsg_get_string(k));
							continue;
						}
						if(addr.plen == 128 && prefix_contains(&zeros_64_prefix, &addr))
							addr.plen = 64;
						if(res == 1)
							filter.plen = 0;
						iface_add_addrconf(iface, &addr.prefix, 128 - addr.plen, &filter);
					}
				}
			}

			unsigned minv6len;
			if(iface && tb[OPT_IP6_PLEN]
			               && sscanf(blobmsg_get_string(tb[OPT_IP6_PLEN]), "%u", &minv6len) == 1
			               && minv6len <= 128) {
				iface->ip6_plen = minv6len;
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


			if (tb[OPT_PASSTHRU]) {
				size_t buflen = blobmsg_data_len(tb[OPT_PASSTHRU]) / 2;
				uint8_t *buf = malloc(buflen);
				if (buf) {
					unhexlify(buf, buflen, blobmsg_get_string(tb[OPT_PASSTHRU]));
					iface_add_dhcpv6_received(c, buf, buflen);
					free(buf);
				}
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

		//Send an empty response
		sendto(fd->fd, "", 1, MSG_DONTWAIT, (struct sockaddr *)&sender, sender_len);
	}
}
