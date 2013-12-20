#include <stdio.h>
#include <unistd.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/uloop.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>

#include "ipc.h"
#include "iface.h"
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
	OPT_MAX
};

struct blobmsg_policy ipc_policy[] = {
	[OPT_COMMAND] = {"command", BLOBMSG_TYPE_STRING},
	[OPT_IFNAME] = {"ifname", BLOBMSG_TYPE_STRING},
	[OPT_HANDLE] = {"handle", BLOBMSG_TYPE_STRING},
	[OPT_PREFIX] = {"prefix", BLOBMSG_TYPE_ARRAY},
	[OPT_DNS] = {"dns", BLOBMSG_TYPE_ARRAY},
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
		fputs("Failed to parse input data\n", stderr);
		return 1;
	}

	int sock = usock(USOCK_UNIX | USOCK_UDP, ipcpath, NULL);
	if (sock < 0) {
		fputs("Failed to open socket\n", stderr);
		return 2;
	}

	ssize_t len = blob_len(b.head);
	if (send(sock, blob_data(b.head), len, 0) != len) {
		fputs("Send result wrong\n", stderr);
		return 3;
	}
	return 0;
}


// Handle internal IPC message
static void ipc_handle(struct uloop_fd *fd, __unused unsigned int events)
{
	uint8_t buf[4096];
	ssize_t len;
	struct sockaddr_un sender;
	socklen_t sender_len = sizeof(sender);
	struct blob_attr *tb[OPT_MAX], *p;

	while ((len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr*)&sender, &sender_len)) >= 0) {
		blobmsg_parse(ipc_policy, OPT_MAX, tb, buf, len);
		if (!tb[OPT_COMMAND] || !tb[OPT_IFNAME])
			continue;

		const char *ifname = blobmsg_get_string(tb[OPT_IFNAME]);
		struct iface *c = iface_get(ifname);

		const char *cmd = blobmsg_get_string(tb[OPT_COMMAND]);
		L_DEBUG("Handling ipc command %s", cmd);
		if (!strcmp(cmd, "ifup") && tb[OPT_HANDLE]) {
			iface_create(ifname, blobmsg_get_string(tb[OPT_HANDLE]));
		} else if (!strcmp(cmd, "ifdown")) {
			iface_remove(c);
		} else if (!strcmp(cmd, "set_v4lease")) {
			iface_set_v4leased(c, true);
		} else if (!strcmp(cmd, "unset_v4lease")) {
			iface_set_v4leased(c, false);
		} else if (!strcmp(cmd, "set_prefixes") && (p = tb[OPT_PREFIX])) {
			hnetd_time_t now = hnetd_time();
			iface_update_delegated(c);

			struct blob_attr *k;
			unsigned rem;
			blobmsg_for_each_attr(k, p, rem) {
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
					preferred = now + blobmsg_get_u32(tb[PREFIX_PREFERRED]);

				if (tb[PREFIX_VALID])
					valid = now + blobmsg_get_u32(tb[PREFIX_VALID]);

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
			iface_commit_delegated(c);
		} else if (!strcmp(cmd, "set_dhcpv6_data")) {
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
				iface_set_dhcpv6_received(c, &dns, ((uint8_t*)&dns.addr[dns_cnt]) - ((uint8_t*)&dns));
			} else {
				iface_set_dhcpv6_received(c, NULL, 0);
			}
		}
	}
}
