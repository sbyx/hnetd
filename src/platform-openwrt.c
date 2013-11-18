#include <libubus.h>
#include <syslog.h>
#include <errno.h>

#include <libubox/blobmsg.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <sys/un.h>
#include <sys/socket.h>

#include "platform.h"
#include "iface.h"

static struct ubus_context *ubus = NULL;
static uint32_t ubus_network_interface = 0;
static struct blob_buf b;


int platform_init(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		syslog(LOG_ERR, "Failed to connect to ubus: %s", strerror(errno));
		return -1;
	}

	// TODO: register network event handlers for interface events to scoop PDs + watch nested interfaces
	// TODO: do dump call to get initial PDs from interfaces that are already online

	ubus_lookup_id(ubus, "network.interface", &ubus_network_interface);
	ubus_add_uloop(ubus);

	return 0;
}



enum ipc_option {
	OPT_COMMAND,
	OPT_INTERFACE,
	OPT_DEVICE,
	OPT_MAX
};

struct blobmsg_policy ipc_policy[] = {
	[OPT_COMMAND] = {"command", BLOBMSG_TYPE_INT32},
	[OPT_INTERFACE] = {"interface", BLOBMSG_TYPE_STRING},
	[OPT_DEVICE] = {"device", BLOBMSG_TYPE_STRING},
};

enum ipc_command {
	CMD_IFUP,
	CMD_IFDOWN,
	CMD_MAX
};


void platform_apply_domain(__unused struct iface *iface)
{
	// Dummy, see platform_commit
}

void platform_apply_zone(__unused struct iface *iface)
{
	// Dummy, see platform_commit
}

void platform_apply_route(__unused struct iface_route *route, __unused bool enable)
{
	// Dummy, see platform_commit
}

void platform_apply_address(__unused struct iface_addr *addr, __unused bool enable)
{
	// Dummy, see platform_commit
}


// Handle internal IPC message
void platform_handle(struct uloop_fd *fd, __unused unsigned int events)
{
	uint8_t buf[4096];
	ssize_t len;
	struct sockaddr_un sender;
	socklen_t sender_len = sizeof(sender);
	struct blob_attr *tb[OPT_MAX];

	while ((len = recvfrom(fd->fd, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr*)&sender, &sender_len)) >= 0) {
		blobmsg_parse(ipc_policy, OPT_MAX, tb, buf, len);
		if (!tb[OPT_COMMAND] || !tb[OPT_INTERFACE])
			continue;

		const char *name = blobmsg_get_string(tb[OPT_INTERFACE]);

		enum ipc_command cmd = blobmsg_get_u32(tb[OPT_COMMAND]);
		if (cmd == CMD_IFUP && tb[OPT_DEVICE]) {
			iface_create(name, blobmsg_get_string(tb[OPT_DEVICE]));
			// TODO: Create nested interfaces for DHCP/v6 client
		} else if (cmd == CMD_IFDOWN) {
			struct iface *iface = iface_get(name);
			if (iface)
				iface_delete(iface);
		}
	}
}

// Commit platform changes
void platform_commit(struct iface *iface)
{
	blob_buf_init(&b, 0);
	blobmsg_add_u32(&b, "action", 0);
	blobmsg_add_u8(&b, "link-up", 1);
	blobmsg_add_string(&b, "interface", iface->name);

	void *k, *l;
	struct iface_addr *a;
	struct iface_route *r;

	k = blobmsg_open_array(&b, "ipaddr");
	vlist_for_each_element(&iface->addrs, a, node) {
		if (a->v6)
			continue;

		l = blobmsg_open_table(&b, NULL);

		char *buf = blobmsg_alloc_string_buffer(&b, "ipaddr", INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &a->addr, buf, INET_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "mask", 4);
		snprintf(buf, 4, "%u", a->addr.prefix);
		blobmsg_add_string_buffer(&b);

		blobmsg_close_table(&b, l);
	}
	blobmsg_close_array(&b, k);

	k = blobmsg_open_array(&b, "ip6addr");
	vlist_for_each_element(&iface->addrs, a, node) {
		if (!a->v6)
			continue;

		l = blobmsg_open_table(&b, NULL);

		char *buf = blobmsg_alloc_string_buffer(&b, "ipaddr", INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &a->addr, buf, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "mask", 4);
		snprintf(buf, 4, "%u", a->addr.prefix);
		blobmsg_add_string_buffer(&b);

		if (a->valid_until) {
			blobmsg_add_u32(&b, "preferred", a->preferred_until);
			blobmsg_add_u32(&b, "valid", a->valid_until);
		}

		blobmsg_close_table(&b, l);
	}
	blobmsg_close_array(&b, k);

	k = blobmsg_open_array(&b, "routes");
	vlist_for_each_element(&iface->routes, r, node) {
		if (r->v6)
			continue;

		l = blobmsg_open_table(&b, NULL);

		char *buf = blobmsg_alloc_string_buffer(&b, "target", INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &r->target, buf, INET_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "netmask", 4);
		snprintf(buf, 4, "%u", r->target.prefix);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "gw", INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &r->nexthop, buf, INET_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		if (r->source.prefix) {
			buf = blobmsg_alloc_string_buffer(&b, "source", INET_ADDRSTRLEN + 4);
			inet_ntop(AF_INET, &r->target, buf, INET_ADDRSTRLEN);
			snprintf(buf + strlen(buf), 4, "/%u", r->target.prefix);
			blobmsg_add_string_buffer(&b);
		}

		if (r->metric)
			blobmsg_add_u32(&b, "metric", r->metric);

		if (r->valid_until)
			blobmsg_add_u32(&b, "valid", r->valid_until);

		blobmsg_close_table(&b, l);
	}
	blobmsg_close_array(&b, k);

	k = blobmsg_open_array(&b, "routes6");
	vlist_for_each_element(&iface->routes, r, node) {
		if (!r->v6)
			continue;

		l = blobmsg_open_table(&b, NULL);

		char *buf = blobmsg_alloc_string_buffer(&b, "target", INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &r->target, buf, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "netmask", 4);
		snprintf(buf, 4, "%u", r->target.prefix);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "gw", INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &r->nexthop, buf, INET6_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		if (r->source.prefix) {
			buf = blobmsg_alloc_string_buffer(&b, "source", INET6_ADDRSTRLEN + 4);
			inet_ntop(AF_INET6, &r->target, buf, INET6_ADDRSTRLEN);
			snprintf(buf + strlen(buf), 4, "/%u", r->target.prefix);
			blobmsg_add_string_buffer(&b);
		}

		if (r->metric)
			blobmsg_add_u32(&b, "metric", r->metric);

		if (r->valid_until)
			blobmsg_add_u32(&b, "valid", r->valid_until);

		blobmsg_close_table(&b, l);
	}
	blobmsg_close_array(&b, k);

	k = blobmsg_open_table(&b, "data");

	if (iface->domain) {
		l = blobmsg_open_array(&b, "domain");
		blobmsg_add_string(&b, NULL, iface->domain);
		blobmsg_close_array(&b, l);
	}

	const char *service = (iface->internal) ? "server" : "disabled";
	blobmsg_add_string(&b, "ra", service);
	blobmsg_add_string(&b, "dhcpv4", service);
	blobmsg_add_string(&b, "dhcpv6", service);

	const char *zone = (iface->internal) ? "lan" : "wan";
	blobmsg_add_string(&b, "zone", zone);

	blobmsg_close_table(&b, k);

	// TODO: test return code
	ubus_invoke(ubus, ubus_network_interface, "proto_update", b.head, NULL, NULL, 1000);
}
