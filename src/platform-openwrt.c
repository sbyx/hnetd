#include <syslog.h>
#include <errno.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/un.h>
#include <sys/socket.h>

#include <libubox/blobmsg.h>
#include <libubus.h>

#include "platform.h"
#include "iface.h"

static struct ubus_context *ubus = NULL;
//static struct ubus_subscriber netifd;
static uint32_t ubus_network_interface = 0;
static struct blob_buf b;


int platform_init(void)
{
	if (!(ubus = ubus_connect(NULL))) {
		syslog(LOG_ERR, "Failed to connect to ubus: %s", strerror(errno));
		return -1;
	}

/*
	netifd.cb = handle_update;
	ubus_register_subscriber(ubus, &netifd);
*/

	// TODO: dump iface data

	ubus_lookup_id(ubus, "network.interface", &ubus_network_interface);
	ubus_add_uloop(ubus);

	return 0;
}


void platform_apply_domain(__unused struct iface *iface)
{
	// Dummy, see platform_commit
}

void platform_apply_zone(__unused struct iface *iface)
{
	// Dummy, see platform_commit
}

void platform_apply_address(__unused struct iface_addr *addr, __unused bool enable)
{
	// Dummy, see platform_commit
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

	k = blobmsg_open_array(&b, "ipaddr");
	vlist_for_each_element(&iface->addrs, a, node) {
		if (a->v6)
			continue;

		l = blobmsg_open_table(&b, NULL);

		char *buf = blobmsg_alloc_string_buffer(&b, "ipaddr", INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &a->addr, buf, INET_ADDRSTRLEN);
		blobmsg_add_string_buffer(&b);

		buf = blobmsg_alloc_string_buffer(&b, "mask", 4);
		snprintf(buf, 4, "%u", a->prefix);
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
		snprintf(buf, 4, "%u", a->prefix);
		blobmsg_add_string_buffer(&b);

		if (a->valid_until) {
			blobmsg_add_u32(&b, "preferred", a->preferred_until);
			blobmsg_add_u32(&b, "valid", a->valid_until);
		}

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


enum {
	IFACE_ATTR_INTERFACE,
	IFACE_ATTR_PREFIX,
	IFACE_ATTR_MAX,
};

static const struct blobmsg_policy iface_attrs[IFACE_ATTR_MAX] = {
	[IFACE_ATTR_INTERFACE] = { .name = "interface", .type = BLOBMSG_TYPE_STRING },
	[IFACE_ATTR_PREFIX] = { .name = "ipv6-prefix", .type = BLOBMSG_TYPE_ARRAY },
};

/*
static int handle_update(__unused struct ubus_context *ctx, __unused struct ubus_object *obj,
		__unused struct ubus_request_data *req, __unused const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[IFACE_ATTR_MAX];
	blobmsg_parse(iface_attrs, IFACE_ATTR_MAX, tb, blob_data(msg), blob_len(msg));

	const char *interface = (tb[IFACE_ATTR_INTERFACE]) ?
			blobmsg_get_string(tb[IFACE_ATTR_INTERFACE]) : "";
	const char *ifname = (tb[IFACE_ATTR_IFNAME]) ?
			blobmsg_get_string(tb[IFACE_ATTR_IFNAME]) : "";

	struct interface *c, *iface = NULL;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(interface, c->name) || !strcmp(ifname, c->ifname))
			iface = c;

	if (iface && iface->ignore)
		return 0;

	ubus_invoke(ubus, objid, "dump", NULL, handle_dump, NULL, 0);
	return 0;
}
*/
