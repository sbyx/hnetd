#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>
#include <ifaddrs.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "iface.h"
#include "platform.h"
#include "pa.h"

static void iface_update_prefix(const struct prefix *p, const char *ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len,
		__unused void *priv);
static void iface_update_link_owner(const char *ifname, bool owner, void *priv);

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static struct list_head users = LIST_HEAD_INIT(users);
static struct pa_iface_callbacks pa_cb = {
	.update_prefix = iface_update_prefix,
	.update_link_owner = iface_update_link_owner
};


static void iface_update_prefix(const struct prefix *p, const char *ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len,
		__unused void *priv)
{
	struct iface *c = iface_get(ifname);
	assert(c != NULL && c->platform != NULL);

	if (valid_until < hnetd_time()) { // Delete action
		struct iface_addr *a = vlist_find(&c->assigned, p, a, node);
		if (a)
			vlist_delete(&c->assigned, &a->node);
	} else { // Create / update action
		struct iface_addr *a = calloc(1, sizeof(*a) + dhcpv6_len);
		a->prefix = *p;
		if (!IN6_IS_ADDR_V4MAPPED(&a->prefix.prefix))
			memcpy(&a->prefix.prefix.s6_addr[8], &c->eui64_addr.s6_addr[8], 8);
		a->valid_until = valid_until;
		a->preferred_until = preferred_until;
		a->dhcpv6_len = dhcpv6_len;
		memcpy(a->dhcpv6_data, dhcpv6_data, dhcpv6_len);
		vlist_add(&c->assigned, &a->node, &a->prefix);
	}
}


static void iface_update_link_owner(const char *ifname, bool owner, __unused void *priv)
{
	struct iface *c = iface_get(ifname);
	assert(c != NULL && c->platform != NULL);

	if (owner != c->linkowner) {
		c->linkowner = owner;
		platform_set_owner(c, owner);
	}
}


static void iface_notify_internal_state(struct iface *c, bool enabled)
{
	struct iface_user *u;
	list_for_each_entry(u, &users, head)
		if (u->cb_intiface)
			u->cb_intiface(u, c->ifname, enabled);
}


static void iface_notify_data_state(struct iface *c, bool enabled)
{
	void *data = (enabled) ? c->dhcpv6_data_in : NULL;
	size_t len = (enabled) ? c->dhcpv6_len_in : 0;
	void *data4 = (enabled) ? c->dhcp_data_in : NULL;
	size_t len4 = (enabled) ? c->dhcp_len_in : 0;

	struct iface_user *u;
	list_for_each_entry(u, &users, head) {
		if (u->cb_extdata)
			u->cb_extdata(u, c->ifname, data, len);
		if (u->ipv4_update)
			u->ipv4_update(u, c->ifname, data4, len4);
	}


}


int iface_init(pa_t pa)
{
	pa_iface_subscribe(pa, &pa_cb);
	return platform_init();
}


void iface_register_user(struct iface_user *user)
{
	list_add(&user->head, &users);
}


void iface_unregister_user(struct iface_user *user)
{
	list_del(&user->head);
}


void iface_set_dhcpv6_send(const char *ifname, const void *dhcpv6_data, size_t dhcpv6_len, const void *dhcp_data, size_t dhcp_len)
{
	struct iface *c = iface_get(ifname);
	if (c && (c->dhcpv6_len_out != dhcpv6_len || c->dhcp_len_out ||
			memcmp(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len) ||
			memcmp(c->dhcp_data_out, dhcp_data, dhcp_len))) {

		c->dhcpv6_data_out = realloc(c->dhcpv6_data_out, dhcpv6_len);
		memcpy(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len);
		c->dhcpv6_len_out = dhcpv6_len;

		c->dhcp_data_out = realloc(c->dhcp_data_out, dhcp_len);
		memcpy(c->dhcp_data_out, dhcp_data, dhcp_len);
		c->dhcp_len_out = dhcp_len;

		platform_set_dhcpv6_send(c, c->dhcpv6_data_out, c->dhcpv6_len_out, c->dhcp_data_out, c->dhcp_len_out);
	}
}

// Begin route update cycle
void iface_update_routes(void)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		vlist_update(&c->routes);
}

// Add new routes
void iface_add_default_route(const char *ifname, const struct prefix *from, const struct in6_addr *via, unsigned hopcount)
{
	struct iface *c = iface_get(ifname);
	if (c) {
		struct iface_route *r = calloc(1, sizeof(*r));
		if (!IN6_IS_ADDR_V4MAPPED(via)) {
			r->from = *from;
		} else {
			r->to.plen = 96;
			r->to.prefix.s6_addr[10] = 0xff;
			r->to.prefix.s6_addr[11] = 0xff;
		}

		r->via = *via;
		r->metric = hopcount + 10000;
		vlist_add(&c->routes, &r->node, r);

		if (!IN6_IS_ADDR_V4MAPPED(via)) {
			r = calloc(1, sizeof(*r));
			r->from.plen = 128;
			r->via = *via;
			r->metric = hopcount + 10000;
			vlist_add(&c->routes, &r->node, r);
		}
	}
}

// Add new routes
void iface_add_internal_route(const char *ifname, const struct prefix *to, const struct in6_addr *via, unsigned hopcount)
{
	struct iface *c = iface_get(ifname);
	if (c) {
		struct iface_route *r = calloc(1, sizeof(*r));
		r->to = *to;
		r->via = *via;
		r->metric = hopcount + 10000;
		vlist_add(&c->routes, &r->node, r);
	}
}

// Flush and commit routes to synthesize events
void iface_commit_routes(void)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		vlist_flush(&c->routes);
}


// Compare if two addresses are identical
static int compare_routes(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct iface_route *r1 = a, *r2 = b;
	int c = prefix_cmp(&r1->from, &r2->from);

	if (!c)
		c = prefix_cmp(&r1->to, &r2->to);

	if (!c)
		c = memcmp(&r1->via, &r2->via, sizeof(r1->via));

	if (!c)
		c = r2->metric - r1->metric;

	return c;
}


// Update route if necessary (node_new: route that will be present, node_old: route that was present)
static void update_route(struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_route *r_new = container_of(node_new, struct iface_route, node);
	struct iface_route *r_old = container_of(node_old, struct iface_route, node);
	struct iface_route *r = (node_new) ? r_new : r_old;
	struct iface *c = container_of(t, struct iface, routes);

	if (!node_new || !node_old)
		platform_set_route(c, r, !!node_new);

	__unused char buf[PREFIX_MAXBUFFLEN];
	__unused char buf2[INET6_ADDRSTRLEN];
	L_INFO("iface: %s route %s via %s%%%s",
			(node_new) ? (node_old) ? "updated" : "added" : "removed",
			prefix_ntop(buf, sizeof(buf), &r->to, false),
			inet_ntop(AF_INET6, &r->via, buf2, sizeof(buf2)),
			c->ifname);

	if (node_old)
		free(r_old);
}


// Compare if two addresses are identical
static int compare_addrs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct prefix *a1 = a, *a2 = b;
	return prefix_cmp(a1, a2);
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_addr(struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);

	struct iface *c = container_of(t, struct iface, assigned);
	bool enable = !!node_new;

	if (!enable && !IN6_IS_ADDR_V4MAPPED(&a_old->prefix.prefix)) {
		// Don't actually remove addresses, but deprecate them so the change is announced
		enable = true;
		a_old->preferred_until = 0;

		hnetd_time_t bound = hnetd_time() + (7200 * HNETD_TIME_PER_SECOND);
		if (a_old->valid_until > bound)
			a_old->valid_until = bound;

		// Reinsert deprecated if not flushing all
		if (t->version != -1) {
			vlist_add(t, &a_old->node, &a_old->prefix);
			node_old = NULL;
		}
	}

	platform_set_address(c, (node_new) ? a_new : a_old, enable);

	__unused char buf[PREFIX_MAXBUFFLEN];
	L_INFO("iface: %s assigned prefix %s to %s",
			(node_new) ? (node_old) ? "updated" : "added" : "removed",
			prefix_ntop(buf, sizeof(buf), (node_new) ? &a_new->prefix : &a_old->prefix, false),
			c->ifname);

	if (node_old)
		free(a_old);

	uloop_timeout_set(&c->preferred, 100);
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_prefix(struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);
	struct iface_addr *a = (node_new) ? a_new : a_old;

	struct iface *c = container_of(t, struct iface, delegated);

	if (node_old && !node_new)
		a_old->valid_until = -1;

	struct iface_user *u;
	list_for_each_entry(u, &users, head)
		if (u->cb_prefix)
			u->cb_prefix(u, c->ifname, &a->prefix,
					(a->excluded.plen) ? &a->excluded : NULL,
					a->valid_until, a->preferred_until,
					a->dhcpv6_data, a->dhcpv6_len);

	__unused char buf[PREFIX_MAXBUFFLEN];
	L_INFO("iface: %s delegated prefix %s to %s",
			(node_new) ? (node_old) ? "updated" : "added" : "removed",
			prefix_ntop(buf, sizeof(buf), &a->prefix, false), c->ifname);

	if (node_old)
		free(a_old);
}


struct iface* iface_get(const char *ifname)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->ifname, ifname))
			return c;

	return NULL;
}


void iface_remove(struct iface *c)
{
	if (!c)
		return;

	// If interface was internal, let subscribers know of removal
	if (c->internal)
		iface_notify_internal_state(c, false);
	else
		iface_notify_data_state(c, false);

	list_del(&c->head);
	vlist_flush_all(&c->assigned);
	vlist_flush_all(&c->delegated);
	vlist_flush_all(&c->routes);

	if (c->platform)
		platform_iface_free(c);

	free(c->dhcpv6_data_in);
	free(c->dhcpv6_data_out);
	free(c->dhcp_data_in);
	free(c->dhcp_data_out);

	uloop_timeout_cancel(&c->transition);
	uloop_timeout_cancel(&c->preferred);

	if (c->internal)
		c->preferred.cb(&c->preferred);

	free(c);
}


void iface_update_init(struct iface *c)
{
	vlist_update(&c->assigned);
	vlist_update(&c->delegated);
}


static void iface_announce_border(struct uloop_timeout *t)
{
	struct iface *c = container_of(t, struct iface, transition);
	iface_notify_data_state(c, c->internal);
	iface_notify_internal_state(c, c->internal);
	platform_set_internal(c, c->internal);

	if (!c->internal)
		uloop_timeout_set(&c->preferred, 100);
}


static void iface_announce_preferred(struct uloop_timeout *t)
{
	struct iface *c = container_of(t, struct iface, preferred);
	hnetd_time_t now = hnetd_time();

	struct iface_addr *a, *pref6 = NULL, *pref4 = NULL;
	vlist_for_each_element(&c->assigned, a, node) {
		if (!IN6_IS_ADDR_V4MAPPED(&a->prefix.prefix)) {
			if (a->preferred_until > now &&
					(!pref6 || a->preferred_until > pref6->preferred_until))
				pref6 = a;
		} else if (!pref4) {
			pref4 = a;
		}
	}

	struct iface_user *u;
	list_for_each_entry(u, &users, head)
		if (u->cb_intaddr)
			u->cb_intaddr(u, c->ifname, &pref6->prefix, &pref4->prefix);
}


static void iface_discover_border(struct iface *c)
{
	if (!c->platform) // No border discovery on unmanaged interfaces
		return;

	// Perform border-discovery (border on DHCPv4 assignment or DHCPv6-PD)
	bool internal = avl_is_empty(&c->delegated.avl) &&
			!c->v4leased && !c->dhcpv6_len_in;
	if (c->internal != internal) {
		L_INFO("iface: %s border discovery detected state %s",
				c->ifname, (internal) ? "internal" : "external");

		c->internal = internal;

		if (c->transition.pending)
			uloop_timeout_cancel(&c->transition); // Flapped back to original state
		else if (internal)
			uloop_timeout_set(&c->transition, 5000);
		else
			iface_announce_border(&c->transition);
	}
}


struct iface* iface_create(const char *ifname, const char *handle)
{
	struct iface *c = iface_get(ifname);
	if (!c) {
		size_t namelen = strlen(ifname) + 1;
		c = calloc(1, sizeof(*c) + namelen);
		memcpy(c->ifname, ifname, namelen);

		// Get EUI-64 address
		struct ifaddrs *ifaddr, *ifa;
		if (!getifaddrs(&ifaddr)) {
			for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
				struct sockaddr_in6 *sa = (struct sockaddr_in6*)ifa->ifa_addr;
				if (ifa->ifa_name && !strcmp(ifa->ifa_name, ifname) &&
						sa && sa->sin6_family == AF_INET6 &&
						IN6_IS_ADDR_LINKLOCAL(&sa->sin6_addr))
					c->eui64_addr = sa->sin6_addr;
			}
			freeifaddrs(ifaddr);
		}

		// Fallback to random EUI-64 address
		if (IN6_IS_ADDR_UNSPECIFIED(&c->eui64_addr))
			for (size_t i = 8; i < 16; ++i)
				c->eui64_addr.s6_addr[i] = random();

		vlist_init(&c->assigned, compare_addrs, update_addr);
		vlist_init(&c->delegated, compare_addrs, update_prefix);
		vlist_init(&c->routes, compare_routes, update_route);
		c->transition.cb = iface_announce_border;
		c->preferred.cb = iface_announce_preferred;

		list_add(&c->head, &interfaces);
	}

	if (!c->platform && handle) {
		platform_iface_new(c, handle);
		iface_announce_border(&c->transition);
		iface_discover_border(c);
	}

	return c;
}


void iface_flush(void)
{
	while (!list_empty(&interfaces))
		iface_remove(list_first_entry(&interfaces, struct iface, head));
}


void iface_set_dhcp_received(struct iface *c, bool leased, ...)
{
	if (c->v4leased != leased) {
		c->v4leased = leased;
		iface_discover_border(c);
	}

	bool equal = true;
	size_t offset = 0;
	va_list ap;

	va_start(ap, leased);
	for (;;) {
		void *data = va_arg(ap, void*);
		if (!data)
			break;

		size_t len = va_arg(ap, size_t);
		if (!equal || offset + len > c->dhcp_len_in ||
				memcmp(((uint8_t*)c->dhcp_data_in) + offset, data, len))
			equal = false;

		offset += len;
	}
	va_end(ap);

	if (equal && offset != c->dhcp_len_in)
		equal = false;

	if (!equal) {
		c->dhcp_data_in = realloc(c->dhcp_data_in, offset);
		c->dhcp_len_in = offset;

		offset = 0;

		va_start(ap, leased);
		for (;;) {
			void *data = va_arg(ap, void*);
			if (!data)
				break;

			size_t len = va_arg(ap, size_t);
			memcpy(((uint8_t*)c->dhcp_data_in) + offset, data, len);

			offset += len;
		}
		va_end(ap);

		if (!c->internal)
			iface_notify_data_state(c, true);
	}
}


void iface_update_delegated(struct iface *c)
{
	vlist_update(&c->delegated);
}


void iface_add_delegated(struct iface *c,
		const struct prefix *p, const struct prefix *excluded,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcpv6_data, size_t dhcpv6_len)
{
	struct iface_addr *a = calloc(1, sizeof(*a) + dhcpv6_len);
	a->prefix = *p;
	if (excluded)
		a->excluded = *excluded;
	a->valid_until = valid_until;
	a->preferred_until = preferred_until;
	a->dhcpv6_len = dhcpv6_len;
	memcpy(a->dhcpv6_data, dhcpv6_data, dhcpv6_len);
	vlist_add(&c->delegated, &a->node, &a->prefix);
}


void iface_commit_delegated(struct iface *c)
{
	vlist_flush(&c->delegated);
	iface_discover_border(c);
}


void iface_set_dhcpv6_received(struct iface *c, ...)
{
	bool equal = true;
	size_t offset = 0;
	va_list ap;

	va_start(ap, c);
	for (;;) {
		void *data = va_arg(ap, void*);
		if (!data)
			break;

		size_t len = va_arg(ap, size_t);
		if (!equal || offset + len > c->dhcpv6_len_in ||
				memcmp(((uint8_t*)c->dhcpv6_data_in) + offset, data, len))
			equal = false;

		offset += len;
	}
	va_end(ap);

	if (equal && offset != c->dhcp_len_in)
		equal = false;

	if (!equal) {
		c->dhcpv6_data_in = realloc(c->dhcpv6_data_in, offset);
		c->dhcpv6_len_in = offset;

		offset = 0;

		va_start(ap, c);
		for (;;) {
			void *data = va_arg(ap, void*);
			if (!data)
				break;

			size_t len = va_arg(ap, size_t);
			memcpy(((uint8_t*)c->dhcpv6_data_in) + offset, data, len);

			offset += len;
		}
		va_end(ap);

		if (!c->internal)
			iface_notify_data_state(c, true);
	}
}
