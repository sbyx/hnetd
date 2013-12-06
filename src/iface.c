#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>

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

	struct iface_user *u;
	list_for_each_entry(u, &users, head)
		if (u->cb_extdata)
			u->cb_extdata(u, c->ifname, data, len);
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


void iface_set_dhcpv6_send(const char *ifname, const void *dhcpv6_data, size_t dhcpv6_len)
{
	struct iface *c = iface_get(ifname);
	if (c && (c->dhcpv6_len_out != dhcpv6_len || memcmp(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len))) {
		c->dhcpv6_data_out = realloc(c->dhcpv6_data_out, dhcpv6_len);
		memcpy(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len);
		c->dhcpv6_len_out = dhcpv6_len;
		platform_set_dhcpv6_send(c, c->dhcpv6_data_out, c->dhcpv6_len_out);
	}
}


// Compare if two addresses are identical
static int compare_addrs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct iface_addr *a1 = a, *a2 = b;
	return prefix_cmp(&a1->prefix, &a2->prefix);
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_addr(struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);

	struct iface *c = container_of(t, struct iface, assigned);
	platform_set_address(c, (node_new) ? a_new : a_old, !!node_new);

	if (node_old)
		free(a_old);
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
			u->cb_prefix(u, c->ifname, &a->prefix, &a->excluded,
					a->valid_until, a->preferred_until,
					a->dhcpv6_data, a->dhcpv6_len);

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

	if (c->platform)
		platform_iface_free(c);

	free(c->dhcpv6_data_in);
	free(c->dhcpv6_data_out);
	free(c);
}


void iface_update_init(struct iface *c)
{
	vlist_update(&c->assigned);
	vlist_update(&c->delegated);
}


static void iface_discover_border(struct iface *c)
{
	if (!c->platform) // No border discovery on unmanaged interfaces
		return;

	// Perform border-discovery (border on DHCPv4 assignment or DHCPv6-PD)
	bool internal = avl_is_empty(&c->delegated.avl) &&
			!c->v4leased && !c->dhcpv6_len_in;
	if (c->internal != internal) {
		c->internal = internal;
		iface_notify_data_state(c, internal);
		iface_notify_internal_state(c, internal);
		platform_set_internal(c, internal);
	}
}


struct iface* iface_create(const char *ifname, const char *handle)
{
	struct iface *c = iface_get(ifname);
	if (!c) {
		size_t namelen = strlen(ifname) + 1;
		c = calloc(1, sizeof(*c) + namelen);
		memcpy(c->ifname, ifname, namelen);

		vlist_init(&c->assigned, compare_addrs, update_addr);
		vlist_init(&c->delegated, compare_addrs, update_prefix);

		list_add(&c->head, &interfaces);
	}

	if (!c->platform && handle) {
		platform_iface_new(c, handle);
		iface_discover_border(c);
	}

	return c;
}


void iface_set_v4leased(struct iface *c, bool v4leased)
{
	if (c->v4leased != v4leased) {
		c->v4leased = v4leased;
		iface_discover_border(c);
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


void iface_set_dhcpv6_received(struct iface *c, const void *dhcpv6_data, size_t dhcpv6_len)
{
	if (c->dhcpv6_len_in != dhcpv6_len || memcmp(c->dhcpv6_data_in, dhcpv6_data, dhcpv6_len)) {
		c->dhcpv6_data_in = realloc(c->dhcpv6_data_in, dhcpv6_len);
		memcpy(c->dhcpv6_data_in, dhcpv6_data, dhcpv6_len);
		c->dhcpv6_len_in = dhcpv6_len;

		if (!c->internal)
			iface_notify_data_state(c, true);
	}
}
