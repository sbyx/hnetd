#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>

#include "iface.h"
#include "platform.h"
#include "pa.h"

static struct iface* iface_find(const char *ifname);
static void iface_update_prefix(const struct prefix *p, const char *ifname,
		time_t valid_until, time_t preferred_until, void *priv);
static void iface_update_link_owner(const char *ifname, bool owner, void *priv);

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static struct list_head users = LIST_HEAD_INIT(users);
static struct pa_iface_callbacks pa_cb = {
	.update_prefix = iface_update_prefix,
	.update_link_owner = iface_update_link_owner
};


static void iface_update_prefix(const struct prefix *p, const char *ifname,
		time_t valid_until, time_t preferred_until, __unused void *priv)
{
	struct iface *c = iface_find(ifname);
	assert(c != NULL && c->platform != NULL);

	if (valid_until && valid_until < hnetd_time()) { // Delete action
		struct iface_addr *a = vlist_find(&c->assigned, p, a, node);
		if (a)
			vlist_delete(&c->assigned, &a->node);
	} else { // Create / update action
		struct iface_addr *a = calloc(1, sizeof(*a));
		a->prefix = *p;
		a->valid_until = valid_until;
		a->preferred_until = preferred_until;
		vlist_add(&c->assigned, &a->node, &a->prefix);
	}
}


static void iface_update_link_owner(const char *ifname, bool owner, __unused void *priv)
{
	struct iface *c = iface_find(ifname);
	assert(c != NULL && c->platform != NULL);

	if (owner != c->linkowner) {
		c->linkowner = owner;
		platform_set_owner(c, owner);
	}
}


int iface_init(void)
{
	// TODO: pa_iface_subscribe(NULL, &pa_cb);
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
static void update_prefix(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);
	struct iface_addr *a = (node_new) ? a_new : a_old;

	if (node_old && !node_new)
		a_old->valid_until = -1;

	struct iface_user *u;
	list_for_each_entry(u, &users, head)
		if (u->cb_prefix)
			u->cb_prefix(u, &a->prefix, a->valid_until, a->preferred_until);

	if (node_old)
		free(a_old);
}


static struct iface* iface_find(const char *ifname)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->ifname, ifname))
			return c;

	return NULL;
}


struct iface* iface_get(const char *ifname, const char *handle)
{
	struct iface *c = iface_find(ifname);
	if (!c) {
		size_t namelen = strlen(ifname) + 1;
		c = calloc(1, sizeof(*c) + namelen);
		memcpy(c->ifname, ifname, namelen);

		vlist_init(&c->assigned, compare_addrs, update_addr);
		vlist_init(&c->delegated, compare_addrs, update_prefix);

		if (handle)
			platform_iface_new(c, handle);

		list_add(&c->head, &interfaces);
	}

	return c;
}


void iface_remove(const char *ifname)
{
	struct iface *c = iface_get(ifname, NULL);
	if (c) {
		list_del(&c->head);
		vlist_flush_all(&c->assigned);
		vlist_flush_all(&c->delegated);
		if (c->platform)
			platform_iface_free(c);
		free(c->domain);
		free(c);
	}
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
	bool internal = !c->v4leased && avl_is_empty(&c->delegated.avl);
	if (c->internal != internal) {
		c->internal = internal;

		struct iface_user *u;
		list_for_each_entry(u, &users, head)
			if (u->cb_intiface)
				u->cb_intiface(u, c->ifname, internal);

		platform_set_internal(c, internal);
	}
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


void iface_add_delegated(struct iface *c, const struct prefix *p, time_t valid_until, time_t preferred_until)
{
	struct iface_addr *a = calloc(1, sizeof(*a));
	a->prefix = *p;
	a->valid_until = valid_until;
	a->preferred_until = preferred_until;
	vlist_add(&c->delegated, &a->node, &a->prefix);
}


void iface_commit_delegated(struct iface *c)
{
	vlist_flush(&c->delegated);
	iface_discover_border(c);
}
