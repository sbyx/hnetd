#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "iface.h"
#include "platform.h"

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static struct list_head users = LIST_HEAD_INIT(users);


int iface_init(void)
{
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


struct iface* iface_get(const char *ifname, const char *handle)
{
	struct iface *c = NULL, *k;
	list_for_each_entry(k, &interfaces, head) {
		if (!strcmp(k->ifname, ifname)) {
			c = k;
			break;
		}
	}

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


void iface_update_commit(struct iface *c)
{
	vlist_flush(&c->assigned);
	vlist_flush(&c->delegated);

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
