#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "iface.h"
#include "platform.h"

struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static void iface_free(struct iface *iface);


// Compare if two addresses are identical
static int compare_addrs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct iface_addr *a1 = a, *a2 = b;
	return memcmp(&a1->v6, &a2->v6, sizeof(*a1) - offsetof(struct iface_addr, v6));
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_addr(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);

	platform_apply_address((node_new) ? a_new : a_old, !!node_new);

	if (node_old)
		free(a_old);
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_prefix(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	//struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);

	// TODO: notify PA

	if (node_old) {
		// Delete unmanaged interfaces with no other prefixes
		if (!node_new) {
			struct iface *iface = a_old->iface;
			if (!iface->managed && avl_is_empty(&iface->prefixes.avl))
				iface_free(iface);
		}
		free(a_old);
	}
}


struct iface* iface_get(const char *name)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->name, name))
			return c;
	return NULL;
}


struct iface* iface_create(const char *name, const char *ifname, bool managed)
{
	iface_delete(name);

	struct iface *c = NULL;
	int ifindex = if_nametoindex(ifname);
	if (ifindex > 0) {
		c = calloc(1, sizeof(*c));
		c->name = strdup(name);
		c->ifname = strdup(ifname);
		c->ifindex = ifindex;
		c->managed = managed;

		vlist_init(&c->addrs, compare_addrs, update_addr);
		vlist_init(&c->prefixes, compare_addrs, update_prefix);
		list_add(&c->head, &interfaces);
	}
	return c;
}


static void iface_free(struct iface *iface)
{
	list_del(&iface->head);
	vlist_flush_all(&iface->addrs);
	vlist_flush_all(&iface->prefixes);
	free(iface->domain);
	free(iface->ifname);
	free(iface->name);
	free(iface);
}


void iface_delete(const char *name)
{
	struct iface *iface = iface_get(name);
	if (iface)
		iface_free(iface);
}


static void iface_add_addr(struct vlist_tree *tree, struct iface *iface,
		bool v6, const union iface_ia *addr, uint8_t prefix,
		time_t valid_until, time_t preferred_until)
{
	struct iface_addr *a = calloc(1, sizeof(*a));
	a->iface = iface;
	a->v6 = v6;
	a->prefix = prefix;
	a->addr = *addr;
	a->valid_until = valid_until;
	a->preferred_until = preferred_until;

	vlist_add(tree, &a->node, &a->v6);
}


void iface_set_addr(struct iface *iface, bool v6, const union iface_ia *addr,
		uint8_t prefix, time_t valid_until, time_t preferred_until)
{
	iface_add_addr(&iface->addrs, iface, v6, addr, prefix, valid_until, preferred_until);
}


void iface_set_prefix(struct iface *iface, bool v6, const union iface_ia *addr,
		uint8_t prefix, time_t valid_until, time_t preferred_until)
{
	iface_add_addr(&iface->prefixes, iface, v6, addr, prefix, valid_until, preferred_until);
}


void iface_set_domain(struct iface *iface, const char *domain)
{
	if (!iface->domain != !domain ||
			(iface->domain && strcmp(iface->domain, domain))) {
		free(iface->domain);
		iface->domain = (domain) ? strdup(domain) : NULL;
		if (iface->managed)
			platform_apply_domain(iface);
	}
}


void iface_set_internal(struct iface *iface, bool internal)
{
	if (iface->internal != internal) {
		iface->internal = internal;
		if (iface->managed)
			platform_apply_zone(iface);
	}
}


void iface_commit(struct iface *iface)
{
	vlist_flush(&iface->addrs);
	vlist_flush(&iface->prefixes);
	if (iface->managed)
		platform_commit(iface);
}
