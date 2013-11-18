#include <string.h>
#include <stdlib.h>
#include <net/if.h>

#include "iface.h"
#include "platform.h"

struct list_head interfaces = LIST_HEAD_INIT(interfaces);


struct iface* iface_get(const char *name)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		if (!strcmp(c->name, name))
			return c;
	return NULL;
}


// Compare if two routes are identical
static int compare_routes(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct iface_route *r1 = a, *r2 = b;
	return memcmp(&r1->v6, &r2->v6, sizeof(*r1) - offsetof(struct iface_route, v6));
}

// Compare if two addresses are identical
static int compare_addrs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct iface_addr *a1 = a, *a2 = b;
	return memcmp(&a1->v6, &a2->v6, sizeof(*a1) - offsetof(struct iface_addr, v6));
}

// Update route if necessary (node_new: route that will be present, node_old: route that was present)
static void update_route(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_route *r_new = container_of(node_new, struct iface_route, node);
	struct iface_route *r_old = container_of(node_old, struct iface_route, node);

	platform_apply_route((node_new) ? r_new : r_old, !!node_new);

	if (node_old)
		free(r_old);
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


struct iface* iface_create(const char *name, const char *ifname)
{
	struct iface *c = iface_get(name);
	if (c) {
		iface_delete(c);
		c = NULL;
	}

	int ifindex = if_nametoindex(ifname);
	if (!c && ifindex > 0) {
		c = calloc(1, sizeof(*c));
		c->name = strdup(name);
		c->ifname = strdup(ifname);
		c->ifindex = ifindex;

		vlist_init(&c->addrs, compare_addrs, update_addr);
		vlist_init(&c->routes, compare_routes, update_route);
	}

	return c;
}


void iface_delete(struct iface *iface)
{
	list_del(&iface->head);
	vlist_flush_all(&iface->addrs);
	vlist_flush_all(&iface->routes);
	free(iface->domain);
	free(iface->ifname);
	free(iface->name);
	free(iface);
}


void iface_set_route(struct iface *iface, bool v6, const struct iface_ia *target,
		const struct iface_ia *nexthop, const struct iface_ia *source,
		uint32_t metric, time_t valid_until)
{
	struct iface_route *r = calloc(1, sizeof(*r));
	r->iface = iface;
	r->v6 = v6;
	r->target = *target;
	r->nexthop = *nexthop;
	r->metric = metric;
	r->valid_until = valid_until;

	if (source)
		r->source = *source;

	vlist_add(&iface->routes, &r->node, &r->v6);
}


void iface_set_addr(struct iface *iface, bool v6, const struct iface_ia *addr,
		time_t valid_until, time_t preferred_until)
{
	struct iface_addr *a = calloc(1, sizeof(*a));
	a->iface = iface;
	a->v6 = v6;
	a->addr = *addr;
	a->valid_until = valid_until;
	a->preferred_until = preferred_until;

	vlist_add(&iface->addrs, &a->node, &a->v6);
}


void iface_set_domain(struct iface *iface, const char *domain)
{
	if (!iface->domain != !domain ||
			(iface->domain && strcmp(iface->domain, domain))) {
		free(iface->domain);
		iface->domain = (domain) ? strdup(domain) : NULL;
		platform_apply_domain(iface);
	}
}


void iface_set_internal(struct iface *iface, bool internal)
{
	if (iface->internal != internal) {
		iface->internal = internal;
		platform_apply_zone(iface);
	}
}


void iface_commit(struct iface *iface)
{
	vlist_flush(&iface->routes);
	vlist_flush(&iface->addrs);
	platform_commit(iface);
}
