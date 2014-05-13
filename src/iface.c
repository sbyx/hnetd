/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include <assert.h>
#include <ifaddrs.h>
#include <stdarg.h>
#include <limits.h>
#include <arpa/inet.h>

#include <sys/socket.h>
#ifdef __linux__
#include <linux/rtnetlink.h>
#endif /* __linux__ */

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP 1
#endif

#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#include "iface.h"
#include "platform.h"
#include "pa_data.h"

void iface_pa_ifs(struct pa_data_user *, struct pa_iface *, uint32_t flags);
void iface_pa_cps(struct pa_data_user *, struct pa_cp *, uint32_t flags);
void iface_pa_aas(struct pa_data_user *, struct pa_aa *, uint32_t flags);
void iface_pa_dps(struct pa_data_user *, struct pa_dp *, uint32_t flags);

static bool iface_discover_border(struct iface *c);

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static struct list_head users = LIST_HEAD_INIT(users);
static struct pa *pa_p = NULL;
static struct pa_data_user pa_data_cb = {
	.cps = iface_pa_cps,
	.aas = iface_pa_aas,
	.ifs = iface_pa_ifs,
	.dps = iface_pa_dps
};

void iface_pa_dps(__attribute__((unused))struct pa_data_user *user,
		struct pa_dp *dp, uint32_t flags)
{
	if(flags & PADF_DP_CREATED) {
		struct iface *c;
		list_for_each_entry(c, &interfaces, head)
			if (c->flags & IFACE_FLAG_GUEST)
				platform_filter_prefix(c, &dp->prefix, true);

		if(!prefix_is_ipv4(&dp->prefix)) {
			L_DEBUG("Pushing to platform "PA_DP_L, PA_DP_LA(dp));
			platform_set_prefix_route(&dp->prefix, true);
		} else if (!dp->local) {
			struct iface *c;
			list_for_each_entry(c, &interfaces, head) {
				if (c->designatedv4) {
					c->designatedv4 = false;
					platform_restart_dhcpv4(c);
				}
			}
		}
	} else if(flags & PADF_DP_TODELETE) {
		struct iface *c;
		list_for_each_entry(c, &interfaces, head)
			if (c->flags & IFACE_FLAG_GUEST)
				platform_filter_prefix(c, &dp->prefix, false);

		if(!prefix_is_ipv4(&dp->prefix)) {
			L_DEBUG("Removing from platform "PA_DP_L, PA_DP_LA(dp));
			platform_set_prefix_route(&dp->prefix, false);
		} else {
			bool ipv4_edp = false;
			struct pa_dp *dp;
			pa_for_each_dp(dp, &pa_p->data)
				if (!dp->local && IN6_IS_ADDR_V4MAPPED(&dp->prefix.prefix))
					ipv4_edp = true;

			struct iface *c;
			list_for_each_entry(c, &interfaces, head) {
				if (c->designatedv4 != !ipv4_edp) {
					c->designatedv4 = !ipv4_edp;
					platform_restart_dhcpv4(c);
				}
			}
		}
	} else if(flags & (PADF_DP_DHCP | PADF_DP_LIFETIME)) {
		struct pa_cp *cp;
		pa_for_each_cp_in_dp(cp, dp) {
			iface_pa_cps(user, cp, PADF_CP_DP); /* A bit hacky, but should work */
		}
	}
}

void iface_pa_ifs(__attribute__((unused))struct pa_data_user *user,
		struct pa_iface *iface, uint32_t flags)
{
	if(flags & (PADF_IF_DODHCP | PADF_IF_TODELETE)) {
		struct iface *c = iface_get(iface->ifname);
		if(!c)
			return;
		assert(c->platform != NULL);

		bool owner = (flags & PADF_IF_TODELETE)?false:iface->do_dhcp;
		if (owner != c->linkowner) {
			c->linkowner = owner;
			platform_set_owner(c, owner);
		}
	}
}

/* todo: Te new pa algorithm also selects the chosen address. But this address
 * is provided asynchronously with the prefix. As a trick for fast integration,
 * a prefix is installed if and only if the prefix is applied and the address is
 * applied.
 * This could cause unnecessary flaps in prefixes configuration. iface.c should manage that
 * asynchronously as well.
 */

static void iface_pa_prefix_update(struct pa_cpl *cpl)
{
	L_DEBUG("iface_pa_prefix_update: "PA_CP_L, PA_CP_LA(&cpl->cp));
	if(!cpl->iface) {
		L_WARN("Trying to configure a prefix with no interface");
		return;
	}

	if(!cpl->cp.dp) { /* Can happen when a cp is made orphan. But it can't last long, or it will be deleted. */
		L_DEBUG("iface_pa_prefix_update: Ignoring cp with no dp.");
		return;
	}

	struct iface *c = iface_get(cpl->iface->ifname);
	if(!c) {
		L_DEBUG("iface_pa_prefix_update: No iface found (%s).", cpl->iface->ifname);
		return;
	}
	assert(c->platform != NULL);
	struct iface_addr *a = calloc(1, sizeof(*a) + cpl->cp.dp->dhcp_len);
	memcpy(&a->prefix.prefix, &cpl->laa->aa.address, sizeof(struct in6_addr));
	a->prefix.plen = cpl->cp.prefix.plen;
	a->valid_until = cpl->cp.dp->valid_until;
	a->preferred_until = cpl->cp.dp->preferred_until;
	a->dhcpv6_len = cpl->cp.dp->dhcp_len;
	memcpy(a->dhcpv6_data, cpl->cp.dp->dhcp_data, cpl->cp.dp->dhcp_len);
	vlist_add(&c->assigned, &a->node, &a->prefix);
}

static void iface_pa_prefix_delete(struct pa_cpl *cpl)
{
	L_DEBUG("iface_pa_prefix_delete: "PA_CP_L, PA_CP_LA(&cpl->cp));
	if(!cpl->iface) {
		L_WARN("Trying to delete a prefix with no interface");
		return;
	}

	struct iface *c = iface_get(cpl->iface->ifname);
	if(!c) {
		L_DEBUG("iface_pa_prefix_delete: No iface found (%s).", cpl->iface->ifname);
		return;
	}
	assert(c->platform != NULL);
	struct iface_addr *a = vlist_find(&c->assigned, &cpl->cp.prefix, a, node);
	if (a) {
		vlist_delete(&c->assigned, &a->node);
	} else {
		L_DEBUG("iface_pa_prefix_delete: element not found.");
	}
	//todo: why no free of a here ?
}

void iface_pa_cps(__attribute__((unused))struct pa_data_user *user,
		struct pa_cp *cp, uint32_t flags)
{
	/* This function is also called by iface_pa_dps when lifetime or dhcp data is modified.
	 * The flags is then PADF_CP_DP. */
	struct pa_cpl *cpl;
	if(!(cpl = _pa_cpl(cp)))
		return;

	if(!cpl->laa || !cpl->laa->applied) /* This prefix is not known here */
			return;

	bool applied = cp->applied;
	if((flags & PADF_CP_TODELETE) && applied) {
		flags |= PADF_CP_APPLIED;
		applied = false;
	}
	//todo: What to do if iface is set to NULL ? We don't remember the old one...
	//Maybe a cp should never change iface... (which is true for now)
	if(flags & (PADF_CP_APPLIED | PADF_CP_DP)) {
		/* Changed application */
		if(applied) {
			iface_pa_prefix_update(cpl);
		} else {
			iface_pa_prefix_delete(cpl);
		}
	}
}

void iface_pa_aas(__attribute__((unused))struct pa_data_user *user,
		struct pa_aa *aa, uint32_t flags)
{
	if(!aa->local)
		return;

	struct pa_laa *laa = container_of(aa, struct pa_laa, aa);
	if(!laa->cpl || !laa->cpl->cp.applied)
		return;

	bool applied = laa->applied;
	if((flags & PADF_AA_TODELETE) && applied) {
		flags |= PADF_LAA_APPLIED;
		applied = false;
	}

	if(flags & (PADF_LAA_APPLIED)) {
		if(applied) {
			iface_pa_prefix_update(laa->cpl);
		} else {
			iface_pa_prefix_delete(laa->cpl);
		}
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
	void *data = (enabled) ? (c->dhcpv6_data_in ? c->dhcpv6_data_in : (void*)1) : NULL;
	size_t len = (enabled) ? c->dhcpv6_len_in : 0;
	void *data4 = (enabled) ? (c->dhcp_data_in ? c->dhcp_data_in : (void*)1) : NULL;
	size_t len4 = (enabled) ? c->dhcp_len_in : 0;

	struct iface_user *u;
	list_for_each_entry(u, &users, head) {
		if (u->cb_extdata)
			u->cb_extdata(u, c->ifname, data, len);
		if (u->cb_ext4data)
			u->cb_ext4data(u, c->ifname, data4, len4);
	}


}

#ifdef __linux__

static void iface_link_event(struct uloop_fd *fd, __unused unsigned events)
{
	struct {
		struct nlmsghdr hdr;
		struct ifinfomsg msg;
		uint8_t pad[4000];
	} resp;

	ssize_t read;
	do {
		read = recv(fd->fd, &resp, sizeof(resp), MSG_DONTWAIT);
		if (read < 0 || !NLMSG_OK(&resp.hdr, (size_t)read) ||
				(resp.hdr.nlmsg_type != RTM_NEWLINK &&
						resp.hdr.nlmsg_type != RTM_DELLINK))
			continue;

		char namebuf[IF_NAMESIZE];
		if (!if_indextoname(resp.msg.ifi_index, namebuf))
			continue;

		struct iface *c = iface_get(namebuf);
		if (!c)
			continue;

		bool up = resp.hdr.nlmsg_type == RTM_NEWLINK && (resp.msg.ifi_flags & IFF_LOWER_UP);
		if (c->carrier != up) {
			c->carrier = up;
			syslog(LOG_NOTICE, "carrier => %i event on %s", (int)up, namebuf);
			iface_discover_border(c);
		}
	} while (read > 0);
}

static struct uloop_fd rtnl_fd = { .fd = -1 };

void iface_set_unreachable_route(const struct prefix *p, bool enable)
{
	struct {
		struct nlmsghdr nhm;
		struct rtmsg rtm;
		struct rtattr rta_addr;
		struct in6_addr addr;
		struct rtattr rta_prio;
		uint32_t prio;
	} req = {
		.nhm = {sizeof(req), RTM_DELROUTE, NLM_F_REQUEST, 1, 0},
		.rtm = {AF_INET6, p->plen, 0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_NOWHERE, 0, 0},
		.rta_addr = {sizeof(req.rta_addr) + sizeof(req.addr), RTA_DST},
		.addr = p->prefix,
		.rta_prio = {sizeof(req.rta_prio) + sizeof(req.prio), RTA_PRIORITY},
		.prio = 1000000000
	};

	if (enable) {
		req.nhm.nlmsg_type = RTM_NEWROUTE;
		req.nhm.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
		req.rtm.rtm_type = RTN_UNREACHABLE;
	}

	send(rtnl_fd.fd, &req, sizeof(req), 0);
}

#endif /* __linux__ */

int iface_init(struct pa *pa, const char *pd_socket)
{
#ifdef __linux__
	rtnl_fd.fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (rtnl_fd.fd < 0)
		return -1;

	struct sockaddr_nl rtnl_kernel = { .nl_family = AF_NETLINK };
	if (connect(rtnl_fd.fd, (const struct sockaddr*)&rtnl_kernel, sizeof(rtnl_kernel)) < 0)
		return -1;

	int val = RTNLGRP_LINK;
	setsockopt(rtnl_fd.fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &val, sizeof(val));

	rtnl_fd.cb = iface_link_event;
	uloop_fd_add(&rtnl_fd, ULOOP_READ | ULOOP_EDGE_TRIGGER);
#endif /* __linux__ */

	pa_data_subscribe(&pa->data, &pa_data_cb);
	pa_p = pa;
	return platform_init(&pa->data, pd_socket);
}


void iface_register_user(struct iface_user *user)
{
	list_add(&user->head, &users);
}


void iface_unregister_user(struct iface_user *user)
{
	list_del(&user->head);
}


void iface_set_dhcp_send(const char *ifname, const void *dhcpv6_data, size_t dhcpv6_len, const void *dhcp_data, size_t dhcp_len)
{
	struct iface *c = iface_get(ifname);

	if (!c || !c->platform)
		return;
	if (c->dhcp_len_out == dhcp_len && (!dhcp_len || memcmp(c->dhcp_data_out, dhcp_data, dhcp_len) == 0) && 
	    c->dhcpv6_len_out == dhcpv6_len && (!dhcpv6_len || memcmp(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len) == 0))
		return;

	c->dhcpv6_data_out = realloc(c->dhcpv6_data_out, dhcpv6_len);
	memcpy(c->dhcpv6_data_out, dhcpv6_data, dhcpv6_len);
	c->dhcpv6_len_out = dhcpv6_len;

	c->dhcp_data_out = realloc(c->dhcp_data_out, dhcp_len);
	memcpy(c->dhcp_data_out, dhcp_data, dhcp_len);
	c->dhcp_len_out = dhcp_len;

	platform_set_dhcpv6_send(c, c->dhcpv6_data_out, c->dhcpv6_len_out, c->dhcp_data_out, c->dhcp_len_out);
}

void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len, const void *dhcp_data, size_t dhcp_len)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head)
		iface_set_dhcp_send(c->ifname, dhcpv6_data, dhcpv6_len, dhcp_data, dhcp_len);
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


bool iface_has_ipv4_address(const char *ifname)
{
	struct iface_addr *a;
	struct iface *c = iface_get(ifname);
	vlist_for_each_element(&c->assigned, a, node)
		if (IN6_IS_ADDR_V4MAPPED(&a->prefix.prefix))
			return true;


	return false;
}


// Compare if two addresses are identical
static int compare_addrs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
	const struct prefix *a1 = a, *a2 = b;
	return prefix_cmp(a1, a2);
}


static void purge_addr(struct uloop_timeout *t)
{
	struct iface_addr *a = container_of(t, struct iface_addr, timer);
	vlist_delete(&a->iface->assigned, &a->node);
}

// Update address if necessary (node_new: addr that will be present, node_old: addr that was present)
static void update_addr(struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct iface_addr *a_new = container_of(node_new, struct iface_addr, node);
	struct iface_addr *a_old = container_of(node_old, struct iface_addr, node);

	struct iface *c = container_of(t, struct iface, assigned);
	bool enable = !!node_new;
	hnetd_time_t now = hnetd_time();

	if (!enable && !IN6_IS_ADDR_V4MAPPED(&a_old->prefix.prefix)) {
		// Don't actually remove addresses, but deprecate them so the change is announced
		enable = true;
		a_old->preferred_until = 0;

		hnetd_time_t bound = now + (7200 * HNETD_TIME_PER_SECOND);
		if (a_old->valid_until > bound)
			a_old->valid_until = bound;

		// Reinsert deprecated if not flushing all
		if (t->version != -1 && a_old->valid_until > now) {
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

	if (node_new) {
		a_new->timer.cb = purge_addr;
		a_new->iface = c;
		hnetd_time_t timeout = a_new->valid_until - now + 1;
		if (timeout <= INT_MAX)
			uloop_timeout_set(&a_new->timer, timeout);
	}

	if (node_old) {
		uloop_timeout_cancel(&a_old->timer);
		free(a_old);
	}

	uloop_timeout_set(&c->preferred, 100);
}

static void purge_prefix(struct uloop_timeout *t)
{
	struct iface_addr *a = container_of(t, struct iface_addr, timer);
	vlist_delete(&a->iface->delegated, &a->node);
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

	if (node_new) {
		a_new->timer.cb = purge_prefix;
		a_new->iface = c;
		hnetd_time_t timeout = a->valid_until - hnetd_time() + 1;
		if (timeout <= INT_MAX)
			uloop_timeout_set(&a_new->timer, timeout);
	}

	if (node_old) {
		uloop_timeout_cancel(&a_old->timer);
		free(a_old);
	}
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

	while (!list_empty(&c->chosen)) {
		struct pa_static_prefix_rule *sprule =
				list_first_entry(&c->chosen, struct pa_static_prefix_rule, user);
		pa_core_rule_del(&pa_p->core, &sprule->rule);
		list_del(&sprule->user);
		free(sprule);
	}

	if (c->id) {
		pa_core_rule_del(&pa_p->core, &c->id->rule);
		free(c->id);
	}

	if (c->platform) {
		if (c->flags & IFACE_FLAG_GUEST) {
			struct pa_dp *dp;
			pa_for_each_dp(dp, &pa_p->data)
				platform_filter_prefix(c, &dp->prefix, false);
		}

		platform_iface_free(c);
	}

	if (c->dhcpv6_len_in)
		free(c->dhcpv6_data_in);

	if (c->dhcpv6_len_out)
		free(c->dhcpv6_data_out);

	if (c->dhcp_len_in)
		free(c->dhcp_data_in);

	if (c->dhcp_len_out)
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
	iface_notify_data_state(c, !c->internal);
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
			u->cb_intaddr(u, c->ifname, pref6 ? &pref6->prefix : NULL, pref4 ? &pref4->prefix: NULL);
}


static bool iface_discover_border(struct iface *c)
{
	if (!c->platform) // No border discovery on unmanaged interfaces
		return false;

	// Perform border-discovery (border on DHCPv4 assignment or DHCPv6-PD)
	bool internal = c->carrier && ((c->flags & IFACE_FLAG_GUEST) ||
			(avl_is_empty(&c->delegated.avl) && !c->v4uplink));
	if (c->internal != internal) {
		L_INFO("iface: %s border discovery detected state %s",
				c->ifname, (internal) ? "internal" : "external");

		c->internal = internal;
		uloop_timeout_cancel(&c->transition); // Flapped back to original state

		if (internal)
			uloop_timeout_set(&c->transition, 5000);
		else
			iface_announce_border(&c->transition);

		return true;
	} else if (c->flags & IFACE_FLAG_ACCEPT_CERID) {
		iface_announce_border(&c->transition);
	}
	return false;
}


struct iface* iface_create(const char *ifname, const char *handle, enum iface_flags flags)
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
		INIT_LIST_HEAD(&c->chosen);
		c->transition.cb = iface_announce_border;
		c->preferred.cb = iface_announce_preferred;

		c->designatedv4 = true;
		struct pa_dp *dp;
		if(pa_p) { //This is just for test cases
			pa_for_each_dp(dp, &pa_p->data)
					if (!dp->local && IN6_IS_ADDR_V4MAPPED(&dp->prefix.prefix))
						c->designatedv4 = false;
		}

#ifdef __linux__
		struct {
			struct nlmsghdr hdr;
			struct ifinfomsg ifi;
		} req = {
			.hdr = {sizeof(req), RTM_GETLINK, NLM_F_REQUEST, 1, 0},
			.ifi = {.ifi_index = if_nametoindex(ifname)}
		};
		send(rtnl_fd.fd, &req, sizeof(req), 0);
#endif /* __linux__ */

		list_add(&c->head, &interfaces);
	}

	c->flags = flags;

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


void iface_set_ipv4_uplink(struct iface *c)
{
	c->v4uplink = true;
}


void iface_add_dhcp_received(struct iface *c, const void *data, size_t len)
{
	c->dhcp_data_stage = realloc(c->dhcp_data_stage, c->dhcp_len_stage + len);
	memcpy(((uint8_t*)c->dhcp_data_stage) + c->dhcp_len_stage, data, len);
	c->dhcp_len_stage += len;
}


void iface_update_ipv6_uplink(struct iface *c)
{
	vlist_update(&c->delegated);
	memset(&c->cer, 0, sizeof(c->cer));
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


void iface_update_ipv4_uplink(struct iface *c)
{
	c->v4uplink = false;
}


void iface_commit_ipv4_uplink(struct iface *c)
{
	bool changed = !iface_discover_border(c) && (c->dhcp_len_in != c->dhcp_len_stage ||
					memcmp(c->dhcp_data_in, c->dhcp_data_stage, c->dhcp_len_in));

	free(c->dhcp_data_in);
	c->dhcp_data_in = c->dhcp_data_stage;
	c->dhcp_len_in = c->dhcp_len_stage;
	c->dhcp_data_stage = NULL;
	c->dhcp_len_stage = 0;

	if (changed && !c->internal)
		iface_notify_data_state(c, !c->internal);
}


void iface_commit_ipv6_uplink(struct iface *c)
{
	vlist_flush(&c->delegated);
	bool changed = !iface_discover_border(c) && (c->dhcpv6_len_in != c->dhcpv6_len_stage ||
					memcmp(c->dhcpv6_data_in, c->dhcpv6_data_stage, c->dhcpv6_len_in));

	free(c->dhcpv6_data_in);
	c->dhcpv6_data_in = c->dhcpv6_data_stage;
	c->dhcpv6_len_in = c->dhcpv6_len_stage;
	c->dhcpv6_data_stage = NULL;
	c->dhcpv6_len_stage = 0;

	if (changed && !c->internal)
		iface_notify_data_state(c, !c->internal);
}


void iface_add_dhcpv6_received(struct iface *c, const void *data, size_t len)
{
	c->dhcpv6_data_stage = realloc(c->dhcpv6_data_stage, c->dhcpv6_len_stage + len);
	memcpy(((uint8_t*)c->dhcpv6_data_stage) + c->dhcpv6_len_stage, data, len);
	c->dhcpv6_len_stage += len;
}


void iface_add_chosen_prefix(struct iface *c, const struct prefix *p)
{
	struct pa_static_prefix_rule *sprule = calloc(1, sizeof(*sprule));
	pa_core_static_prefix_init(sprule, c->ifname, p, true);
	sprule->rule.priority = PA_PRIORITY_AUTO_MAX + 2;
	pa_core_rule_add(&pa_p->core, &sprule->rule);
	list_add_tail(&sprule->user, &c->chosen);
}


void iface_set_link_id(struct iface *c, uint32_t linkid, uint8_t mask)
{
	struct pa_link_id_rule *id_rule = c->id;

	if (id_rule)
		pa_core_rule_del(&pa_p->core, &id_rule->rule);
	else
		id_rule = malloc(sizeof(*id_rule));

	memset(id_rule, 0, sizeof(*id_rule));

	pa_core_link_id_init(id_rule, c->ifname, linkid, mask, true);
	id_rule->rule.priority = PA_PRIORITY_AUTO_MAX + 1;
	pa_core_rule_add(&pa_p->core, &id_rule->rule);
}


void iface_update(void)
{
	struct iface *c;
	list_for_each_entry(c, &interfaces, head) {
		iface_update_ipv6_uplink(c);
		iface_update_ipv4_uplink(c);
		c->unused = true;
	}
}


void iface_commit(void)
{
	struct iface *c, *n;
	list_for_each_entry_safe(c, n, &interfaces, head) {
		iface_commit_ipv6_uplink(c);
		iface_commit_ipv4_uplink(c);

		if ((!c->platform || c->unused) && !c->v4uplink && avl_is_empty(&c->delegated.avl))
			iface_remove(c);
	}
}
