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
#include <linux/fib_rules.h>
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
#include "hncp_pa.h"
#include "dhcpv6.h"

static void iface_update_dp_cb(__unused struct hncp_pa_iface_user *u,
		const struct hncp_pa_dp *dp, bool del);
static void iface_update_address_cb(struct hncp_pa_iface_user *i, const char *ifname,
		const struct in6_addr *addr, uint8_t plen,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		uint8_t *dhcp_data, size_t dhcp_len,
		bool del);
void iface_link_cb(struct hncp_link_user *user, const char *ifname,
		enum hncp_link_elected elected);

static bool iface_discover_border(struct iface *c);

static struct list_head interfaces = LIST_HEAD_INIT(interfaces);
static struct list_head users = LIST_HEAD_INIT(users);
static dncp hncp_p = NULL;
static hncp_sd hncp_sd_p = NULL;
static hncp_pa hncp_pa_p = NULL;
static struct hncp_pa_iface_user hncp_pa_cbs = {
		.update_address = iface_update_address_cb,
		.update_dp = iface_update_dp_cb
};
static struct hncp_link_user link_cb = {
	.cb_elected = iface_link_cb,
};

void iface_link_cb(struct hncp_link_user *user __unused, const char *ifname,
		enum hncp_link_elected elected)
{
	struct iface *c = iface_get(ifname);
	elected &= HNCP_LINK_HOSTNAMES | HNCP_LINK_LEGACY |
			HNCP_LINK_PREFIXDEL | HNCP_LINK_STATELESS;

	if (c && c->elected != elected && strcmp(c->ifname, "lo") &&
			(c->flags & IFACE_FLAG_HYBRID) != IFACE_FLAG_HYBRID) {
		platform_set_dhcp(c, elected);
		c->elected = elected;
	}
}



static void iface_update_dp_cb(__unused struct hncp_pa_iface_user *u,
		const struct hncp_pa_dp *dp, bool del)
{
	// Called by hncp_pa when a DP is added or removed.
	// The DP can be local (from iface), local (from IPv4, ULA) or
	// distant (from HNCP)
	if(!del) {
		//Add new DP
		struct iface *c;
		list_for_each_entry(c, &interfaces, head)
			if ((c->flags & IFACE_FLAG_GUEST) == IFACE_FLAG_GUEST)
				platform_filter_prefix(c, &dp->prefix, true);

		//L_DEBUG("Pushing to platform "PA_DP_L, PA_DP_LA(dp));
		platform_set_prefix_route(&dp->prefix, true);

		if(prefix_is_ipv4(&dp->prefix)) {
			if (!dp->local) {
				struct iface *c;
				list_for_each_entry(c, &interfaces, head) {
					if (c->designatedv4) {
						c->designatedv4 = false;
						platform_restart_dhcpv4(c);
					}
				}
			} else {
				struct iface *c;
				list_for_each_entry(c, &interfaces, head)
				if ((c->flags & IFACE_FLAG_HYBRID) == IFACE_FLAG_HYBRID)
					platform_set_snat(c, &dp->prefix);
			}
		}
	} else {
		//Remove DP
		struct iface *c;
		list_for_each_entry(c, &interfaces, head)
		if ((c->flags & IFACE_FLAG_GUEST) == IFACE_FLAG_GUEST)
			platform_filter_prefix(c, &dp->prefix, false);

		//L_DEBUG("Removing from platform "PA_DP_L, PA_DP_LA(dp));
		platform_set_prefix_route(&dp->prefix, false);

		if(prefix_is_ipv4(&dp->prefix)) {
			if (dp->local) {
				list_for_each_entry(c, &interfaces, head)
					if ((c->flags & IFACE_FLAG_HYBRID) == IFACE_FLAG_HYBRID)
							platform_set_snat(c, NULL);
			}

			bool ipv4_edp = (c->flags & IFACE_FLAG_INTERNAL) &&
					(c->flags & IFACE_FLAG_HYBRID) != IFACE_FLAG_HYBRID;
			struct hncp_pa_dp *dpc;
			hncp_pa_for_each_dp(dpc, hncp_pa_p)
				if (dpc != dp && !dpc->local && IN6_IS_ADDR_V4MAPPED(&dpc->prefix.prefix))
					ipv4_edp = true;

			struct iface *c;
			list_for_each_entry(c, &interfaces, head) {
				if (c->designatedv4 != !ipv4_edp) {
					c->designatedv4 = !ipv4_edp;
					platform_restart_dhcpv4(c);
				}
			}
		}
	}
}

//Called by hncp_pa when an address is added or modified.
static void iface_update_address_cb(__unused struct hncp_pa_iface_user *i,
		const char *ifname,
		const struct in6_addr *addr, uint8_t plen,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		uint8_t *dhcp_data, size_t dhcp_len,
		bool del)
{
	struct iface_addr *a;
	struct iface *c = iface_get(ifname);
	if(!c) {
		L_DEBUG("iface_pa_prefix_update: No iface found (%s).", ifname);
		return;
	}
	assert(c->platform != NULL);

	if(del) {
		struct prefix p = {.plen = plen, .prefix = *addr};
		if ((a = vlist_find(&c->assigned, &p, a, node))) {
			vlist_delete(&c->assigned, &a->node);
		} else {
			L_DEBUG("iface_update_address_cb: element not found.");
		}
	} else {
		if(!(a = calloc(1, sizeof(*a) + dhcp_len))) {
			L_DEBUG("iface_update_address_cb: can't allocate memory.");
			return;
		}
		memcpy(&a->prefix.prefix, addr, sizeof(struct in6_addr));
		a->prefix.plen = plen;
		a->valid_until = valid_until;
		a->preferred_until = preferred_until;
		a->dhcpv6_len = dhcp_len;
		memcpy(a->dhcpv6_data, dhcp_data, dhcp_len);
		vlist_add(&c->assigned, &a->node, &a->prefix);
	}
}

// Notify
static void iface_notify_internal_state(struct iface *c, bool enable)
{
	struct iface_user *u;
	list_for_each_entry(u, &users, head) {
		if (u->cb_intiface && (enable || c->internal))
			u->cb_intiface(u, c->ifname, enable && c->internal);

		if (u->cb_extiface && (enable || !c->internal))
			u->cb_extiface(u, c->ifname, enable && !c->internal);
	}

	if (enable || c->internal)
		platform_set_internal(c, enable && c->internal);
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
	struct req {
		struct nlmsghdr nhm;
		struct rtmsg rtm;
		struct rtattr rta_addr;
		struct in6_addr addr;
		struct rtattr rta_prio;
		uint32_t prio;
	} req = {
		.nhm = {sizeof(req), RTM_DELROUTE, NLM_F_REQUEST, 1, 0},
		.rtm = {prefix_is_ipv4(p) ? AF_INET : AF_INET6, prefix_af_length(p),
				0, 0, RT_TABLE_MAIN, RTPROT_STATIC, RT_SCOPE_NOWHERE, 0, 0},
		.rta_addr = {sizeof(req.rta_addr) + sizeof(req.addr), RTA_DST},
		.addr = p->prefix,
		.rta_prio = {sizeof(req.rta_prio) + sizeof(req.prio), RTA_PRIORITY},
		.prio = INT32_MAX - 1,
	};

	if (enable) {
		req.nhm.nlmsg_type = RTM_NEWROUTE;
		req.nhm.nlmsg_flags |= NLM_F_CREATE | NLM_F_REPLACE;
		req.rtm.rtm_scope = RT_SCOPE_UNIVERSE;
		req.rtm.rtm_type = RTN_UNREACHABLE;
	}

	send(rtnl_fd.fd, &req, req.nhm.nlmsg_len, 0);
}
#endif /* __linux__ */

int iface_init(dncp hncp, hncp_sd sd, hncp_pa hncp_pa, struct hncp_link *link, const char *pd_socket)
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

	hncp_link_register(link, &link_cb);
	hncp_pa_p = hncp_pa;
	hncp_pa_iface_user_register(hncp_pa, &hncp_pa_cbs);
	hncp_p = hncp;
	hncp_sd_p = sd;
	return platform_init(hncp, hncp_pa, pd_socket);
}


void iface_register_user(struct iface_user *user)
{
	list_add(&user->head, &users);
}


void iface_unregister_user(struct iface_user *user)
{
	list_del(&user->head);
}


char* iface_get_fqdn(const char *ifname, char *buf, size_t len)
{
	dncp_link link = dncp_find_link_by_name(hncp_p, ifname, false);
	hncp_sd_dump_link_fqdn(hncp_sd_p, link, ifname, buf, len);
	return buf;
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

	if (!node_new && !node_old)
		return;

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

	L_INFO("iface: %s assigned prefix %s to %s",
			(node_new) ? (node_old) ? "updated" : "added" : "removed",
			PREFIX_REPR((node_new) ? &a_new->prefix : &a_old->prefix),
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
	else if (!node_new && !node_old)
		return;

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
					PREFIX_REPR(&a->prefix), c->ifname);

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

struct iface* iface_next(struct iface *prev)
{
	struct list_head *p = (prev) ? &prev->head : &interfaces;
	return (p->next != &interfaces) ? list_entry(p->next, struct iface, head) : NULL;
}

void iface_remove(struct iface *c)
{
	if (!c)
		return;

	iface_update_ipv6_uplink(c);
	iface_update_ipv4_uplink(c);
	iface_commit_ipv6_uplink(c);
	iface_commit_ipv4_uplink(c);

	// If interface was internal, let subscribers know of removal
	iface_notify_internal_state(c, false);

	list_del(&c->head);
	vlist_flush_all(&c->assigned);

	if (c->platform) {
		if ((c->flags & IFACE_FLAG_GUEST) == IFACE_FLAG_GUEST) {
			struct hncp_pa_dp *dp;
			hncp_pa_for_each_dp(dp, hncp_pa_p)
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
	iface_notify_internal_state(c, true);

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

int iface_get_preferred_address(struct in6_addr *addr, bool v4)
{
	hnetd_time_t now = hnetd_time();
	struct iface_addr *pref = NULL;
	struct iface *c;

	list_for_each_entry(c, &interfaces, head) {
		struct iface_addr *a;
		vlist_for_each_element(&c->assigned, a, node) {
			if (v4 == IN6_IS_ADDR_V4MAPPED(&a->prefix.prefix) &&
					(v4 || a->preferred_until > now) &&
					(!pref || a->preferred_until > pref->preferred_until))
				pref = a;
		}
	}

	if (pref)
		*addr = pref->prefix.prefix;

	return -!pref;
}

static bool iface_discover_border(struct iface *c)
{
	if (!c->platform) // No border discovery on unmanaged interfaces
		return false;

	// Perform border-discovery (border on DHCPv4 assignment or DHCPv6-PD)
	bool internal = c->carrier && !(c->flags & IFACE_FLAG_EXTERNAL) && (
			(c->flags & IFACE_FLAG_INTERNAL) ||
			(avl_is_empty(&c->delegated.avl) && !c->v4_saddr.s_addr));
	if (c->internal != internal) {
		L_INFO("iface: %s border discovery detected state %s",
				c->ifname, (internal) ? "internal" : "external");

		c->internal = internal;
		uloop_timeout_cancel(&c->transition); // Flapped back to original state

		if (internal) {
			uloop_timeout_set(&c->transition, 5000);
			return true;
		} else {
			c->transition.cb(&c->transition);
		}
	}
	return false;
}


struct iface* iface_create(const char *ifname, const char *handle, iface_flags flags)
{
	struct iface *c = iface_get(ifname);
	if (!c) {
		size_t namelen = strlen(ifname) + 1;
		c = calloc(1, sizeof(*c) + namelen);
		memcpy(c->ifname, ifname, namelen);

		if (!strcmp(ifname, "lo") || !strcmp(ifname, "lo0")) {
			c->flags = IFACE_FLAG_INTERNAL;
			c->ip6_plen = 128;
		}

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
		INIT_LIST_HEAD(&c->chosen);
		INIT_LIST_HEAD(&c->addrconf);
		c->transition.cb = iface_announce_border;
		c->preferred.cb = iface_announce_preferred;

		c->designatedv4 = !(flags & IFACE_FLAG_INTERNAL) ||
				(flags & IFACE_FLAG_HYBRID) == IFACE_FLAG_HYBRID;
		struct hncp_pa_dp *dp;
		if(hncp_pa_p) { //This is just for test cases
			hncp_pa_for_each_dp(dp, hncp_pa_p)
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
		c->transition.cb(&c->transition);
		iface_discover_border(c);
	}

	return c;
}


void iface_flush(void)
{
	while (!list_empty(&interfaces))
		iface_remove(list_first_entry(&interfaces, struct iface, head));
}


void iface_set_ipv4_uplink(struct iface *c, const struct in_addr *saddr, int prefix)
{
	c->v4_saddr = *saddr;
	c->v4_prefix = prefix;
}


void iface_add_dhcp_received(struct iface *c, const void *data, size_t len)
{
	c->dhcp_data_stage = realloc(c->dhcp_data_stage, c->dhcp_len_stage + len);
	memcpy(((uint8_t*)c->dhcp_data_stage) + c->dhcp_len_stage, data, len);
	c->dhcp_len_stage += len;
}


void iface_update_ipv6_uplink(struct iface *c)
{
	c->had_ipv6_uplink = !avl_is_empty(&c->delegated.avl);
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


void iface_update_ipv4_uplink(struct iface *c)
{
	c->had_ipv4_uplink = !!c->v4_saddr.s_addr;
	c->v4_saddr.s_addr = INADDR_ANY;
	c->v4_prefix = 0;
}


void iface_commit_ipv4_uplink(struct iface *c)
{
	iface_discover_border(c);
	bool has_ipv4_uplink = c->designatedv4 && c->v4_saddr.s_addr;
	bool changed = c->had_ipv4_uplink != has_ipv4_uplink ||
			(has_ipv4_uplink && ((c->dhcp_len_in != c->dhcp_len_stage ||
					memcmp(c->dhcp_data_in, c->dhcp_data_stage, c->dhcp_len_in))));

	free(c->dhcp_data_in);
	c->dhcp_data_in = c->dhcp_data_stage;
	c->dhcp_len_in = c->dhcp_len_stage;
	c->dhcp_data_stage = NULL;
	c->dhcp_len_stage = 0;

	if (changed) {
		bool enabled = !c->internal || (c->flags & IFACE_FLAG_HYBRID) == IFACE_FLAG_HYBRID;
		void *data4 = (enabled && c->v4_saddr.s_addr) ? (c->dhcp_data_in ? c->dhcp_data_in : (void*)1) : NULL;
		size_t len4 = (enabled && c->v4_saddr.s_addr) ? c->dhcp_len_in : 0;

		struct iface_user *u;
		list_for_each_entry(u, &users, head)
			if (u->cb_ext4data)
				u->cb_ext4data(u, c->ifname, data4, len4);
	}
}


void iface_commit_ipv6_uplink(struct iface *c)
{
	vlist_flush(&c->delegated);
	iface_discover_border(c);
	bool has_ipv6_uplink = !avl_is_empty(&c->delegated.avl);
	bool changed = c->had_ipv6_uplink != has_ipv6_uplink || (
			has_ipv6_uplink && (c->dhcpv6_len_in != c->dhcpv6_len_stage ||
					memcmp(c->dhcpv6_data_in, c->dhcpv6_data_stage, c->dhcpv6_len_in)));

	free(c->dhcpv6_data_in);
	c->dhcpv6_data_in = c->dhcpv6_data_stage;
	c->dhcpv6_len_in = c->dhcpv6_len_stage;
	c->dhcpv6_data_stage = NULL;
	c->dhcpv6_len_stage = 0;

	if (changed) {
		bool enabled = !c->internal || (c->flags & IFACE_FLAG_HYBRID) == IFACE_FLAG_HYBRID;
		void *data = (enabled && !avl_is_empty(&c->delegated.avl)) ? (c->dhcpv6_data_in ? c->dhcpv6_data_in : (void*)1) : NULL;
		size_t len = (enabled && !avl_is_empty(&c->delegated.avl)) ? c->dhcpv6_len_in : 0;

		struct iface_user *u;
		list_for_each_entry(u, &users, head)
			if (u->cb_extdata)
				u->cb_extdata(u, c->ifname, data, len);
	}
}


void iface_add_dhcpv6_received(struct iface *c, const void *data, size_t len)
{
	c->dhcpv6_data_stage = realloc(c->dhcpv6_data_stage, c->dhcpv6_len_stage + len);
	memcpy(((uint8_t*)c->dhcpv6_data_stage) + c->dhcpv6_len_stage, data, len);
	c->dhcpv6_len_stage += len;
}

/*
void iface_add_chosen_prefix(struct iface *c, const struct prefix *p)
{
	struct pa_static_prefix_rule *sprule;
	//Check if that prefix is already configured
	list_for_each_entry(sprule, &c->chosen, user) {
		if(!prefix_cmp(p, &sprule->prefix))
			return;
	}
	sprule = calloc(1, sizeof(*sprule));
	pa_core_static_prefix_init(sprule, c->ifname, p, true);
	sprule->rule.result.priority = PA_PRIORITY_AUTO_MAX + 2;
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
	id_rule->rule.result.priority = PA_PRIORITY_AUTO_MAX + 1;
	pa_core_rule_add(&pa_p->core, &id_rule->rule);
	c->id = id_rule;
}

void iface_add_addrconf(struct iface *c, struct in6_addr *addr,
		uint8_t mask, struct prefix *filter)
{
	struct pa_iface_addr *a;
	list_for_each_entry(a, &c->addrconf, user) {
		if(memcmp(addr, &a->address, sizeof(struct in6_addr)) || mask != a->mask ||
				strcmp(c->ifname, a->ifname))
			continue;
		if((filter && !prefix_cmp(filter, &a->filter)) || (!filter && a->filter.plen == 0))
			return; //It is the same entry
	}
	a = malloc(sizeof(*a));
	pa_core_iface_addr_init(a, c->ifname, addr, mask, filter);
	list_add_tail(&a->user, &c->addrconf);
	pa_core_iface_addr_add(&pa_p->core, a);
}
*/

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

		if ((!c->platform || c->unused) && !c->v4_saddr.s_addr && avl_is_empty(&c->delegated.avl))
			iface_remove(c);
	}
}
