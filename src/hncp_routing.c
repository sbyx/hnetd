/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/file.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "hncp_routing.h"
#include "dncp_i.h"
#include "hncp_i.h"
#include "iface.h"

struct hncp_routing_struct {
	dncp_subscriber_s subscr;
	hncp hncp;
	dncp dncp;
	struct uloop_timeout t;
	struct iface_user iface;
	const char *script;
	const char **ifaces;
	size_t ifaces_cnt;
	struct uloop_process configure_proc;
	struct uloop_process routing_proc;
	bool configure_pending;
	bool routing_pending;
};

static void hncp_routing_spawn(char **argv)
{
	pid_t pid = hncp_run(argv);
	waitpid(pid, NULL, 0);
}

static void hncp_configure_exec(struct uloop_process *p, __unused int ret)
{
	hncp_bfs bfs = container_of(p, hncp_bfs_s, configure_proc);
	if (bfs->configure_pending && !bfs->configure_proc.pending) {
		char **argv = alloca((bfs->ifaces_cnt + 3) * sizeof(char*));
		argv[0] = (char*)bfs->script;
		argv[1] = "configure";
		memcpy(&argv[2], bfs->ifaces, bfs->ifaces_cnt * sizeof(char*));
		argv[2 + bfs->ifaces_cnt] = NULL;

		bfs->configure_proc.cb = hncp_configure_exec;
		bfs->configure_proc.pid = hncp_run(argv);
		uloop_process_add(&bfs->configure_proc);
		bfs->configure_pending = false;
	}
}

static void hncp_routing_intiface(struct iface_user *u, const char *ifname, bool enable)
{
	hncp_bfs bfs = container_of(u, hncp_bfs_s, iface);
	size_t i;

	for (i = 0; i < bfs->ifaces_cnt; ++i)
		if (!strcmp(bfs->ifaces[i], ifname))
			break;

	if (enable && i == bfs->ifaces_cnt) {
		bfs->ifaces = realloc(bfs->ifaces, ++bfs->ifaces_cnt * sizeof(char*));
		bfs->ifaces[bfs->ifaces_cnt - 1] = ifname;
	} else if (!enable && i < bfs->ifaces_cnt) {
		bfs->ifaces[i] = bfs->ifaces[--bfs->ifaces_cnt];
	} else {
		/* routing setup did not change -> skip reconfigure */
		return;
	}

	if (bfs->script) {
		bfs->configure_pending = true;
		hncp_configure_exec(&bfs->configure_proc, 0);
	}
}

static void hncp_routing_intaddr(struct iface_user *u, __unused const char *ifname,
		__unused const struct prefix *addr6, const struct prefix *addr4)
{
	// Reschedule routing run when we have an IPv4-address on link
	hncp_bfs bfs = container_of(u, hncp_bfs_s, iface);
	if (addr4)
		uloop_timeout_set(&bfs->t, 0);
}

static void hncp_routing_cb(dncp_subscriber s, __unused dncp_node n,
		struct tlv_attr *tlv, __unused bool add)
{
	hncp_bfs bfs = container_of(s, hncp_bfs_s, subscr);
	if (tlv_id(tlv) == HNCP_T_ASSIGNED_PREFIX || tlv_id(tlv) == HNCP_T_DELEGATED_PREFIX ||
			tlv_id(tlv) == DNCP_T_NEIGHBOR || tlv_id(tlv) == HNCP_T_EXTERNAL_CONNECTION ||
			tlv_id(tlv) == HNCP_T_ROUTER_ADDRESS)
		uloop_timeout_set(&bfs->t, 0);
}

static void hncp_routing_exec(struct uloop_process *p, __unused int ret)
{
	hncp_bfs bfs = container_of(p, hncp_bfs_s, routing_proc);
	if (!(bfs->routing_pending && !bfs->routing_proc.pending))
		return;
	bfs->routing_proc.cb = hncp_routing_exec;
	bfs->routing_proc.pid = fork();
	if (bfs->routing_proc.pid) {
		uloop_process_add(&bfs->routing_proc);
		bfs->routing_pending = false;
		return;
	}

	dncp dncp = bfs->dncp;
	struct list_head queue = LIST_HEAD_INIT(queue);
	dncp_node c, n;
	char dst[PREFIX_MAXBUFFLEN] = "", via[INET6_ADDRSTRLEN] = "";
	char domain[PREFIX_MAXBUFFLEN] = "", metric[16];
	char *argv[] = {(char*)bfs->script, "bfsprepare", dst, via, NULL, metric, domain, NULL};

	vlist_for_each_element(&dncp->nodes, c, in_nodes) {
		hncp_node hc = dncp_node_get_ext_data(c);
		// Mark all nodes as not visited
		hc->bfs.next_hop = NULL;
		hc->bfs.next_hop4 = NULL;
		hc->bfs.hopcount = 0;
	}

	hncp_routing_spawn(argv);
	hncp_node hon = dncp_node_get_ext_data(dncp->own_node);
	list_add_tail(&hon->bfs.head, &queue);

	while (!list_empty(&queue)) {
		hncp_node hc = container_of(list_first_entry(&queue, struct hncp_bfs_head, head), hncp_node_s,bfs);
		c = dncp_node_from_ext_data(hc);
		argv[4] = (char*)hc->bfs.ifname;
		L_WARN("Router %s", DNCP_NODE_REPR(c));

		struct tlv_attr *a, *a2;
		dncp_node_for_each_tlv(c, a) {
			hncp_t_assigned_prefix_header ap;
			dncp_t_neighbor ne;
			if ((ne = dncp_tlv_neighbor(dncp, a))) {
				if (!(n = dncp_node_find_neigh_bidir(c, ne)))
					continue; // Connection not mutual

				hncp_node hn = dncp_node_get_ext_data(n);
				if (hn->bfs.next_hop || n == dncp->own_node)
					continue; // Already visited


				if (c == dncp->own_node) { // We are at the start, lookup neighbor
					dncp_ep ep = dncp_find_ep_by_id(dncp, ne->ep_id);
					if (!ep)
						continue;
					dncp_tlv tlv = dncp_find_tlv(dncp, DNCP_T_NEIGHBOR, tlv_data(a), tlv_len(a));
					dncp_neighbor neigh = tlv ? dncp_tlv_get_extra(tlv) : NULL;
					if (neigh) {
						hn->bfs.next_hop = &neigh->last_sa6.sin6_addr;
						hn->bfs.ifname = ep->ifname;
					}

					struct tlv_attr *na;
					hncp_t_router_address ra;
					dncp_node_for_each_tlv_with_type(n, na, HNCP_T_ROUTER_ADDRESS) {
						if ((ra = hncp_tlv_ra(na))) {
							if (ra->ep_id == ne->neighbor_ep_id &&
							    IN6_IS_ADDR_V4MAPPED(&ra->address)) {
								hn->bfs.next_hop4 = &ra->address;
								break;
							}
						}
					}
				} else { // Inherit next-hop from predecessor
					hn->bfs.next_hop = hc->bfs.next_hop;
					hn->bfs.next_hop4 = hc->bfs.next_hop4;
					hn->bfs.ifname = hc->bfs.ifname;
				}

				if (!hn->bfs.next_hop || !hn->bfs.ifname)
					continue;

				hn->bfs.hopcount = hc->bfs.hopcount + 1;
				list_add_tail(&hn->bfs.head, &queue);
			} else if (tlv_id(a) == HNCP_T_EXTERNAL_CONNECTION) {
				hncp_t_delegated_prefix_header dp;
				tlv_for_each_attr(a2, a)
					if ((dp = hncp_tlv_dp(a2))) {
						struct prefix from = { .plen = dp->prefix_length_bits };
						size_t plen = ROUND_BITS_TO_BYTES(from.plen);
						unsigned int flen = ROUND_BYTES_TO_4BYTES(sizeof(*dp) +
											  ROUND_BITS_TO_BYTES(dp->prefix_length_bits));
						struct in6_addr domainaddr;
						struct tlv_attr *b;

						memcpy(&from.prefix, &dp[1], plen);
						prefix_ntop(dst, sizeof(dst), &from.prefix, from.plen);

						if (c != dncp->own_node)
							snprintf(metric, sizeof(metric), "%u", hc->bfs.hopcount);
						else
							metric[0] = 0;

						if (!IN6_IS_ADDR_V4MAPPED(&from.prefix))
							argv[1] = "bfsipv6prefix";
						else
							argv[1] = "bfsipv4prefix";

						hncp_routing_spawn(argv);

						if (tlv_len(a2) < flen || !metric[0] || !hc->bfs.ifname)
							continue;

						tlv_for_each_in_buf(b, tlv_data(a2) + flen, tlv_len(a2) - flen) {
							hncp_t_prefix_domain d = tlv_data(b);
							if (tlv_id(b) != HNCP_T_PREFIX_DOMAIN || tlv_len(b) < 1 || d->type > 128)
								continue;

							plen = ROUND_BITS_TO_BYTES(d->type);
							if (tlv_len(b) < 1 + plen)
								continue;

							if (d->type == 0) {
								strcpy(domain, "default");
							} else {
								memcpy(&domainaddr, d->id, plen);
								memset(&domainaddr.s6_addr[plen], 0, sizeof(domainaddr) - plen);
								prefix_ntop(domain, sizeof(domain), &domainaddr, d->type);
							}

							if (!IN6_IS_ADDR_V4MAPPED(&from.prefix) && hc->bfs.next_hop) {
								argv[1] = "bfsipv6uplink";
								inet_ntop(AF_INET6, hc->bfs.next_hop, via, sizeof(via));
								hncp_routing_spawn(argv);
							} else if (IN6_IS_ADDR_V4MAPPED(&from.prefix) && hc->bfs.next_hop4 &&
								iface_has_ipv4_address(hc->bfs.ifname)) {
								argv[1] = "bfsipv4uplink";
								inet_ntop(AF_INET, &hc->bfs.next_hop4->s6_addr[12], via, sizeof(via));
								hncp_routing_spawn(argv);
							}
						}
					}
			} else if ((ap = hncp_tlv_ap(a)) && c != dncp->own_node && hc->bfs.ifname) {
				struct iface *ifo = iface_get(hc->bfs.ifname);
				dncp_ep ep = dncp_find_ep_by_name(dncp, hc->bfs.ifname);
				if (!dncp_ep_is_enabled(ep))
					ep = NULL;
				// Skip routes for prefixes on connected links
				if (ep && ifo && (ifo->flags & IFACE_FLAG_ADHOC) != IFACE_FLAG_ADHOC && hc->bfs.hopcount == 1) {
					dncp_t_neighbor_s np = {
						.neighbor_ep_id = ap->ep_id,
						.ep_id = dncp_ep_get_id(ep)
					};
					size_t buflen = sizeof(np) + DNCP_NI_LEN(dncp);
					void *buf = alloca(buflen);
					memcpy(buf, &c->node_id, DNCP_NI_LEN(dncp));
					memcpy(buf + DNCP_NI_LEN(dncp), &np, sizeof(np));


					if (dncp_find_tlv(dncp, DNCP_T_NEIGHBOR, buf, buflen))
						continue;
				}

				struct prefix to = { .plen = ap->prefix_length_bits };
				size_t plen = ROUND_BITS_TO_BYTES(to.plen);
				memcpy(&to.prefix, &ap[1], plen);
				unsigned linkid = (ep) ? dncp_ep_get_id(ep) : 0;
				prefix_ntop(dst, sizeof(dst), &to.prefix, to.plen);
				snprintf(metric, sizeof(metric), "%u", hc->bfs.hopcount << 8 | linkid);

				if (!IN6_IS_ADDR_V4MAPPED(&to.prefix) && hc->bfs.next_hop) {
					inet_ntop(AF_INET6, hc->bfs.next_hop, via, sizeof(via));
					argv[1] = "bfsipv6assigned";
					hncp_routing_spawn(argv);
				} else if (IN6_IS_ADDR_V4MAPPED(&to.prefix) && hc->bfs.next_hop4 &&
					iface_has_ipv4_address(hc->bfs.ifname)) {
					inet_ntop(AF_INET, &hc->bfs.next_hop4->s6_addr[12], via, sizeof(via));
					argv[1] = "bfsipv4assigned";
					hncp_routing_spawn(argv);
				}
			}
		}

		list_del(&hc->bfs.head);
	}
	_exit(0);
}

static void hncp_routing_schedule(struct uloop_timeout *t)
{
	hncp_bfs bfs = container_of(t, hncp_bfs_s, t);
	bfs->routing_pending = true;
	hncp_routing_exec(&bfs->routing_proc, 0);
}

hncp_bfs hncp_routing_create(hncp hncp, const char *script, bool incremental)
{
	hncp_bfs bfs = calloc(1, sizeof(*bfs));

	bfs->hncp = hncp;
	bfs->dncp = hncp_get_dncp(hncp);
	bfs->script = script;
	bfs->iface.cb_intiface = hncp_routing_intiface;

	if (incremental) {
		bfs->t.cb = hncp_routing_schedule;
		bfs->iface.cb_intaddr = hncp_routing_intaddr;
		bfs->subscr.tlv_change_cb = hncp_routing_cb;
		dncp_subscribe(bfs->dncp, &bfs->subscr);
	}

	iface_register_user(&bfs->iface);
	return bfs;
}

void hncp_routing_destroy(hncp_bfs bfs)
{
	uloop_timeout_cancel(&bfs->t);
	iface_unregister_user(&bfs->iface);

	if (bfs->t.cb)
		dncp_unsubscribe(bfs->dncp, &bfs->subscr);

	free(bfs->ifaces);
	free(bfs);
}
