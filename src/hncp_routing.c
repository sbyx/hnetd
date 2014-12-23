/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "hncp_routing.h"
#include "hncp_i.h"
#include "iface.h"

static void hncp_routing_run(struct uloop_timeout *t);
static void hncp_routing_callback(dncp_subscriber s, __unused dncp_node n,
		__unused struct tlv_attr *tlv, __unused bool add);

static const char *hncp_routing_names[HNCP_ROUTING_MAX] = {
		[HNCP_ROUTING_NONE] = "Fallback routing",
		[HNCP_ROUTING_BABEL] = "Babel",
		[HNCP_ROUTING_OSPF] = "OSPF",
		[HNCP_ROUTING_ISIS] = "IS-IS",
		[HNCP_ROUTING_RIP] = "RIP",
};

struct hncp_routing_struct {
	dncp_subscriber_s subscr;
	dncp hncp;
	struct uloop_timeout t;
	enum hncp_routing_protocol active;
	dncp_tlv tlv[HNCP_ROUTING_MAX];
	struct iface_user iface;
	const char *script;
	const char **ifaces;
	size_t ifaces_cnt;
};

static int call_backend(hncp_bfs bfs, const char *action, int stdin)
{
	if (!bfs->script)
		return 0;

	char protobuf[4];
	snprintf(protobuf, sizeof(protobuf), "%u", bfs->active);

	char **argv = malloc((bfs->ifaces_cnt + 4) * sizeof(char*));
	argv[0] = (char*)bfs->script;
	argv[1] = (char*)action;
	argv[2] = protobuf;
	memcpy(&argv[3], bfs->ifaces, bfs->ifaces_cnt * sizeof(char*));
	argv[3 + bfs->ifaces_cnt] = NULL;

	pid_t pid = fork();
	if (pid == 0) {
		if (stdin >= 0) {
			dup2(stdin, STDOUT_FILENO);
			close(stdin);
		}

		execv(argv[0], argv);
		_exit(128);
	}

	if (stdin >= 0)
		close(stdin);

	free(argv);

	int status;
	waitpid(pid, &status, 0);
	return status;
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
	call_backend(bfs, "reconfigure", -1);
}

static void hncp_routing_intaddr(struct iface_user *u, __unused const char *ifname,
		__unused const struct prefix *addr6, const struct prefix *addr4)
{
	// Reschedule routing run when we have an IPv4-address on link
	hncp_bfs bfs = container_of(u, hncp_bfs_s, iface);
	if (bfs->active == HNCP_ROUTING_NONE && addr4)
		uloop_timeout_set(&bfs->t, 0);
}

hncp_bfs hncp_routing_create(dncp hncp, const char *script)
{
	hncp_bfs bfs = calloc(1, sizeof(*bfs));
	bfs->subscr.tlv_change_callback = hncp_routing_callback;
	bfs->hncp = hncp;
	bfs->t.cb = hncp_routing_run;
	bfs->active = HNCP_ROUTING_MAX;
	bfs->script = script;
	bfs->iface.cb_intiface = hncp_routing_intiface;
	bfs->iface.cb_intaddr = hncp_routing_intaddr;
	dncp_subscribe(hncp, &bfs->subscr);
	iface_register_user(&bfs->iface);

	// Load supported protocols and preferences
	if (script) {
		int fd[2];
		pipe(fd);
		fcntl(fd[0], F_SETFD, fcntl(fd[0], F_GETFD) | FD_CLOEXEC);
		call_backend(bfs, "enumerate", fd[1]);

		FILE *fp = fdopen(fd[0], "r");
		if (fp) {
			char buf[128];
			while (fgets(buf, sizeof(buf), fp)) {
				unsigned proto, preference;
				if (sscanf(buf, "%u %u", &proto, &preference) == 2 &&
						proto < HNCP_ROUTING_MAX && preference < 256 &&
						!bfs->tlv[proto]) {
					struct __packed {
						uint8_t proto;
						uint8_t preference;
					} tlv = { .proto = proto, .preference = preference };
					bfs->tlv[proto] = dncp_add_tlv(hncp, HNCP_T_ROUTING_PROTOCOL, &tlv, 2, 0);
				}
			}
			fclose(fp);
		} else {
			syslog(LOG_WARNING, "Failed to run routing script: %s", strerror(errno));
		}
	}

	return bfs;
}

void hncp_routing_destroy(hncp_bfs bfs)
{
	uloop_timeout_cancel(&bfs->t);
	iface_unregister_user(&bfs->iface);
	dncp_unsubscribe(bfs->hncp, &bfs->subscr);

	for (size_t i = 0; i < HNCP_ROUTING_MAX; ++i) {
		if (!bfs->tlv[i])
			continue;

		dncp_remove_tlv(bfs->hncp, bfs->tlv[i]);
		free(bfs->tlv[i]);
	}
	free(bfs);
}

static void hncp_routing_callback(dncp_subscriber s, __unused dncp_node n,
		__unused struct tlv_attr *tlv, __unused bool add)
{
	hncp_bfs bfs = container_of(s, hncp_bfs_s, subscr);
	uloop_timeout_set(&bfs->t, 0);
}

static void hncp_routing_run(struct uloop_timeout *t)
{
	hncp_bfs bfs = container_of(t, hncp_bfs_s, t);
	dncp hncp = bfs->hncp;
	struct list_head queue = LIST_HEAD_INIT(queue);
	dncp_node c, n;

	size_t routercnt = 0;
	unsigned routing_preference[HNCP_ROUTING_MAX] = {0};
	unsigned routing_supported[HNCP_ROUTING_MAX] = {0};

	vlist_for_each_element(&hncp->nodes, c, in_nodes) {
		bool have_routing = false;

		// Mark all nodes as not visited
		c->profile_data.bfs.next_hop = NULL;
		c->profile_data.bfs.next_hop4 = NULL;
		c->profile_data.bfs.hopcount = 0;

		struct tlv_attr *a;
		dncp_node_for_each_tlv_with_type(c, a, HNCP_T_ROUTING_PROTOCOL) {
			if (tlv_len(a) >= sizeof(hncp_t_routing_protocol_s)) {
				hncp_t_routing_protocol p = tlv_data(a);
				if (p->protocol < HNCP_ROUTING_MAX) {
					++routing_supported[p->protocol];
					routing_preference[p->protocol] += p->preference;
				}
				have_routing = true;
			}
		}

		if (have_routing)
			++routercnt;
	}

	// Elect routing protocol
	size_t current_pref = 0;
	size_t current_proto = HNCP_ROUTING_NONE;

	for (size_t i = 1; i < HNCP_ROUTING_MAX; ++i) {
		if (routing_supported[i] == routercnt &&
				routing_preference[i] >= current_pref) {
			current_proto = i;
			current_pref = routing_preference[i];
		}
	}

	// Disable old routing protocol
	if (current_proto != bfs->active) {
		if (bfs->active == HNCP_ROUTING_NONE) {
			iface_update_routes();
			iface_commit_routes();
		} else {
			call_backend(bfs, "disable", -1);
		}

		bfs->active = current_proto;
		if (current_proto != HNCP_ROUTING_NONE)
			call_backend(bfs, "enable", -1);
	}

	if (bfs->active != HNCP_ROUTING_NONE)
		return;

	// Run BFS fallback algorithm
	bool have_v4uplink = false;

	iface_update_routes();
	list_add_tail(&hncp->own_node->profile_data.bfs.head, &queue);

	while (!list_empty(&queue)) {
		c = container_of(list_first_entry(&queue, struct hncp_bfs_head, head), dncp_node_s, profile_data.bfs);
		L_WARN("Router %s", DNCP_NODE_REPR(c));

		struct tlv_attr *a, *a2;
		dncp_node_for_each_tlv(c, a) {
			hncp_t_assigned_prefix_header ap;
			dncp_t_node_data_neighbor ne;
			if ((ne = dncp_tlv_neighbor(a))) {

				n = dncp_find_node_by_node_identifier(hncp,
					&ne->neighbor_node_identifier, false);

				if (!(n = dncp_node_find_neigh_bidir(c, ne)))
					continue; // Connection not mutual

				if (n->profile_data.bfs.next_hop || n == hncp->own_node)
					continue; // Already visited


				if (c == hncp->own_node) { // We are at the start, lookup neighbor
					dncp_link link = dncp_find_link_by_id(hncp, ne->link_id);
					if (!link)
						continue;
					dncp_neighbor neigh = dncp_link_find_neighbor_for_tlv(link, ne);
					if (neigh) {
						n->profile_data.bfs.next_hop = &neigh->last_sa6.sin6_addr;
						n->profile_data.bfs.ifname = link->ifname;
					}

					struct tlv_attr *na;
					hncp_t_router_address ra;
					dncp_node_for_each_tlv_with_type(n, na, HNCP_T_ROUTER_ADDRESS) {
						if ((ra = dncp_tlv_router_address(na))) {
							if (ra->link_id == ne->neighbor_link_id &&
							    IN6_IS_ADDR_V4MAPPED(&ra->address)) {
								n->profile_data.bfs.next_hop4 = &ra->address;
								break;
							}
						}
					}
				} else { // Inherit next-hop from predecessor
					n->profile_data.bfs.next_hop = c->profile_data.bfs.next_hop;
					n->profile_data.bfs.next_hop4 = c->profile_data.bfs.next_hop4;
					n->profile_data.bfs.ifname = c->profile_data.bfs.ifname;
				}

				if (!n->profile_data.bfs.next_hop || !n->profile_data.bfs.ifname)
					continue;

				n->profile_data.bfs.hopcount = c->profile_data.bfs.hopcount + 1;
				list_add_tail(&n->profile_data.bfs.head, &queue);
			} else if (tlv_id(a) == HNCP_T_EXTERNAL_CONNECTION && c != hncp->own_node) {
				hncp_t_delegated_prefix_header dp;
				tlv_for_each_attr(a2, a)
					if ((dp = dncp_tlv_dp(a2))) {
						struct prefix from = { .plen = dp->prefix_length_bits };
						size_t plen = ROUND_BITS_TO_BYTES(from.plen);
						memcpy(&from.prefix, &dp[1], plen);

						if (!IN6_IS_ADDR_V4MAPPED(&from.prefix)) {
							if (c->profile_data.bfs.next_hop && c->profile_data.bfs.ifname)
								iface_add_default_route(c->profile_data.bfs.ifname, &from, c->profile_data.bfs.next_hop, c->profile_data.bfs.hopcount);
						} else {
							if (c->profile_data.bfs.next_hop4 && c->profile_data.bfs.ifname && !have_v4uplink && iface_has_ipv4_address(c->profile_data.bfs.ifname)) {
								iface_add_default_route(c->profile_data.bfs.ifname, NULL, c->profile_data.bfs.next_hop4, c->profile_data.bfs.hopcount);
								have_v4uplink = true;
							}
						}
					}
			} else if ((ap = dncp_tlv_ap(a)) && c != hncp->own_node) {
				dncp_link link = dncp_find_link_by_name(hncp, c->profile_data.bfs.ifname, false);
				struct iface *ifo = link ? iface_get(c->profile_data.bfs.ifname) : NULL;
				// Skip routes for prefixes on connected links
				if (link && ifo && (ifo->flags & IFACE_FLAG_ADHOC) != IFACE_FLAG_ADHOC && c->profile_data.bfs.hopcount == 1) {
					dncp_t_node_data_neighbor_s np = {
						.neighbor_node_identifier = c->node_identifier,
						.neighbor_link_id = ap->link_id,
						.link_id = link->iid
					};
					if (dncp_link_find_neighbor_for_tlv(link, &np))
						continue;
				}

				struct prefix to = { .plen = ap->prefix_length_bits };
				size_t plen = ROUND_BITS_TO_BYTES(to.plen);
				memcpy(&to.prefix, &ap[1], plen);
				unsigned linkid = (link) ? link->iid : 0;

				if (!IN6_IS_ADDR_V4MAPPED(&to.prefix)) {
					if (c->profile_data.bfs.next_hop && c->profile_data.bfs.ifname)
						iface_add_internal_route(c->profile_data.bfs.ifname, &to, c->profile_data.bfs.next_hop,
								c->profile_data.bfs.hopcount << 8 | linkid);
				} else {
					if (c->profile_data.bfs.next_hop4 && c->profile_data.bfs.ifname && iface_has_ipv4_address(c->profile_data.bfs.ifname))
						iface_add_internal_route(c->profile_data.bfs.ifname, &to, c->profile_data.bfs.next_hop4,
								c->profile_data.bfs.hopcount << 8 | linkid);
				}
			}
		}

		list_del(&c->profile_data.bfs.head);
	}
	iface_commit_routes();
}

const char *hncp_routing_namebyid(enum hncp_routing_protocol id)
{
	if(id >= HNCP_ROUTING_MAX)
		return "Unknown routing protocol";

	return hncp_routing_names[id];
}
