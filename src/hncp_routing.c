#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include "hcp_routing.h"
#include "hcp_i.h"
#include "iface.h"

static void hcp_routing_run(struct uloop_timeout *t);
static void hcp_routing_callback(hcp_subscriber s, __unused hcp_node n,
		__unused struct tlv_attr *tlv, __unused bool add);

struct hcp_routing_struct {
	hcp_subscriber_s subscr;
	hcp hcp;
	struct uloop_timeout t;
	enum hcp_routing_protocol active;
	struct tlv_attr *tlv[HCP_ROUTING_MAX];
	const char *script;
};

static int call_backend(hcp_bfs bfs, const char *action, enum hcp_routing_protocol proto, int stdin)
{
	char protobuf[4];
	snprintf(protobuf, sizeof(protobuf), "%u", proto);

	char *argv[] = {(char*)bfs->script, (char*)action, protobuf, NULL};
	pid_t pid = vfork();
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

	int status;
	waitpid(pid, &status, 0);
	return status;
}

hcp_bfs hcp_routing_create(hcp hcp, const char *script)
{
	hcp_bfs bfs = calloc(1, sizeof(*bfs));
	bfs->subscr.tlv_change_callback = hcp_routing_callback;
	bfs->hcp = hcp;
	bfs->t.cb = hcp_routing_run;
	bfs->active = HCP_ROUTING_MAX;
	bfs->script = script;
	hcp_subscribe(hcp, &bfs->subscr);

	// Load supported protocols and preferences
	if (script) {
		int fd[2];
		pipe(fd);
		fcntl(fd[0], F_SETFD, fcntl(fd[0], F_GETFD) | FD_CLOEXEC);
		call_backend(bfs, "enumerate", HCP_ROUTING_NONE, fd[1]);

		FILE *fp = fdopen(fd[0], "r");
		if (fp) {
			char buf[128];
			while (fgets(buf, sizeof(buf), fp)) {
				unsigned proto, preference;
				if (sscanf(buf, "%u %u", &proto, &preference) == 2 &&
						proto < HCP_ROUTING_MAX && preference < 256 &&
						!bfs->tlv[proto]) {
					struct {
						struct tlv_attr hdr;
						uint8_t proto;
						uint8_t preference;
					} tlv;
					tlv_init(&tlv.hdr, HCP_T_ROUTING_PROTOCOL, 6);
					tlv.proto = proto;
					tlv.preference = preference;
					bfs->tlv[proto] = hcp_add_tlv(hcp, &tlv.hdr);
				}
			}
			fclose(fp);
		} else {
			syslog(LOG_WARNING, "Failed to run routing script: %s", strerror(errno));
		}
	}

	return bfs;
}

void hcp_routing_destroy(hcp_bfs bfs)
{
	uloop_timeout_cancel(&bfs->t);
	hcp_unsubscribe(bfs->hcp, &bfs->subscr);

	for (size_t i = 0; i < HCP_ROUTING_MAX; ++i) {
		if (!bfs->tlv[i])
			continue;

		hcp_remove_tlv(bfs->hcp, bfs->tlv[i]);
		free(bfs->tlv[i]);
	}
	free(bfs);
}

static bool hcp_routing_neighbors_are_mutual(hcp_node node, hcp_hash node_identifier_hash,
		uint32_t link_id, uint32_t neighbor_link_id)
{
	struct tlv_attr *a, *tlvs = node->tlv_container;
	unsigned rem;
	tlv_for_each_attr(a, tlvs, rem) {
		if (tlv_id(a) == HCP_T_NODE_DATA_NEIGHBOR &&
				tlv_len(a) == sizeof(hcp_t_node_data_neighbor_s)) {
			hcp_t_node_data_neighbor ne = tlv_data(a);
			if (ne->link_id == neighbor_link_id && ne->neighbor_link_id == link_id &&
					!memcmp(&ne->neighbor_node_identifier_hash,
							node_identifier_hash, sizeof(*node_identifier_hash)))
				return true;
		}
	}
	return false;
}

static void hcp_routing_callback(hcp_subscriber s, __unused hcp_node n,
		__unused struct tlv_attr *tlv, __unused bool add)
{
	hcp_bfs bfs = container_of(s, hcp_bfs_s, subscr);
	uloop_timeout_set(&bfs->t, 0);
}

static void hcp_routing_run(struct uloop_timeout *t)
{
	hcp_bfs bfs = container_of(t, hcp_bfs_s, t);
	hcp hcp = bfs->hcp;
	struct list_head queue = LIST_HEAD_INIT(queue);
	hcp_node c, n;

	size_t routercnt = 0;
	unsigned routing_preference[HCP_ROUTING_MAX] = {0};
	unsigned routing_supported[HCP_ROUTING_MAX] = {0};

	vlist_for_each_element(&hcp->nodes, c, in_nodes) {
		// Mark all nodes as not visited
		c->bfs.next_hop = NULL;
		c->bfs.hopcount = 0;

		++routercnt;
		struct tlv_attr *a, *tlvs = c->tlv_container;
		unsigned rem;
		tlv_for_each_attr(a, tlvs, rem) {
			if (tlv_id(a) == HCP_T_ROUTING_PROTOCOL &&
					tlv_len(a) >= sizeof(hcp_t_routing_protocol_s)) {
				hcp_t_routing_protocol p = tlv_data(a);
				if (p->protocol < HCP_ROUTING_MAX) {
					++routing_supported[p->protocol];
					routing_preference[p->protocol] += p->preference;
				}
			}
		}
	}

	// Elect routing protocol
	size_t current_pref = 0;
	size_t current_proto = HCP_ROUTING_NONE;

	for (size_t i = 1; i < HCP_ROUTING_MAX; ++i) {
		if (routing_supported[i] == routercnt &&
				routing_preference[i] >= current_pref) {
			current_proto = i;
			current_pref = routing_preference[i];
		}
	}

	// Disable old routing protocol
	if (current_proto != bfs->active && bfs->active != HCP_ROUTING_MAX) {
		if (bfs->active == HCP_ROUTING_NONE) {
			iface_update_routes();
			iface_commit_routes();
		} else {
			call_backend(bfs, "disable", bfs->active, -1);
		}

		if (current_proto != HCP_ROUTING_NONE)
			call_backend(bfs, "enable", current_proto, -1);
	}

	bfs->active = current_proto;
	if (bfs->active != HCP_ROUTING_NONE)
		return;

	// Run BFS fallback algorithm
	iface_update_routes();
	list_add_tail(&hcp->own_node->bfs.head, &queue);

	while (!list_empty(&queue)) {
		c = container_of(list_first_entry(&queue, struct hcp_bfs_head, head), hcp_node_s, bfs);
		L_WARN("Router %d", c->node_identifier_hash.buf[0]);

		struct tlv_attr *a, *tlvs = c->tlv_container;
		unsigned rem;
		tlv_for_each_attr(a, tlvs, rem) {
			if (tlv_id(a) == HCP_T_NODE_DATA_NEIGHBOR &&
					tlv_len(a) == sizeof(hcp_t_node_data_neighbor_s)) {

				hcp_t_node_data_neighbor ne = tlv_data(a);
				n = hcp_find_node_by_hash(hcp,
					&ne->neighbor_node_identifier_hash, false);

				if (!n || n->bfs.next_hop || n == hcp->own_node)
					continue; // Already visited

				if (!hcp_routing_neighbors_are_mutual(n, &c->node_identifier_hash,
						ne->link_id, ne->neighbor_link_id))
					continue; // Connection not mutual

				if (c == hcp->own_node) { // We are at the start, lookup neighbor
					hcp_link link = hcp_find_link_by_id(hcp, be32_to_cpu(ne->link_id));
					if (!link)
						continue;

					hcp_neighbor_s *neigh, query = {
						.node_identifier_hash = ne->neighbor_node_identifier_hash,
						.iid = be32_to_cpu(ne->neighbor_link_id)
					};

					neigh = vlist_find(&link->neighbors, &query, &query, in_neighbors);
					if (neigh) {
						n->bfs.next_hop = &neigh->last_address;
						n->bfs.ifname = link->ifname;
					}
				} else { // Inherit next-hop from predecessor
					n->bfs.next_hop = c->bfs.next_hop;
					n->bfs.ifname = c->bfs.ifname;
				}

				if (!n->bfs.next_hop || !n->bfs.ifname)
					continue;

				n->bfs.hopcount = c->bfs.hopcount + 1;
				list_add_tail(&n->bfs.head, &queue);
			} else if (tlv_id(a) == HCP_T_DELEGATED_PREFIX && hcp_tlv_dp_valid(a) && c != hcp->own_node) {
				hcp_t_delegated_prefix_header dp = tlv_data(a);

				struct prefix from = { .plen = dp->prefix_length_bits };
				size_t plen = ROUND_BITS_TO_BYTES(from.plen);
				memcpy(&from.prefix, &dp[1], plen);

				if (c->bfs.next_hop && c->bfs.ifname)
					iface_add_default_route(c->bfs.ifname, &from, c->bfs.next_hop, c->bfs.hopcount);
			} else if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX && hcp_tlv_ap_valid(a) && c != hcp->own_node) {
				hcp_t_assigned_prefix_header ap = tlv_data(a);

				struct prefix to = { .plen = ap->prefix_length_bits };
				size_t plen = ROUND_BITS_TO_BYTES(to.plen);
				memcpy(&to.prefix, &ap[1], plen);

				if (c->bfs.next_hop && c->bfs.ifname)
					iface_add_internal_route(c->bfs.ifname, &to, c->bfs.next_hop, c->bfs.hopcount);
			}
		}

		list_del(&c->bfs.head);
	}
	iface_commit_routes();
}
