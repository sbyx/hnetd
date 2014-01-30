#include "hcp_bfs.h"
#include "hcp_i.h"
#include "iface.h"

static void hcp_bfs_run(struct uloop_timeout *t);
static void hcp_bfs_callback(hcp_subscriber s, __unused hcp_node n,
		__unused struct tlv_attr *tlv, __unused bool add);

struct hcp_bfs_struct {
	hcp_subscriber_s subscr;
	hcp hcp;
	struct uloop_timeout t;
};

hcp_bfs hcp_bfs_create(hcp hcp)
{
	hcp_bfs bfs = calloc(1, sizeof(*bfs));
	bfs->subscr.tlv_change_callback = hcp_bfs_callback;
	bfs->hcp = hcp;
	bfs->t.cb = hcp_bfs_run;
	hcp_subscribe(hcp, &bfs->subscr);
	return bfs;
}

void hcp_bfs_destroy(hcp_bfs bfs)
{
	uloop_timeout_cancel(&bfs->t);
	hcp_unsubscribe(bfs->hcp, &bfs->subscr);
	free(bfs);
}

static bool hcp_bfs_neighbors_are_mutual(hcp_node node, hcp_hash node_identifier_hash,
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

static void hcp_bfs_callback(hcp_subscriber s, __unused hcp_node n,
		__unused struct tlv_attr *tlv, __unused bool add)
{
	hcp_bfs bfs = container_of(s, hcp_bfs_s, subscr);
	uloop_timeout_set(&bfs->t, 0);
}

static void hcp_bfs_run(struct uloop_timeout *t)
{
	hcp hcp = container_of(t, hcp_bfs_s, t)->hcp;
	struct list_head queue = LIST_HEAD_INIT(queue);
	hcp_node c, n;
	vlist_for_each_element(&hcp->nodes, c, in_nodes) {
		// Mark all nodes as not visited
		c->bfs.next_hop = NULL;
		c->bfs.hopcount = 0;

		// TODO: bail if homenet has chosen real routing algorithm
	}

	list_add_tail(&hcp->own_node->bfs.head, &queue);

	iface_update_routes();

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

				if (!hcp_bfs_neighbors_are_mutual(n, &c->node_identifier_hash,
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
