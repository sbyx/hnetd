#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <net/if.h>

#include "dncp_i.h"
#include "hncp_proto.h"
#include "hncp_link.h"

struct hncp_link {
	dncp dncp;
	dncp_subscriber_s subscr;
	struct list_head users;
};

static void notify(struct hncp_link *l, const char *ifname, dncp_t_link_id ids, size_t cnt,
		enum hncp_link_elected elected)
{
	struct hncp_link_user *u;
	list_for_each_entry(u, &l->users, head) {
		if (u->cb_link)
			u->cb_link(u, ifname, ids, cnt);

		if (u->cb_elected)
			u->cb_elected(u, ifname, elected);
	}
}

static void cb_link(dncp_subscriber s, const char *ifname, enum dncp_subscriber_event event)
{
	struct hncp_link *l = container_of(s, struct hncp_link, subscr);

	if (event == DNCP_EVENT_ADD || event == DNCP_EVENT_REMOVE)
		notify(l, ifname, (event == DNCP_EVENT_ADD) ? (void*)1 : NULL, 0,
				(event == DNCP_EVENT_ADD) ? HNCP_LINK_ALL : HNCP_LINK_NONE);
}

static void cb_tlv(dncp_subscriber s, dncp_node n,
		struct tlv_attr *tlv, bool add __unused)
{
	struct hncp_link *l = container_of(s, struct hncp_link, subscr);
	dncp_t_node_data_neighbor ne = dncp_tlv_neighbor(tlv);
	dncp_link link = NULL;

	if (ne) {
		if (dncp_node_is_self(n))
			link = dncp_find_link_by_id(l->dncp, ne->link_id);
		else if (!memcmp(&ne->neighbor_node_identifier,
				&l->dncp->own_node->node_identifier, DNCP_NI_LEN))
			link = dncp_find_link_by_id(l->dncp, ne->neighbor_link_id);
	}


	if (!link)
		return;

	bool unique = true;
	enum hncp_link_elected elected = HNCP_LINK_ALL;
	hncp_t_version ourversion = NULL;
	dncp_t_link_id peers = NULL;
	size_t peercnt = 0, peerpos = 0;

	struct tlv_attr *c;
	dncp_node_for_each_tlv(l->dncp->own_node, c) {
		if (tlv_id(c) == HNCP_T_VERSION &&
				tlv_len(c) > sizeof(*ourversion))
			ourversion = tlv_data(c);
		else if (dncp_tlv_neighbor(c))
			++peercnt;
	}

	if (peercnt)
		peers = malloc(sizeof(*peers) * peercnt);

	dncp_node_for_each_tlv(l->dncp->own_node, c) {
		dncp_t_node_data_neighbor cn = dncp_tlv_neighbor(c);

		if (!cn || cn->link_id != link->iid)
			continue;

		dncp_node peer = dncp_find_node_by_node_identifier(l->dncp,
				&cn->neighbor_node_identifier, false);

		if (!peer)
			continue;

		bool mutual = false;
		hncp_t_version peerversion = NULL;

		struct tlv_attr *pc;
		dncp_node_for_each_tlv(peer, pc) {
			if (tlv_id(pc) == HNCP_T_VERSION &&
					tlv_len(pc) > sizeof(*peerversion))
				peerversion = tlv_data(pc);

			dncp_t_node_data_neighbor pn = dncp_tlv_neighbor(pc);
			if (!pn || pn->link_id != cn->neighbor_link_id ||
					memcmp(&pn->neighbor_node_identifier,
							&l->dncp->own_node->node_identifier, DNCP_NI_LEN))
				continue;

			if (pn->neighbor_link_id == link->iid) {
				// Matching reverse neighbor entry
				mutual = true;
				peers[peerpos].node_identifier = peer->node_identifier;
				peers[peerpos].link_id = pn->link_id;
				++peerpos;
			} else if (pn->neighbor_link_id < link->iid) {
				// Two of our links seem to be connected
				unique = false;
				break;
			}
		}

		if (!unique)
			break;

		// Capability election
		if (mutual && ourversion && peerversion) {
			uint16_t ourv = be16_to_cpu(ourversion->capabilities);
			uint16_t peerv = be16_to_cpu(peerversion->capabilities);

			// M-Flag
			if ((((ourv >> 12) & 0xf) < ((peerv >> 12) & 0xf)) ||
					((((ourv >> 12) & 0xf) == ((peerv >> 12) & 0xf)) && ourv < peerv))
				elected &= ~HNCP_LINK_MDNSPROXY;

			// P-Flag
			if ((((ourv >> 8) & 0xf) < ((peerv >> 8) & 0xf)) ||
					((((ourv >> 8) & 0xf) == ((peerv >> 8) & 0xf)) && ourv < peerv))
				elected &= ~HNCP_LINK_PREFIXDEL;

			// H-Flag
			if ((((ourv >> 4) & 0xf) < ((peerv >> 4) & 0xf)) ||
					((((ourv >> 4) & 0xf) == ((peerv >> 4) & 0xf)) && ourv < peerv))
				elected &= ~HNCP_LINK_HOSTNAMES;

			// L-Flag
			if ((((ourv >> 0) & 0xf) < ((peerv >> 0) & 0xf)) ||
					((((ourv >> 0) & 0xf) == ((peerv >> 0) & 0xf)) && ourv < peerv))
				elected &= ~HNCP_LINK_LEGACY;
		}
	}

	notify(l, link->ifname, (!unique) ? NULL : (peers) ? peers : (void*)1,
			(unique) ? peerpos : 0, unique ? elected : HNCP_LINK_NONE);
	free(peers);
}

struct hncp_link* hncp_link_create(dncp dncp)
{
	struct hncp_link *l = calloc(1, sizeof(*l));
	if (l) {
		l->dncp = dncp;
		INIT_LIST_HEAD(&l->users);

		l->subscr.link_change_callback = cb_link;
		l->subscr.tlv_change_callback = cb_tlv;
		dncp_subscribe(dncp, &l->subscr);
	}
	return l;
}

void hncp_link_destroy(struct hncp_link *l)
{
	while (!list_empty(&l->users))
		list_del(l->users.next);

	dncp_unsubscribe(l->dncp, &l->subscr);
	free(l);
}

void hncp_link_register(struct hncp_link *l, struct hncp_link_user *user)
{
	list_add(&user->head, &l->users);
}

void hncp_link_unregister(struct hncp_link_user *user)
{
	list_del(&user->head);
}
