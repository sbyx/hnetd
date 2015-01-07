#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <net/if.h>

#include "hncp_link.h"
#include "dncp_i.h"

struct hncp_link {
	dncp dncp;
	dncp_subscriber_s subscr;
	struct list_head users;
};

static void notify(struct hncp_link *l, const char *ifname, dncp_t_link_id ids, size_t cnt)
{
	struct hncp_link_user *u;
	list_for_each_entry(u, &l->users, head)
		if (u->cb_link)
			u->cb_link(u, ifname, ids, cnt);
}

static void cb_link(dncp_subscriber s, const char *ifname, enum dncp_subscriber_event event)
{
	struct hncp_link *l = container_of(s, struct hncp_link, subscr);

	if (event == DNCP_EVENT_ADD || event == DNCP_EVENT_REMOVE)
		notify(l, ifname, (event == DNCP_EVENT_ADD) ? (void*)1 : NULL, 0);
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
	dncp_t_link_id ids = NULL;
	size_t idcnt = 0, idpos = 0;

	struct tlv_attr *c;
	dncp_node_for_each_tlv(l->dncp->own_node, c) {
		dncp_t_node_data_neighbor cn = dncp_tlv_neighbor(c);

		if (!cn)
			continue;

		++idcnt;
	}

	if (idcnt)
		ids = malloc(sizeof(*ids) * idcnt);

	dncp_node_for_each_tlv(l->dncp->own_node, c) {
		dncp_t_node_data_neighbor cn = dncp_tlv_neighbor(c);

		if (!cn || cn->link_id != link->iid)
			continue;

		dncp_node peer = dncp_find_node_by_node_identifier(l->dncp,
				&cn->neighbor_node_identifier, false);

		if (!peer)
			continue;

		struct tlv_attr *pc;
		dncp_node_for_each_tlv(peer, pc) {
			dncp_t_node_data_neighbor pn = dncp_tlv_neighbor(pc);
			if (!pn || pn->link_id != cn->neighbor_link_id ||
					memcmp(&pn->neighbor_node_identifier,
							&l->dncp->own_node->node_identifier, DNCP_NI_LEN))
				continue;

			if (pn->neighbor_link_id == link->iid) {
				// Matching reverse neighbor entry
				ids[idpos].node_identifier = peer->node_identifier;
				ids[idpos].link_id = pn->link_id;
				++idpos;
			} else if (pn->neighbor_link_id < link->iid) {
				// Two of our links seem to be connected
				free(ids);
				ids = NULL;
				idpos = 0;
				unique = false;
				break;
			}
		}

		if (!unique)
			break;
	}

	notify(l, link->ifname, (ids) ? ids : unique ? (void*)1 : NULL, idpos);
	free(ids);
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
