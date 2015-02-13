/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 */


#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <net/if.h>

#include "iface.h"
#include "dncp_i.h"
#include "hncp_i.h"
#include "hncp_proto.h"
#include "hncp_link.h"

struct hncp_link {
	dncp dncp;
	dncp_tlv versiontlv;
	dncp_subscriber_s subscr;
	struct iface_user iface;
	struct list_head users;
};

static void notify(struct hncp_link *l, const char *ifname, dncp_t_link_id ids, size_t cnt,
		enum hncp_link_elected elected)
{
	L_DEBUG("hncp_link_notify: %s neighbors: %d elected(SMPHL): %x", ifname, (int)cnt, elected);

	struct hncp_link_user *u;
	list_for_each_entry(u, &l->users, head) {
		if (u->cb_link)
			u->cb_link(u, ifname, ids, cnt);

		if (u->cb_elected)
			u->cb_elected(u, ifname, elected);
	}
}

static void calculate_link(struct hncp_link *l, dncp_link link)
{
	bool unique = true;
	hncp_t_version ourvertlv = NULL;
	enum hncp_link_elected elected = HNCP_LINK_NONE;
	dncp_t_link_id peers = NULL;
	size_t peercnt = 0, peerpos = 0;

	if (!link)
		return;

	struct tlv_attr *c;
	dncp_node_for_each_tlv(l->dncp->own_node, c) {
		if (tlv_id(c) == HNCP_T_VERSION &&
				tlv_len(c) > sizeof(hncp_t_version_s)) {
			ourvertlv = tlv_data(c);

			if (ourvertlv->cap_mdnsproxy)
				elected |= HNCP_LINK_MDNSPROXY;

			if (ourvertlv->cap_prefixdel)
				elected |= HNCP_LINK_PREFIXDEL;

			if (ourvertlv->cap_hostnames)
				elected |= HNCP_LINK_HOSTNAMES;

			if (ourvertlv->cap_legacy)
				elected |= HNCP_LINK_LEGACY;
		} else if (dncp_tlv_neighbor(c)) {
			++peercnt;
		} else if (tlv_id(c) == HNCP_T_ASSIGNED_PREFIX) {
			hncp_t_assigned_prefix_header ah = dncp_tlv_ap(c);
			if (ah && ah->link_id == link->iid)
				elected |= HNCP_LINK_STATELESS;
		}
	}

	L_DEBUG("hncp_link_calculate: %s peer-candidates: %d preelected(SMPHL): %x",
			link->ifname, (int)peercnt, elected);

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
		hncp_t_version peervertlv = NULL;

		struct tlv_attr *pc;
		dncp_node_for_each_tlv(peer, pc) {
			if (tlv_id(pc) == HNCP_T_VERSION &&
					tlv_len(pc) > sizeof(*peervertlv))
				peervertlv = tlv_data(pc);

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
				L_WARN("hncp_link_calculate: %s links %d and %d appear to be connected",
						link->ifname, link->iid, pn->neighbor_link_id);

				// Two of our links seem to be connected
				unique = false;
				break;
			}
		}

		if (!unique)
			break;

		// Capability election
		if (mutual && ourvertlv && peervertlv) {
			int ourcaps = ourvertlv->cap_mdnsproxy << 12 |
					ourvertlv->cap_prefixdel << 8 |
					ourvertlv->cap_hostnames << 4 |
					ourvertlv->cap_legacy;
			int peercaps = peervertlv->cap_mdnsproxy << 12 |
					peervertlv->cap_prefixdel << 8 |
					peervertlv->cap_hostnames << 4 |
					peervertlv->cap_legacy;

			if (ourvertlv->cap_mdnsproxy < peervertlv->cap_mdnsproxy)
				elected &= ~HNCP_LINK_MDNSPROXY;

			if (ourvertlv->cap_prefixdel < peervertlv->cap_prefixdel)
				elected &= ~HNCP_LINK_PREFIXDEL;

			if (ourvertlv->cap_hostnames < peervertlv->cap_hostnames)
				elected = (elected & ~HNCP_LINK_HOSTNAMES) | HNCP_LINK_OTHERMNGD;

			if (ourvertlv->cap_legacy < peervertlv->cap_legacy)
				elected &= ~HNCP_LINK_LEGACY;

			if (ourcaps < peercaps || (ourcaps == peercaps &&
					memcmp(&l->dncp->own_node->node_identifier, &peer->node_identifier, DNCP_NI_LEN) < 0)) {
				if (peervertlv->cap_mdnsproxy &&
						ourvertlv->cap_mdnsproxy == peervertlv->cap_mdnsproxy)
					elected &= ~HNCP_LINK_MDNSPROXY;

				if (peervertlv->cap_prefixdel &&
						ourvertlv->cap_prefixdel == peervertlv->cap_prefixdel)
					elected &= ~HNCP_LINK_PREFIXDEL;

				if (peervertlv->cap_hostnames &&
						ourvertlv->cap_hostnames == peervertlv->cap_hostnames)
					elected = (elected & ~HNCP_LINK_HOSTNAMES) | HNCP_LINK_OTHERMNGD;

				if (peervertlv->cap_legacy &&
						ourvertlv->cap_legacy == peervertlv->cap_legacy)
					elected &= ~HNCP_LINK_LEGACY;
			}

			L_DEBUG("hncp_link_calculate: %s peer: %x peer-caps: %x ourcaps: %x pre-elected(SMPHL): %x",
					link->ifname, *((uint32_t*)&peer->node_identifier), peercaps, ourcaps, elected);
		}
	}

	notify(l, link->ifname, (!unique) ? NULL : (peers) ? peers : (void*)1,
			(unique) ? peerpos : 0, unique ? elected : HNCP_LINK_NONE);
	free(peers);
}

static void cb_intiface(struct iface_user *u, const char *ifname, bool enabled)
{
	struct hncp_link *l = container_of(u, struct hncp_link, iface);
	if (enabled)
		calculate_link(l, dncp_find_link_by_name(l->dncp, ifname, false));
	else
		notify(l, ifname, NULL, 0, HNCP_LINK_NONE);
}

static void cb_tlv(dncp_subscriber s, dncp_node n,
		struct tlv_attr *tlv, bool add __unused)
{
	struct hncp_link *l = container_of(s, struct hncp_link, subscr);
	dncp_t_node_data_neighbor ne = dncp_tlv_neighbor(tlv);
	hncp_t_assigned_prefix_header ap = dncp_tlv_ap(tlv);
	uint32_t link = 0;

	if (ne) {
		if (dncp_node_is_self(n))
			link = ne->link_id;
		else if (!memcmp(&ne->neighbor_node_identifier,
				&l->dncp->own_node->node_identifier, DNCP_NI_LEN))
			link = ne->neighbor_link_id;
	} else if (ap && dncp_node_is_self(n)) {
		link = ap->link_id;
	}

	calculate_link(l, dncp_find_link_by_id(l->dncp, link));
}

struct hncp_link* hncp_link_create(dncp dncp, const struct hncp_link_config *conf)
{
	struct hncp_link *l = calloc(1, sizeof(*l));
	if (l) {
		l->dncp = dncp;
		INIT_LIST_HEAD(&l->users);

		l->subscr.tlv_change_callback = cb_tlv;
		dncp_subscribe(dncp, &l->subscr);

		l->iface.cb_intiface = cb_intiface;
		iface_register_user(&l->iface);

		if (conf) {
			struct __packed {
				hncp_t_version_s version;
				char agent[sizeof(conf->agent)];
			} data = {
				{conf->version, 0, conf->cap_mdnsproxy, conf->cap_prefixdel,
						conf->cap_hostnames, conf->cap_legacy}, {0}
			};
			memcpy(data.agent, conf->agent, sizeof(data.agent));

			l->versiontlv = dncp_add_tlv(dncp, HNCP_T_VERSION, &data,
					sizeof(hncp_t_version_s) + strlen(conf->agent) + 1, 0);
		}
	}
	return l;
}

void hncp_link_destroy(struct hncp_link *l)
{
	while (!list_empty(&l->users))
		list_del(l->users.next);

	dncp_remove_tlv(l->dncp, l->versiontlv);
	dncp_unsubscribe(l->dncp, &l->subscr);
	iface_unregister_user(&l->iface);
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
