/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * hncp_pa.c is too big.
 * hncp_pa_i.h and .c contain structure manipulation functions (dummy things).
 *
 */

#ifndef HNCP_PA_I_H_
#define HNCP_PA_I_H_

#include "hncp_i.h"
#include "pa_core.h"
#include "pa_rules.h"
#include "pa_filters.h"
#include "iface.h"
#include "pa_store.h"
#include "dhcpv6.h"
#include "dhcp.h"

#define HNCP_PA_PD_TEMP_LEASE  60 * HNETD_TIME_PER_SECOND

typedef struct hpa_iface_struct *hpa_iface, hpa_iface_s;

typedef struct hpa_adjacency_struct {
	struct avl_node te;
	dncp_t_link_id_s id;
	hpa_iface iface;
	bool updated;
} *hpa_adjacency, hpa_adjacency_s;

typedef struct hpa_advp_struct {
	struct pa_advp advp;
	struct list_head le; //APs are linked in main struct
	dncp_t_link_id_s link_id;
	uint8_t ap_flags;
} hpa_advp_s, *hpa_advp;

#define hpa_for_each_iface(hpa, i) list_for_each_entry(i, &(hpa)->ifaces, le)

typedef struct hpa_conf_struct {
	struct vlist_node vle;
	hpa_iface iface;
	enum {
		HPA_CONF_T_PREFIX,
		HPA_CONF_T_ADDR,
		HPA_CONF_T_LINK_ID,
		HPA_CONF_T_IP4_PLEN,
		HPA_CONF_T_IP6_PLEN
	} type;
	union {
		/* HPA_CONF_T_PREFIX */
		struct {
			struct prefix prefix;
			struct pa_rule_static rule;
		} prefix;

		/* HPA_CONF_T_ADDR */
		struct {
			struct in6_addr addr;
			uint8_t mask;
			struct prefix filter;
			struct pa_rule_static rule;
		} addr;

		/* HPA_CONF_T_LINK_ID */
		struct {
			uint32_t id;
			uint8_t mask;
			struct pa_rule_static rule;
		} link_id;

		/* HPA_CONF_T_IP4_PLEN
		 * HPA_CONF_T_IP6_PLEN */
		uint8_t plen;
	};
} *hpa_conf, hpa_conf_s;

#define HPA_LINK_T_IFACE 0x1
#define HPA_LINK_T_LEASE 0x2
#define HPA_LINK_T_EXCLU 0x3

#define HPA_LINK_NAME_IF   "if:"
#define HPA_LINK_NAME_PD   "pd:"
#define HPA_LINK_NAME_ADDR "addr:"
#define HPA_LINK_NAME_LEN  8

enum {
	HNCP_PA_EXTDATA_IPV4 = 0,
	HNCP_PA_EXTDATA_IPV6 = 1,
	HNCP_PA_EXTDATA_N    = 2
};

struct hpa_iface_struct {
	struct list_head le;
	char ifname[IFNAMSIZ];

	//Backpointer to main hpa struct
	hncp_pa hpa;

	//If the interface is PA enabled
	bool pa_enabled;
	char pa_name[IFNAMSIZ + HPA_LINK_NAME_LEN];
	struct pa_link pal;
	struct pa_rule_adopt pa_adopt;
	struct pa_rule_random pa_rand;


	char aa_name[IFNAMSIZ + HPA_LINK_NAME_LEN];
	struct pa_link aal;
	//struct pa_rule_slaac aa_slaac; //todo
	struct pa_rule_random aa_rand;

	//Stable storage
	struct pa_store_link pasl;
	struct pa_store_link aasl;

	//If the interface is dncp enabled
	dncp_link l;

	//If iface is an external link
	void *extdata[HNCP_PA_EXTDATA_N];
	size_t extdata_len[HNCP_PA_EXTDATA_N];

	bool ipv4_uplink;

	//Configuration stored for this interface
	struct vlist_tree conf;
};

struct hpa_lease_struct {
	struct list_head le;
	char pa_link_name[DHCP_DUID_MAX_LENGTH + HPA_LINK_NAME_LEN];
	uint8_t hint_len;
	hpa_pd_cb cb;
	void *priv; //For storing your own stuff

	struct pa_link pal;
	struct pa_rule_random rule_rand;
	struct pa_store_rule rule_store;
};

typedef struct hpa_dp_struct {
	struct hncp_pa_dp dp;

#define HPA_DP_T_IFACE 0x1 //DP or local IPv4
#define HPA_DP_T_ULA   0x2 //Local ULA
#define HPA_DP_T_HNCP  0x3 //From another node
	struct pa_dp pa;

	//Backpointer to main hpa struct
	hncp_pa hpa;

	//DP valid and preferred lifetime
	hnetd_time_t valid_until;
	hnetd_time_t preferred_until;

	//DP associated dhcp info
	void *dhcp_data;
	size_t dhcp_len;

	//Type specific data
	union {
		struct {
			hpa_iface iface;
			bool excluded;
			struct prefix excluded_prefix;
			struct pa_rule_static excluded_rule;
		} iface;
		struct {

		} local;
		struct {
			dncp_node_identifier_s node_id;
			struct uloop_timeout delete_to;
		} hncp;
	};
} *hpa_dp, hpa_dp_s;

#define hpa_for_each_dp(hpa, dp_p) list_for_each_entry(dp_p, &(hpa)->dps, dp.le)

struct hncp_pa_struct {
	dncp dncp;
	dncp_subscriber_s dncp_user;

	struct iface_user iface_user;

	/* hncp_link helps us deciding who is on our link */
	struct hncp_link *hncp_link;
	struct hncp_link_user hncp_link_user;

	/* Main PA structures */
	struct pa_core pa;
	struct pa_user pa_user;
	struct pa_core aa;
	struct pa_user aa_user;

	/* Pa storage */
	struct pa_store store; //PA storage structure itself
	struct pa_store_bound store_pa_b; //Get events from aa
	struct pa_store_bound store_aa_b; //Get events from pa
	struct pa_store_rule store_pa_r;  //Configure pa
	struct pa_store_rule store_aa_r;  //Configure aa

	struct pa_link excluded_link; //Link used to exclude prefixes

	/* iface.c subscription callbacks */
	struct hncp_pa_iface_user *if_cbs;

	/* ULA configuration parameters */
	struct hncp_pa_ula_conf ula_conf;

	/* List of all available dps */
	struct list_head dps;

	/* All APs are linked here for fast iteration */
	struct list_head aps;

	/* List of ifaces known to hncp_pa */
	struct list_head ifaces;

	/* List of downstream PD leases */
	struct list_head leases;

	/* Tree containing the adjacent links provided by hncp_link.c */
	struct avl_tree adjacencies;

	/* IPv4 and ula delegated prefixes */
	struct uloop_timeout v4_to;
	bool v4_enabled;
	hpa_dp_s v4_dp;

	struct uloop_timeout ula_to;
	bool ula_enabled;
	hpa_dp_s ula_dp;
	hnetd_time_t ula_backoff;
};


#define APPEND_BUF(buf, len, ibuf, ilen)        \
do                                              \
  {                                             \
  if (ilen)                                     \
    {                                           \
      buf = realloc(buf, len + ilen);           \
      if (!buf)                                 \
        {                                       \
          L_ERR("oom gathering buf");           \
          goto oom;                             \
        }                                       \
      memcpy(buf + len, ibuf, ilen);            \
      len += ilen;                              \
    }                                           \
 } while(0)

#define SAME(d1,l1,d2,l2) \
  (l1 == l2 && (!l1 || (d1 && d2 && !memcmp(d1, d2, l1))))

#define REPLACE(d1,l1,d2,l2)    \
do                              \
  {                             \
    if (d1)                     \
      free(d1);                 \
    d1 = NULL;                  \
    l1 = 0;                     \
    if (l2 && (d1 = malloc(l2)))\
      {                         \
         l1 = l2;               \
         memcpy(d1, d2, l2);    \
      }                         \
  } while(0)


hnetd_time_t _remote_rel_to_local_abs(hnetd_time_t base, uint32_t netvalue)
{
	if (netvalue == UINT32_MAX)
		return HNETD_TIME_MAX;
	return base + be32_to_cpu(netvalue);
}

static uint32_t _local_abs_to_remote_rel(hnetd_time_t now, hnetd_time_t v)
{
	if (v == HNETD_TIME_MAX)
		return cpu_to_be32(UINT32_MAX);
	if (now > v)
		return 0;
	hnetd_time_t delta = v - now;
	/* Convert to infinite if it would overflow too. */
	if (delta >= UINT32_MAX)
		return cpu_to_be32(UINT32_MAX);
	return cpu_to_be32(delta);
}

static int hpa_ifconf_comp(const void *k1, const void *k2, __unused void *ptr)
{
	const hpa_conf_s *e1 = k1, *e2 = k2;
	int i;
	if((i = ((int)e1->type - (int)e2->type)))
		return i;

	switch (e1->type) {
		case HPA_CONF_T_PREFIX: //One entry per prefix
			return prefix_cmp(&e1->prefix.prefix, &e2->prefix.prefix);
		case HPA_CONF_T_ADDR: //One netry per address
			if((i = (int)e1->addr.mask - (int)e2->addr.mask) ||
					(i = prefix_cmp(&e1->addr.filter, &e2->addr.filter)) ||
					(i = memcmp(&e1->addr, &e2->addr, sizeof(e1->addr))))
				return i;
			return 0;
		case HPA_CONF_T_LINK_ID:
			if((i = (int)e1->link_id.mask - (int)e2->link_id.mask) ||
					(i = (int)e1->link_id.mask - (int)e2->link_id.mask))
				return i;
			return 0;
		case HPA_CONF_T_IP4_PLEN:
		case HPA_CONF_T_IP6_PLEN:
		default:
			return 0; //Only one entry is allowed for these types
	}
}


static void hpa_ap_iface_notify(__unused hncp_pa hpa,
		struct pa_ldp *ldp, struct pa_ldp *addr_ldp)
{
	hpa_iface i = container_of(ldp->link, hpa_iface_s, pal);
	hpa_dp dp = container_of(ldp->dp, hpa_dp_s, pa);
	if(hpa->if_cbs)
		hpa->if_cbs->update_address(hpa->if_cbs, i->ifname,
				(struct in6_addr *)&addr_ldp->prefix, ldp->plen,
				dp->valid_until, dp->preferred_until,
				dp->dhcp_data, dp->dhcp_len,
				!addr_ldp->applied);
}

static void hpa_ap_pd_notify(__unused hncp_pa hpa, struct pa_ldp *ldp)
{
	hnetd_time_t valid, pref;
	hpa_lease l = container_of(ldp->link, hpa_lease_s, pal);
	hpa_dp dp = container_of(ldp->dp, hpa_dp_s, pa);
	if(ldp->applied) {
		valid = dp->valid_until;
		pref = dp->preferred_until;
	} else if(ldp->assigned) {
		hnetd_time_t max = hnetd_time() + HNCP_PA_PD_TEMP_LEASE;
		valid = (dp->valid_until > max)?max:dp->valid_until;
		pref = (dp->preferred_until > max)?max:dp->preferred_until;
	} else {
		valid = 0;
		pref = 0;
	}

	if(l->cb)
		l->cb(&ldp->prefix, ldp->plen,
				valid, pref, dp->dhcp_data, dp->dhcp_len, l->priv);
}

static hpa_iface hpa_get_adjacent_iface(hncp_pa hpa, dncp_t_link_id id)
{
	hpa_adjacency adj;
	adj = avl_find_element(&hpa->adjacencies, id, adj, te);
	return adj?adj->iface:NULL;
}

#endif /* HNCP_PA_I_H_ */
