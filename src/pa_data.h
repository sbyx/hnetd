/*
 * pa_data.h
 *
 * Author: Pierre Pfister
 *
 * Prefix assignment database.
 *
 * This file provides database structures for the
 * prefix assignment algorithm.
 *
 */

#ifndef PA_DATA_H
#define PA_DATA_H

#include <libubox/avl.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "hnetd.h"
#include "prefix_utils.h"

/* Router ID */
struct pa_rid {
#define PA_RIDLEN 16
	uint8_t id[PA_RIDLEN];

#define PA_RIDCMP(r1, r2) memcmp((r1)->id, (r2)->id, PA_RIDLEN)
#define PA_RIDCPY(dst, src) memcpy((dst)->id, (src)->id, PA_RIDLEN)
#define PA_RID_L		"%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x:%02x%02x%02x%02x"
#define PA_RID_LA(rid)  (rid)->id[0], (rid)->id[1], (rid)->id[2], (rid)->id[3], \
		(rid)->id[4], (rid)->id[5], (rid)->id[6], (rid)->id[7], \
		(rid)->id[8], (rid)->id[9], (rid)->id[10], (rid)->id[11], \
		(rid)->id[12], (rid)->id[13], (rid)->id[15], (rid)->id[15]
};

/* Interface */
struct pa_iface {
	struct list_head le;   /* Linked in pa_data's ifaces list */
	char ifname[IFNAMSIZ]; /* Interface name */

	bool internal;         /* Whether the iface is internal */
	bool designated;       /* Whether router is designated on that iface. */
	bool do_dhcp;          /* Whether router should do dhcp on that iface. */

	struct list_head aps;   /* assigned prefixes on that iface */
	struct list_head cps;   /* chosen prefixes on that iface */

#define PA_IFNAME_L  "%s"
#define PA_IFNAME_LA(iface) (iface)?(iface)->ifname:"no-iface"

#define PA_IF_L 	    "iface '"PA_IFNAME_L"'"
#define PA_IF_LA(iface)	PA_IFNAME_LA(iface)
};

/* Delegated prefix generic element. */
struct pa_dp {
	struct list_head le;          /* Linked in pa_data's lists */
	struct prefix prefix;         /* The delegated prefix */
	hnetd_time_t valid_until;     /* Valid until (zero means not valid) */
	hnetd_time_t preferred_until; /* Preferred until */
	size_t dhcp_len;              /* dhcp data length (or 0) */
	void *dhcp_data;     	      /* dhcp data (or NULL) */
	struct list_head cps;         /* cps that are associated to that dp */
	bool local;                   /* Whether it is ldp or edp */

#define PA_DP_L			"dp %s(local=%d)"
#define PA_DP_LA(dp)	PREFIX_REPR(&(dp)->prefix), (dp)->local
};

/* DPs made by others */
struct pa_edp {
	struct pa_dp dp;
	struct pa_rid rid;            /* Source rid */
};

/* Local dps */
struct pa_ldp {
	struct pa_dp dp;
	struct {
		bool valid;
		struct prefix excluded;
		struct pa_cp *cp;
	} excluded;
};

struct pa_ap {
	struct avl_node avl_node; /* Put in pa_data's ap tree */
	struct prefix prefix;	  /* The assigned prefix */
	struct pa_rid rid;        /* Sender's router id */

	bool authoritative;           /* Authority bit */
	uint8_t priority;         /* Priority value */

	struct pa_iface *iface;   /* Iface for that cp or null if no interface */
	struct list_head if_le;   /* Linked in iface list */

#define PA_AP_L         "ap %s%%"PA_IFNAME_L" from "PA_RID_L" priority %d:%d"
#define PA_AP_LA(ap)    PREFIX_REPR(&(ap)->prefix), PA_IFNAME_LA((ap)->iface), PA_RID_LA(&(ap)->rid), !!(ap)->authoritative, (ap)->priority
};

struct pa_cp {
	struct list_head le;      /* Put in pa_data's cp list */
	struct prefix prefix;	  /* The assigned prefix */

	bool advertised;          /* Whether it was given to the flooding protocol */
	bool applied;             /* Whether it was applied */
	bool authoritative;       /* Whether that assignment is authoritative */
	uint8_t priority;         /* Assignment's priority */

	bool invalid;             /* Used by pa algo */

	struct pa_iface *iface;   /* Iface for that cp or null if no interface */
	struct list_head if_le;   /* Linked in iface list */

	struct pa_dp *dp;         /* The dp associated to that cp */
	struct list_head dp_le;   /* Linked in dp's list */

	struct pa_data *pa_data;        /* Need that because of timeout callback */
	struct uloop_timeout apply_to;  /* When to apply the prefix */

	struct pa_laa *laa;       /* A local address assignment for the router */

#define PA_CP_L         "cp %s%%"PA_IFNAME_L" priority %d:%d  state |%s|%s|"
#define PA_CP_LA(cp)    PREFIX_REPR(&(cp)->prefix), PA_IFNAME_LA((cp)->iface), !!(cp)->authoritative, (cp)->priority, \
	((cp)->advertised)?"adv.":"not adv.", ((cp)->applied)?"app.":"not app."
};

/* Address assignment */
struct pa_aa {
	struct in6_addr address;  /* The assigned address */

	bool local;               /* Whether it is a laa or eaa */

#define PA_AA_L         "aa %s (local=%d)"
#define PA_AA_LA(aa)    (aa)?ADDR_REPR(&(aa)->address):"NULL",!!(aa)->local
};

/* Internal AA */
struct pa_laa {
	struct pa_aa aa;
	struct pa_cp *cp;              /* The associated cp */
	bool applied;                  /* Whether it was applied */
	struct uloop_timeout apply_to; /* When to apply the prefix */
	bool invalid;
};

/* External AA */
struct pa_eaa {
	struct pa_aa aa;
	struct pa_rid rid;
	struct list_head le;      /* Put in pa_data's eaa list */
};

struct pa_data {
	struct list_head ifs;  /* Ifaces */
	struct list_head dps;  /* Delegated prefixes */
	struct avl_tree  aps;  /* Assigned prefixes */
	struct list_head  cps;  /* Chosen prefixes */
	struct list_head eaas; /* Externally Address assignments */
};

#define PA_SET_SCALAR(var, new) \
	(((var)==(new))?(0):(((var) = (new)) || 1))

void pa_data_init(struct pa_data *);
void pa_data_term(struct pa_data *);

#define pa_for_each_iface(pa_iface, pa_data) \
	list_for_each_entry(pa_iface, &(pa_data)->ifs, le)
struct pa_iface *pa_iface_get(struct pa_data *, const char *ifname, bool *created);
#define pa_iface_set_internal(iface, intern) PA_SET_SCALAR((iface)->internal, intern)
#define pa_iface_set_designated(iface, design) PA_SET_SCALAR((iface)->designated, design)
#define pa_iface_set_dodhcp(iface, dodhcp) PA_SET_SCALAR((iface)->do_dhcp, dodhcp)
void pa_iface_destroy(struct pa_data *, struct pa_iface *);



#define pa_for_each_dp(pa_dp, pa_data) \
	list_for_each_entry(pa_dp, &(pa_data)->dps, le)
int pa_dp_set_dhcp(struct pa_dp *, const void *dhcp_data, size_t dhcp_len);
int pa_dp_set_lifetime(struct pa_dp *, hnetd_time_t preferred, hnetd_time_t valid);



#define pa_for_each_ldp_in_iface(pa_ldp, pa_iface) \
	list_for_each_entry(pa_ldp, &(pa_iface)->ldps, if_le)
struct pa_ldp *pa_ldp_get(struct pa_data *, const struct prefix *, bool *created);
int pa_ldp_set_excluded(struct pa_ldp *, const struct prefix *excluded);
void pa_ldp_destroy(struct pa_ldp *);



struct pa_edp *pa_edp_get(struct pa_data *, const struct prefix *, const struct pa_rid *rid, bool *created);
void pa_edp_destroy(struct pa_edp *);



#define pa_for_each_ap(pa_ap, pa_data) \
		avl_for_element_range(avl_first_element(&(pa_data)->aps, pa_ap, avl_node), \
		                        avl_last_element(&(pa_data)->aps, pa_ap,  avl_node), \
		                        pa_ap, avl_node)
#define pa_for_each_ap_in_iface(pa_ap, pa_iface) \
	list_for_each_entry(pa_ap, &(pa_iface)->aps, if_le)
struct pa_ap *pa_ap_get(struct pa_data *, const struct prefix *, const struct pa_rid *rid, bool *created);
int pa_ap_set_iface(struct pa_ap *ap, struct pa_iface *iface);
#define pa_ap_set_priority(ap, prio) PA_SET_SCALAR((ap)->priority, prio)
#define pa_ap_set_authoritative(ap, auth) PA_SET_SCALAR((ap)->authoritative, auth)
void pa_ap_destroy(struct pa_data *, struct pa_ap *);


#define pa_for_each_cp(pa_cp, pa_data) \
		list_for_each_entry(pa_cp, &(pa_data)->cps, le)
#define pa_for_each_cp_in_iface(pa_cp, pa_iface) \
	list_for_each_entry(pa_cp, &(pa_iface)->cps, if_le)
#define pa_for_each_cp_in_dp(pa_cp, pa_dp) \
	list_for_each_entry(pa_cp, &(pa_dp)->cps, dp_le)
struct pa_cp *pa_cp_get(struct pa_data *, const struct prefix *, bool *created);
int pa_cp_set_iface(struct pa_cp *, struct pa_iface *);
int pa_cp_set_address(struct pa_cp *, const struct in6_addr *);
int pa_cp_set_dp(struct pa_cp *, struct pa_dp *dp);
#define pa_cp_set_priority(cp, prio) PA_SET_SCALAR((cp)->priority, prio)
#define pa_cp_set_authoritative(cp, auth) PA_SET_SCALAR((cp)->authoritative, auth)
#define pa_cp_set_advertised(cp, adv) PA_SET_SCALAR((cp)->advertised, adv)
#define pa_cp_set_applied(cp, appl) PA_SET_SCALAR((cp)->applied, appl)
void pa_cp_set_apply_timeout(struct pa_cp *, int msecs);
void pa_cp_destroy(struct pa_cp *);

void pa_laa_set_apply_timeout(struct pa_laa *, int msecs);
#define pa_laa_set_applied(laa, appl) PA_SET_SCALAR((laa)->applied, appl)


#define pa_for_each_eaa(pa_eaa, pa_data) \
		list_for_each_entry(pa_eaa, &(pa_data)->eaas, le)
struct pa_eaa *pa_eaa_get(struct pa_data *, const struct in6_addr *, const struct pa_rid *, bool *created);
void pa_eaa_destroy(struct pa_eaa *);


#endif





