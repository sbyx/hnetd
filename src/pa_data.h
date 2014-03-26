/*
 * pa_data.h
 *
 * Author: Pierre Pfister
 *
 * Prefix assignment database.
 *
 * pa_data.* provide database structure and notification
 * callbacks for prefix assignment's related entities.
 * Subscribers are notified whenever an event concerning
 * an type of element they subscribed to occur. A flag field
 * is provided to explain the nature of the event.
 *
 * Whenever modifying an object, the user should call the
 * corresponding notify function. It will notify subscribed users.
 *
 * DO NOT MODIFY THE CURRENTLY NOTIFIED OBJECT
 * It should not happen given the program architecture, but may happen in some
 * cases.
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

#define PAD_FLOOD_DELAY_DEFAULT     5000
#define PAD_FLOOD_DELAY_LL_DEFAULT  1000
#define PAD_FLOOD_AA_LL_ENABLED_DEFAULT false

#define PAD_CONF_DFLT_MAX_SP      100
#define PAD_CONF_DFLT_MAX_SP_P_IF 10
#define PAD_CONF_DFLT_MAX_SA      40

#define PAD_PRIORITY_DEFAULT 8

/* Modification flags */
#define PADF_ALL_CREATED  0x0001
#define PADF_ALL_TODELETE 0x0002
#define PADF_ALL_ERROR    0x0004
#define PADF_ALL_IFACE    0x0008
#define PADF_ALL_DHCP     0x0010

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
	bool do_dhcp;          /* Whether router should do dhcp on that iface. */

	struct list_head aps;   /* assigned prefixes on that iface */
	struct list_head cpls;/* chosen prefixes on that iface */
	struct list_head ldps;  /* ldps on that iface */
	struct list_head eaas;  /* eaas on that iface */

	size_t sp_count;
	struct list_head sps;   /* stored prefixes for that iface */

	bool designated;        /* Used by paa. */
	bool ipv4_uplink;       /* Whether this iface is the ipv4 uplink - used by pa.c */

	uint32_t prand_ctr[2];  /* Pseudo random counters used for prefix and address generation */

#define PADF_IF_CREATED  PADF_ALL_CREATED
#define PADF_IF_TODELETE PADF_ALL_TODELETE
#define PADF_IF_INTERNAL 0x0100
#define PADF_IF_DODHCP   0x0200
	uint32_t __flags;

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

#define PADF_DP_CREATED   PADF_ALL_CREATED
#define PADF_DP_TODELETE  PADF_ALL_TODELETE
#define PADF_LDP_IFACE    PADF_ALL_IFACE
#define PADF_DP_ERROR     PADF_ALL_ERROR    /* In case dhcp malloc fails */
#define PADF_DP_DHCP      PADF_ALL_DHCP
#define PADF_DP_LIFETIME  0x0100
#define PADF_LDP_EXCLUDED 0x0200
	uint32_t __flags;

#define PA_DP_L			"dp %s(local=%d)"
#define PA_DP_LA(dp)	PREFIX_REPR(&(dp)->prefix), (int)(dp)->local
};

/* Delegated prefix advertised by somebody else */
struct pa_edp {
	struct pa_dp dp;
	struct pa_rid rid;            /* Source rid */
	struct uloop_timeout timeout; /* Used by flooding in order to delay removal */
	struct pa_data *data;         /* Private to the timeout user */
};

/* Delegated prefix advertised locally */
struct pa_ldp {
	struct pa_dp dp;
	struct pa_iface *iface;       /* Iface for that dp or null if no interface */
	struct list_head if_le;       /* Linked in iface list */
	struct {
		bool valid;
		struct prefix excluded;
		struct pa_cpx *cpx;
	} excluded;
};

struct pa_ap {
	struct avl_node avl_node; /* Put in pa_data's ap tree */
	struct prefix prefix;	  /* The assigned prefix */
	struct pa_rid rid;        /* Sender's router id */

	bool authoritative;       /* Authority bit */
	uint8_t priority;         /* Priority value */

	struct pa_iface *iface;   /* Iface for that cp or null if no interface */
	struct list_head if_le;   /* If iface not null, linked in iface's interface */

#define PADF_AP_CREATED   PADF_ALL_CREATED
#define PADF_AP_TODELETE  PADF_ALL_TODELETE
#define PADF_AP_IFACE     PADF_ALL_IFACE
#define PADF_AP_AUTHORITY 0x0100
#define PADF_AP_PRIORITY  0x0200
	uint32_t __flags;

#define PA_AP_L         "ap %s%%"PA_IFNAME_L" from "PA_RID_L" priority %d:%d"
#define PA_AP_LA(ap)    PREFIX_REPR(&(ap)->prefix), PA_IFNAME_LA((ap)->iface), PA_RID_LA(&(ap)->rid), !!(ap)->authoritative, (ap)->priority
};

/* Generic part of chosen prefixes structure.
 * That generic part is used for:
 * 1) Check for assignment's validity
 * 2) Advertise assignments
 * A chosen prefix MUST always be part of an existing delegated prefix. */
struct pa_cp {
	struct list_head le;      /* Put in pa_data's cp list */
	struct prefix prefix;	  /* The assigned prefix */

	bool advertised;          /* Whether it must be advertised */
	bool applied;             /* Whether it was applied */
	bool authoritative;       /* Whether that assignment is authoritative */
	uint8_t priority;         /* The assignment priority */

	/* A chosen prefix is -most of the time- associated to a dp.
	 * During short lapses of time, it may be NULL. But it has to be
	 * updated shortly. */
	struct pa_dp *dp;         /* The dp associated to that cp */
	struct list_head dp_le;   /* Linked in dp's list */

	struct pa_data *pa_data;        /* Used by pa algo */
	struct uloop_timeout apply_to;  /* Used by pa algo */

	enum pa_cp_type {
		PA_CPT_ANY,		/* NO TYPE - ONLY IN FUNCTION CALL */
		PA_CPT_L,		/* Assignment made on some link */
		PA_CPT_X,		/* Assignment made to exclude it */
		PA_CPT_D		/* Assignment made to give it */
	} type;

#define PADF_CP_CREATED   PADF_ALL_CREATED
#define PADF_CP_TODELETE  PADF_ALL_TODELETE
#define PADF_CP_ERROR     PADF_ALL_ERROR    /* In case address malloc fails */
#define PADF_CP_IFACE     PADF_ALL_IFACE    /* Not really usefull cause iface should not change in cpl */
#define PADF_CP_AUTHORITY 0x0100
#define PADF_CP_PRIORITY  0x0200
#define PADF_CP_ADVERTISE 0x0400
#define PADF_CP_APPLIED   0x0800
#define PADF_CP_DP        0x1000
	uint32_t __flags;

#define PA_CP_TYPE(type)  ((type == PA_CPT_L)?"Assignment":((type == PA_CPT_X)?"Excluded":"Delegated" ))
#define PA_CP_L         "cp(%s) %s priority %d:%d  state |%s|%s|"
#define PA_CP_LA(cp)    PA_CP_TYPE((cp)->type), PREFIX_REPR(&(cp)->prefix), !!(cp)->authoritative, (cp)->priority, \
	((cp)->advertised)?"adv.":"not adv.", ((cp)->applied)?"app.":"not app."
};

/* Chosen prefix for local assignment.
 * Such struct MUST have an interface specified.
 * It represents an assignment on some interface that must be
 * acted upon by creating a localy assigned address.
 * It is managed by pa_core.c */
struct pa_cpl {
	struct pa_cp cp;
	struct pa_iface *iface;   /* Iface for that cp or null if no interface */
	struct list_head if_le;   /* Linked in iface list */
	struct pa_laa *laa;       /* A local address assignment for the router */
	bool invalid;             /* Used by pa algo */
};

/* Chosen prefix for exclusion
 * Created and managed by pa_core.c, it only intends
 * to prevent prefix use.
 * It is not associated to any particular interface. */
struct pa_cpx {
	struct pa_cp cp;
};

/* Chosen prefix for Prefix Delegation
 * This chosen prefix allows PD in the home.
 * It is not associated to any particular interface.
 * It is managed by pa_pd.c */
struct pa_cpd {
	struct pa_cp cp;
	struct list_head lease_le;
	struct pa_pd_lease *lease;
};

/* Address assignment */
struct pa_aa {
	struct in6_addr address;  /* The assigned address */

	bool local;               /* Whether it is a laa or eaa */

#define PADF_AA_CREATED   PADF_ALL_CREATED
#define PADF_AA_TODELETE  PADF_ALL_TODELETE
#define PADF_EAA_IFACE    PADF_ALL_IFACE
#define PADF_LAA_APPLIED  0x0100
	uint32_t __flags;

#define PA_AA_L         "aa %s (local=%d)"
#define PA_AA_LA(aa)    (aa)?ADDR_REPR(&(aa)->address):"NULL",!!(aa)->local
};

/* Internal AA */
struct pa_laa {
	struct pa_aa aa;
	struct pa_cpl *cpl;          /* The associated cp */
	bool applied;                  /* Whether it was applied */

	struct uloop_timeout apply_to; /* Used by pa algo */
};

/* External AA */
struct pa_eaa {
	struct pa_aa aa;
	struct pa_rid rid;
	struct list_head le;      /* Put in pa_data's eaa list */
	struct pa_iface *iface;   /* An associated iface */
	struct list_head if_le;   /* When iface not null, put in iface's list */
};

struct pa_flood {
	struct pa_rid rid;
	hnetd_time_t flooding_delay;
	hnetd_time_t flooding_delay_ll;
	bool aa_ll_enabled; /* Assigned addresses are flooded link locally. Default is false. */

#define PADF_FLOOD_RID   0x0100
#define PADF_FLOOD_DELAY 0x0200
	uint32_t __flags;
};

struct pa_ipv4 {
	struct pa_iface *iface;
	void *dhcp_data;
	size_t dhcp_len;

#define PADF_IPV4_IFACE  PADF_ALL_IFACE
#define PADF_IPV4_ERROR  PADF_ALL_ERROR  /* If dhcp malloc fails */
#define PADF_IPV4_DHCP   PADF_ALL_DHCP
	uint32_t __flags;
};

/* A stored prefix. No notification system for that structure. */
struct pa_sp {
	struct list_head le;
	struct prefix prefix;
	struct pa_iface *iface;       /* Iface for that sp or null if no interface */
	struct list_head if_le;       /* Linked in iface list */

#define PA_SP_L         "sp %s%%"PA_IFNAME_L
#define PA_SP_LA(sp)    PREFIX_REPR(&(sp)->prefix), PA_IFNAME_LA((sp)->iface)
};

/* A stored address. No notification system for that structure. */
struct pa_sa {
	struct list_head le;
	struct in6_addr addr;

#define PA_SA_L         "sa %s"
#define PA_SA_LA(sp)    ADDR_REPR(&(sa)->addr)
};

struct pa_data_conf {
	/* Maximum number of stored prefixes (dflt = 100) */
	size_t max_sp;
	/* Maximum number of stored prefixes per interface (dflt = 10) */
	size_t max_sp_per_if;
	/* Maximum number of stored addresses (dflt = 20) */
	size_t max_sa;
};

struct pa_data {
	struct pa_data_conf conf; /* pa_data configuration */

	struct pa_flood  flood; /* Information from flooding */
	struct pa_ipv4   ipv4;  /* IPv4 global connectivity */
	struct list_head ifs;   /* Ifaces */
	struct list_head dps;   /* Delegated prefixes */
	struct avl_tree  aps;   /* Assigned prefixes */
	struct list_head cps;   /* Chosen prefixes */
	struct list_head eaas;  /* Externally Address assignments */
	struct list_head users; /* List of subscribed users */

	size_t sp_count;
	struct list_head sps;   /* Stored prefixes */

	size_t sa_count;
	struct list_head sas;   /* Stored addresses */
};

/* Subscription to data events */
struct pa_data_user {
	struct list_head le;
	void (*flood)(struct pa_data_user *, struct pa_flood *, uint32_t flags);
	void (*ipv4)(struct pa_data_user *, struct pa_ipv4 *, uint32_t flags);
	void (*ifs)(struct pa_data_user *, struct pa_iface *, uint32_t flags);
	void (*dps)(struct pa_data_user *, struct pa_dp *, uint32_t flags);
	void (*aps)(struct pa_data_user *, struct pa_ap *, uint32_t flags);
	void (*cps)(struct pa_data_user *, struct pa_cp *, uint32_t flags);
	void (*aas)(struct pa_data_user *, struct pa_aa *, uint32_t flags);
};

void pa_data_conf_defaults(struct pa_data_conf *);
void pa_data_init(struct pa_data *, const struct pa_data_conf *);
void pa_data_term(struct pa_data *);

void pa_flood_set_rid(struct pa_data *, const struct pa_rid *rid);
void pa_flood_set_flooddelays(struct pa_data *, hnetd_time_t delay, hnetd_time_t ll_delay);
void pa_flood_notify(struct pa_data *);

void pa_ipv4_set_uplink(struct pa_data *, struct pa_iface *iface);
void pa_ipv4_set_dhcp(struct pa_data *data, const void *dhcp_data, size_t dhcp_len);
void pa_ipv4_notify(struct pa_data *);

void pa_data_subscribe(struct pa_data *, struct pa_data_user *);
void pa_data_unsubscribe(struct pa_data_user *);

#define pa_for_each_iface(pa_iface, pa_data) list_for_each_entry(pa_iface, &(pa_data)->ifs, le)
struct pa_iface *pa_iface_get(struct pa_data *, const char *ifname, bool goc);
void pa_iface_set_internal(struct pa_iface *, bool internal);
void pa_iface_set_dodhcp(struct pa_iface *, bool dodhcp);
#define pa_iface_todelete(iface) (iface)->__flags |= PADF_IF_TODELETE
void pa_iface_notify(struct pa_data *, struct pa_iface *);


#define pa_for_each_dp(pa_dp, pa_data) list_for_each_entry(pa_dp, &(pa_data)->dps, le)
void pa_dp_set_dhcp(struct pa_dp *, const void *dhcp_data, size_t dhcp_len);
void pa_dp_set_lifetime(struct pa_dp *, hnetd_time_t preferred, hnetd_time_t valid);
#define pa_dp_todelete(dp) (dp)->__flags |= PADF_DP_TODELETE
void pa_dp_notify(struct pa_data *data, struct pa_dp *dp);


#define pa_for_each_ldp_in_iface(pa_ldp, pa_iface) list_for_each_entry(pa_ldp, &(pa_iface)->ldps, if_le)
struct pa_ldp *pa_ldp_get(struct pa_data *, const struct prefix *, bool goc);
void pa_ldp_set_excluded(struct pa_ldp *, const struct prefix *excluded);
void pa_ldp_set_iface(struct pa_ldp *, struct pa_iface *);

struct pa_edp *pa_edp_get(struct pa_data *, const struct prefix *, const struct pa_rid *rid, bool goc);

#define pa_for_each_ap(pa_ap, pa_data) \
		avl_for_element_range(avl_first_element(&(pa_data)->aps, pa_ap, avl_node), \
		                        avl_last_element(&(pa_data)->aps, pa_ap,  avl_node), \
		                        pa_ap, avl_node)
#define pa_for_each_ap_in_iface(pa_ap, pa_iface) list_for_each_entry(pa_ap, &(pa_iface)->aps, if_le)
struct pa_ap *pa_ap_get(struct pa_data *, const struct prefix *, const struct pa_rid *rid, bool goc);
void pa_ap_set_iface(struct pa_ap *ap, struct pa_iface *iface);
void pa_ap_set_priority(struct pa_ap *ap, uint8_t priority);
void pa_ap_set_authoritative(struct pa_ap *ap, bool authoritative);
#define pa_ap_todelete(ap) (ap)->__flags |= PADF_AP_TODELETE
void pa_ap_notify(struct pa_data *data, struct pa_ap *ap);


#define pa_for_each_cp(pa_cp, pa_data) list_for_each_entry(pa_cp, &(pa_data)->cps, le)
#define pa_for_each_cp_safe(pa_cp, cp2, pa_data) list_for_each_entry_safe(pa_cp, cp2, &(pa_data)->cps, le)
#define pa_for_each_cpl_in_iface(pa_cpl, pa_iface) list_for_each_entry(pa_cpl, &(pa_iface)->cpls, if_le)
#define pa_for_each_cp_in_dp(pa_cp, pa_dp) list_for_each_entry(pa_cp, &(pa_dp)->cps, dp_le)
#define _pa_cpl(_cp) ((struct pa_cpl *)((_cp && (_cp)->type == PA_CPT_L)?container_of(_cp, struct pa_cpl, cp):NULL))
#define _pa_cpx(_cp) ((struct pa_cpx *)((_cp && (_cp)->type == PA_CPT_X)?container_of(_cp, struct pa_cpx, cp):NULL))
#define _pa_cpd(_cp) ((struct pa_cpd *)((_cp && (_cp)->type == PA_CPT_D)?container_of(_cp, struct pa_cpd, cp):NULL))
struct pa_cp *pa_cp_get(struct pa_data *, const struct prefix *, uint8_t type, bool goc);
void pa_cpl_set_iface(struct pa_cpl *, struct pa_iface *iface);
void pa_cp_set_dp(struct pa_cp *, struct pa_dp *dp);
void pa_cp_set_priority(struct pa_cp *, uint8_t priority);
void pa_cp_set_authoritative(struct pa_cp *, bool authoritative);
void pa_cp_set_advertised(struct pa_cp *, bool adv);
void pa_cp_set_apply_to(struct pa_cp *, hnetd_time_t delay);
void pa_cp_set_applied(struct pa_cp *, bool applied);
#define pa_cp_todelete(cp) (cp)->__flags |= PADF_CP_TODELETE
void pa_cp_notify(struct pa_cp *);

#define pa_aa_todelete(aa) (aa)->__flags |= PADF_AA_TODELETE
void pa_aa_notify(struct pa_data *, struct pa_aa *);

struct pa_laa *pa_laa_create(const struct in6_addr *, struct pa_cpl *);
void pa_laa_set_applied(struct pa_laa *, bool applied);
void pa_laa_set_apply_to(struct pa_laa *laa, hnetd_time_t delay);

#define pa_for_each_eaa(pa_eaa, pa_data) \
		list_for_each_entry(pa_eaa, &(pa_data)->eaas, le)
#define pa_for_each_eaa_in_iface(pa_eaa, pa_iface) \
		list_for_each_entry(pa_eaa, &(pa_iface)->eaas, if_le)
struct pa_eaa *pa_eaa_get(struct pa_data *, const struct in6_addr *, const struct pa_rid *, bool goc);
void pa_eaa_set_iface(struct pa_eaa *, struct pa_iface *);

#define pa_for_each_sp_reverse(pa_sp, pa_data) \
	list_for_each_entry_reverse(pa_sp, &(pa_data)->sps, le)
#define pa_for_each_sp_in_iface(pa_sp, pa_iface) \
	list_for_each_entry(pa_sp, &(pa_iface)->sps, if_le)
struct pa_sp *pa_sp_get(struct pa_data *, struct pa_iface *, const struct prefix *p, bool goc);
void pa_sp_promote(struct pa_data *, struct pa_sp *);

#define pa_for_each_sa(pa_sa, pa_data) \
	list_for_each_entry(pa_sa, &(pa_data)->sas, le)
#define pa_for_each_sa_reverse(pa_sa, pa_data) \
	list_for_each_entry_reverse(pa_sa, &(pa_data)->sas, le)
struct pa_sa *pa_sa_get(struct pa_data *, const struct in6_addr *addr, bool goc);
void pa_sa_promote(struct pa_data *, struct pa_sa *);

#endif





