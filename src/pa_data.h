/*
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

#include "hnetd.h"
#include "prefix_utils.h"

/* Router ID */
struct pa_rid {
#define PA_RIDLEN 16
	uint8_t id[PA_RIDLEN];

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
	bool designated;       /* Whether we are designated router. */
	bool do_dhcp;          /* Whether we should do dhcp on this interface */

	struct list_head aps;   /* aps on that iface */
	struct list_head cps;   /* cps on that iface */
	struct list_head ldps;  /* ldps on that iface */
	struct list_head aas;   /* laas on that iface */

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
	hnetd_time_t preferred_until;
	struct list_head cps;         /* cps attached to that prefix */
	size_t dhcp_len;              /* dhcp data length (or 0) */
	void *dhcp_data;     	      /* dhcp data (or NULL) */
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
	struct pa_iface *iface;       /* Delegating side iface */
	struct list_head if_le;       /* When iface is not null, this is linked in iface dps */
	struct pa_cp *cp;             /* The excluded prefix cp (or null). */
};

struct pa_ap {
	struct list_head le;      /* Put in pa_data's cp list */
	struct prefix prefix;	  /* The assigned prefix */
	struct pa_rid rid;        /* Sender's router id */

	bool authority;           /* Authority bit */
	uint8_t priority;         /* Priority value */

	struct pa_iface *iface;   /* Iface for that cp or null if no interface */
	struct list_head if_le;   /* Linked in iface list */


#define PA_AP_L         "ap %s%%"PA_IFNAME_L" from "PA_RID_L" priority %d:%d"
#define PA_AP_LA(ap)    PREFIX_REPR(&(ap)->prefix), PA_IFNAME_LA((ap)->iface), PA_RID_LA(&(ap)->rid), !!(ap)->authority, (ap)->priority
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

	struct pa_dp *dp;		  /* The used delegated prefix*/
	struct list_head dp_le;   /* Linked in dp list */

	struct pa_data *pa_data;     /* Need that because of timeout callback */
	struct uloop_timeout apply;  /* When to apply the prefix */

	struct pa_aa *aa;         /* A local address assignment for the router */

#define PA_CP_L         "cp %s%%"PA_IFNAME_L" priority %d:%d  state |%s|%s|"
#define PA_CP_LA(cp)    PREFIX_REPR(&(cp)->prefix), PA_IFNAME_LA((cp)->iface), !!(cp)->authority, (cp)->priority, \
	((cp)->advertised)?"adv.":"not adv.", ((cp)->assigned)?"app.":"not app."
};

/* Address assignment */
struct pa_aa {
	struct list_head le;      /* Put in pa_data's aa list */
	struct prefix address;    /* The assigned address */

	struct pa_iface *iface;   /* Iface for that cp */
	struct list_head if_le;   /* Linked in iface list */

	bool local;               /* Whether it is a laa or eaa */

#define PA_AA_L         "aa %s%%"PA_IFNAME_L" %s"
#define PA_AA_LA(aa)    PREFIX_REPR(&(aa)->prefix), PA_IFNAME_LA((aa)->iface)
};

/* Internal AA */
struct pa_laa {
	struct pa_aa aa;
	bool applied;               /* Whether it was applied */
	struct uloop_timeout apply; /* When to apply the prefix */
};

/* External AA */
struct pa_eaa {
	struct pa_aa aa;
	struct pa_rid rid;
};

/* Prefix assignment's data structure */
struct pa_data {
	struct list_head ifs; /* Ifaces */
	struct list_head dps; /* Delegated prefixes */
	struct avl_tree  aps; /* Assigned prefixes */
	struct list_head cps; /* Chosen prefixes */
	struct list_head aas; /* Address assignments */
};


void pa_data_init(struct pa_data *);

#define pa_for_each_dp(pa_data, pa_dp) \
	list_for_each_entry(pa_dp, &(pa_data)->dps, le)
/* Sets dhcp data. Returns 1 if modified. -1 if error. 0 Otherwise. */
int pa_dp_set_dhcp(struct pa_dp *, const void *dhcp_data, size_t dhcp_len);
/* Returns an existing ldp with the specified prefix, or NULL. */
struct pa_ldp *pa_ldp_get(struct pa_data *, const struct prefix *);
/* Returns an existing or creating ldp, or NULL if error. */
struct pa_ldp *pa_ldp_goc(struct pa_data *, const struct prefix *);
/* Set iface and return whether it was modified. */
int pa_ldp_set_iface( struct pa_ldp *, struct pa_iface *);
/* Destroyes ldp entry and unlinks it from other structures. */
void pa_ldp_destroy(struct pa_data *, struct pa_ldp *);




#endif





