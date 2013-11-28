#include "pa.h"

#include <stdlib.h>
#include <string.h>
#include <libubox/list.h>
#include <libubox/avl.h>

/* Different algorithm flavours */
#define PA_ALGO_ARKKO	0
#define PA_ALGO_PFISTER	1

#define PA_ALGO PA_ALGO_PFISTER

#ifndef PA_ALGO
#error "No prefix assignment algorithm defined"
#elif (PA_ALGO > 1 && PA_ALGO < 0)
#error "Invalid prefix assignment algorithm"
#endif

/* Logs */
#define PA_L_LEVEL 7
#define PA_L_PX "PA: "
#ifdef PA_L_LEVEL
#ifdef L_LEVEL
	#undef L_LEVEL
#endif
	#define L_LEVEL PA_L_LEVEL
#endif

/* #of ms waiting when we want immediate pa run */
#define PA_SCHEDULE_RUNNEXT_MS  10

#define PA_MAX_RANDOM_ROUNDS	20

#define PA_RIDCMP(r1, r2) memcmp(r1, r2, PA_RIDLEN)

#define PA_CONF_DFLT_COMMIT_LAP_DELAY  20

#define PA_CONF_DFLT_USE_ULA             1
#define PA_CONF_DFLT_NO_ULA_IF_V6        1
#define PA_CONF_DFLT_USE_V4              1
#define PA_CONF_DFLT_NO_V4_IF_V6         0
#define PA_CONF_DFLT_USE_RDM_ULA         1

#define PA_CONF_DFLT_IFACE_REGISTER      iface_register_user
#define PA_CONF_DFLT_IFACE_UNREGISTER      iface_unregister_user

/* 10/8 */
static struct prefix PA_CONF_DFLT_V4 = {
	.prefix = { .s6_addr = {
			0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
			0x00,0x00, 0xff,0xff,  0x0a }},
	.plen = 104 };

/* PA's interface structure.
 * We don't only care about internal because hcp could
 * possibly provide eaps on external interfaces. */
struct pa_iface {
	struct list_head le;   /* Linked in pa's ifaces list */
	char ifname[IFNAMSIZ]; /* Interface name */

	bool internal;         /* Whether the iface is internal */
	bool do_dhcp;          /* Whether we should do dhcp on that
	                          iface. Which means we are owner of that link. */

	struct list_head laps; /* laps on that iface */
	struct list_head eaps; /* eaps on that iface */
};

/* Locally assigned prefix */
struct pa_lap {
	struct avl_node avl_node; /* Put in pa's lap tree */
	struct prefix prefix;	  /* The assigned prefix */

	struct pa_iface *iface;   /* Iface for that lap */
	struct list_head if_le;   /* Linked in iface list */

	struct pa_dp *dp;		  /* The used delegated prefix*/
	struct list_head dp_le;   /* Linked in dp list */

	struct pa *pa;            /* Need that because of timeout callback */

	bool flooded;             /* Whether it was given to hcp */
	bool assigned;            /* Whether it was assigned */

	/* Used by pa algo. marked true before running.
	 * Checked against at the end of pa algo. */
	bool invalid;

	/* Whether we are the one that is currently owner
	 * of that assignment (only one per link) */
	bool own;

	/* Delayed actions */
	hnetd_time_t delayed_delete_time; /* When to delete or zero */

	bool delayed_flooding; /* Value to set to flood */
	hnetd_time_t delayed_flooding_time; /* When or zero */

	bool delayed_assign; /* Value to set to assign*/
	hnetd_time_t delayed_assign_time; /* When or zero */

	struct uloop_timeout delayed_timeout;
};

/* Externally assigned prefix */
struct pa_eap {
	struct avl_node avl_node; /* Put in pa's eap tree */
	struct prefix prefix;     /* The assigned prefix */
	struct pa_rid rid;        /* Sender's router id */

	struct pa_iface *iface;   /* Iface for that eap (or NULL) */
	struct list_head if_le;   /* Linked in iface list (or not) */
};

/* A delegated prefix (for both ldp and edp) */
struct pa_dp {
	struct list_head le;          /* Linked in pa's dp tree */
	struct prefix prefix;         /* The delegated prefix */
	hnetd_time_t valid_until;     /* Valid until (zero means not valid) */
	hnetd_time_t preferred_until;

	struct list_head laps;        /* laps attached to that prefix */
	bool local;                   /* Whether we own that assignment */
	struct pa_rid rid;            /* If not local, source rid */
};

struct pa {
	struct pa_conf conf;

	struct avl_tree laps; /* Locally assigned prefixes */
	struct avl_tree eaps; /* Externally assigned prefixes */

	struct list_head dps; /* Delegated prefixes list */

	struct list_head ifaces; /* List of interfaces known by pa */

	struct pa_rid rid; /* Our router id */

	struct pa_flood_callbacks fcb;  /* hcp callbacks */
	struct pa_iface_callbacks ifcb; /* iface callbacks */

	struct iface_user ifu; /* Subscriber to ifaces callbacks */

	bool started;   /* Whether the pa is started */
	bool scheduled; /* Schedule time */
	struct uloop_timeout pa_short_timeout; /* PA short delay schedule */
	struct uloop_timeout pa_dp_timeout; /* For dp events */
/* Ways of optimizing the pa algorithm */
#define PA_TODO_ALL    0xffff
	uint32_t todo_flags;
};


/**************************************************************/
/*********************** Prototypes ***************************/
/**************************************************************/
static void pa_eap_iface_assign(struct pa *pa, struct pa_eap *eap, struct pa_iface *iface);
static void pa_lap_destroy(struct pa *pa, struct pa_lap *lap);

/**************************************************************/
/*********************** Utilities ****************************/
/**************************************************************/

/* avl_tree key comparator */
static int pa_avl_prefix_cmp (const void *k1, const void *k2, void *ptr)
{
	int i = prefix_cmp((struct prefix *)k1, (struct prefix *)k2);
	if(!i)
		return 0;
	return (i>0)?1:-1;
}

/**************************************************************/
/************************ pa general **************************/
/**************************************************************/

static void pa_schedule(struct pa *pa, uint32_t todo_flags)
{
	pa->todo_flags |= todo_flags;
	if(pa->started && pa->todo_flags && !pa->scheduled) {
		uloop_timeout_set(&pa->pa_short_timeout, PA_SCHEDULE_RUNNEXT_MS);
		pa->scheduled = true;
	}
}

void pa_conf_default(struct pa_conf *conf)
{
	conf->commit_lap_delay =
			PA_CONF_DFLT_COMMIT_LAP_DELAY;

	conf->use_ula = PA_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PA_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_random_ula = PA_CONF_DFLT_USE_RDM_ULA;

	conf->use_ipv4 = PA_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PA_CONF_DFLT_NO_V4_IF_V6;
	memcpy(&conf->v4_prefix, &PA_CONF_DFLT_V4, sizeof(conf->v4_prefix));

	conf->iface_registration = PA_CONF_DFLT_IFACE_REGISTER;
	conf->iface_unregistration = PA_CONF_DFLT_IFACE_UNREGISTER;
}

void pa_flood_subscribe(pa_t pat, const struct pa_flood_callbacks *cb)
{
	struct pa *pa = (struct pa *)pat;
	memcpy(&pa->fcb, cb, sizeof(struct pa_flood_callbacks));
}

void pa_iface_subscribe(pa_t pat, const struct pa_iface_callbacks *cb)
{
	struct pa *pa = (struct pa *)pat;
	memcpy(&pa->ifcb, cb, sizeof(struct pa_iface_callbacks));
}

/**************************************************************/
/********************** Utilities *****************************/
/**************************************************************/

/* Safe timeout set.
 * Use when = 0 to cancel. */
static void pa_uloop_set(struct uloop_timeout *timeout,
		hnetd_time_t now, hnetd_time_t when)
{
	hnetd_time_t delay;
	if(!when) {
		uloop_timeout_cancel(timeout);
		return;
	}

	if(when < now)
		delay = 0;

	delay = when - now;

	if(delay)
		++delay; /* To avoid free loops caused by imprecision */

	if(delay > INTMAX_MAX)
		delay = INTMAX_MAX;

	uloop_timeout_set(timeout, (int) delay);
}

/**************************************************************/
/******************* iface managment **************************/
/**************************************************************/

static struct pa_iface *pa_iface_goc(struct pa *pa, const char *ifname)
{
	struct pa_iface *iface;

	list_for_each_entry(iface, &pa->ifaces, le) {
		if(!strcmp(ifname, iface->ifname))
			return iface;
	}

	if(strlen(ifname) >= IFNAMSIZ)
		return NULL; //Name too long

	if(!(iface = (struct pa_iface *)malloc(sizeof(struct pa_iface))))
		return NULL;

	strcpy(iface->ifname, ifname);
	list_init_head(&iface->eaps);
	list_init_head(&iface->laps);
	iface->internal = 0;
	list_add(&iface->le, &pa->ifaces);

	return iface;
}

/* Removes all laps from that interface */
static void pa_iface_rmlaps(struct pa *pa, struct pa_iface *iface)
{
	struct pa_lap *lap;
	struct pa_lap *slap;
	list_for_each_entry_safe(lap, slap, &iface->laps, if_le)
		pa_lap_destroy(pa, lap);
}

/* Delete an iface */
static void pa_iface_destroy(struct pa *pa, struct pa_iface *iface)
{
	struct pa_eap *eap;

	/* Destroys all laps */
	pa_iface_rmlaps(pa, iface);

	/* Remove iface from all eaps */
	list_for_each_entry(eap, &iface->eaps, if_le)
		pa_eap_iface_assign(pa, eap, NULL);

	list_del(&iface->le);
	free(iface);
}

/* Check whether we need to delete that interface or
 * its laps */
static void pa_iface_cleanmaybe(struct pa *pa,
		struct pa_iface *iface)
{
	if(iface->internal)
		return;

	if(list_empty(&iface->eaps)) {
		/* We don't need an external iface with no eaps */
		pa_iface_destroy(pa, iface);
	} else {
		/* External ifaces can't have laps */
		pa_iface_rmlaps(pa, iface);
	}
}

static void pa_iface_set_internal(struct pa *pa,
		struct pa_iface *iface, bool internal)
{
	if(iface->internal != internal)
		pa_schedule(pa, PA_TODO_ALL);

	iface->internal = internal;
	pa_iface_cleanmaybe(pa, iface);
}

static void pa_iface_set_dodhcp(struct pa *pa,
		struct pa_iface *iface, bool do_dhcp)
{
	if(iface->do_dhcp == do_dhcp)
		return;

	iface->do_dhcp = do_dhcp;

	/* When iface ownership changes,
	 * it can be important to run PA again. */
	pa_schedule(pa, PA_TODO_ALL);

	/* Tell iface about link ownership */
	if(pa->ifcb.update_link_owner)
		pa->ifcb.update_link_owner(iface->ifname, do_dhcp,
				pa->ifcb.priv);
}

/**************************************************************/
/********************* eap managment **************************/
/**************************************************************/

/* iface are optional for eaps */
static void pa_eap_iface_assign(struct pa *pa,
		struct pa_eap *eap, struct pa_iface *iface)
{
	if(eap->iface == iface)
		return;

	if(eap->iface)
		list_remove(&eap->if_le);

	eap->iface = iface;

	if(eap->iface)
		list_add(&eap->if_le, &iface->eaps);

	pa_schedule(pa, PA_TODO_ALL);
}

/* Find an eap with specified prefix and rid */
static struct pa_eap *pa_eap_get(struct pa *pa,
		const struct prefix *prefix, const struct pa_rid *rid)
{
	struct pa_eap *iter;
	struct pa_eap *first;
	struct pa_eap *last;

	first = avl_find_ge_element(&pa->eaps, prefix, iter, avl_node);
	last = avl_find_le_element(&pa->eaps, prefix, iter, avl_node);

	if(!first)
		return NULL;

	avl_for_element_range(first, last, iter, avl_node) {
		if(!PA_RIDCMP(rid, &iter->rid))
			return iter;
	}

	return NULL;
}

static int pa_eap_iface_assignbyname(struct pa *pa,
		struct pa_eap *eap, const char *ifname)
{
	struct pa_iface *iface = NULL;
	if(ifname && strlen(ifname)) {
		iface = pa_iface_goc(pa, ifname);

		if(iface == NULL)
			return -1;
	}

	pa_eap_iface_assign(pa, eap, iface);
	return 0;
}

static struct pa_eap *pa_eap_create(struct pa *pa, const struct prefix *prefix,
		const struct pa_rid *rid)
{
	struct pa_eap *eap;

	if(!(eap = malloc(sizeof(struct pa_eap))))
		goto malloc;

	eap->iface = NULL; /* Important for assign */

	memcpy(&eap->rid, rid, sizeof(struct pa_rid));
	memcpy(&eap->prefix, prefix, sizeof(struct prefix));

	if(avl_insert(&pa->eaps, &eap->avl_node))
		goto insert;

	/* New eap means we rerun algo */
	pa_schedule(pa, PA_TODO_ALL);

	return eap;
insert:
	free(eap);
malloc:
	return NULL;
}

/* Only hcp controls eaps.
 * Destroying it is straightworward. */
static void pa_eap_destroy(struct pa *pa, struct pa_eap *eap)
{
	pa_eap_iface_assign(pa, eap, NULL);
	avl_delete(&pa->eaps, &eap->avl_node);
	free(eap);

	/* Destoyed eap, we rerun algo */
	pa_schedule(pa, PA_TODO_ALL);
}

static struct pa_eap *pa_eap_goc(struct pa *pa, const struct prefix *prefix,
		const char *ifname, const struct pa_rid *rid)
{
	struct pa_eap *eap;

	eap = pa_eap_get(pa, prefix, rid);

	if(!eap)
		eap = pa_eap_create(pa, prefix, rid);

	if(!eap)
		return NULL;

	if(pa_eap_iface_assignbyname(pa, eap, ifname)) {
		pa_eap_destroy(pa, eap);
		return NULL;
	}

	return eap;
}

static void pa_eap_update(struct pa *pa, struct pa_eap *eap,
		bool to_delete)
{
	if(to_delete) {
		pa_eap_destroy(pa, eap);
		pa_schedule(pa, PA_TODO_ALL);
	}
}

/**************************************************************/
/********************* lap management *************************/
/**************************************************************/

static void pa_lap_delayed_cb(struct uloop_timeout *t);

static struct pa_lap *pa_lap_create(struct pa *pa, const struct prefix *prefix,
		struct pa_iface *iface, struct pa_dp* dp)
{
	struct pa_lap *lap;

	if(!(lap = malloc(sizeof(struct pa_lap))))
		return NULL;

	lap->assigned = false;
	lap->flooded = false;
	lap->invalid = false; /* For pa algo */
	lap->own = false;
	memcpy(&lap->prefix, prefix, sizeof(struct prefix));

	lap->pa = pa;
	if(avl_insert(&pa->laps, &lap->avl_node)) {
		free(lap);
		return NULL;
	}

	/* Attaching dp */
	lap->dp = dp;
	list_add(&lap->dp_le, &dp->laps);

	/* Attaching iface */
	lap->iface = iface;
	list_add(&lap->if_le, &iface->laps);

	/* Setting delayed operations */
	lap->delayed_timeout = (struct uloop_timeout) {.cb = pa_lap_delayed_cb};
	lap->delayed_assign_time = 0;
	lap->delayed_flooding_time = 0;
	lap->delayed_delete_time = 0;

	pa_schedule(pa, PA_TODO_ALL);

	return lap;
}

static void pa_lap_delayed_update_timeout(struct pa *pa, struct pa_lap *lap,
		hnetd_time_t now)
{
	hnetd_time_t timeout = 0;
	if(lap->delayed_assign_time &&
			(!timeout || lap->delayed_assign_time < timeout))
		timeout = lap->delayed_assign_time;

	if(lap->delayed_delete_time &&
				(!timeout || lap->delayed_delete_time < timeout))
			timeout = lap->delayed_delete_time;

	if(lap->delayed_flooding_time &&
					(!timeout || lap->delayed_flooding_time < timeout))
				timeout = lap->delayed_flooding_time;

	pa_uloop_set(&lap->delayed_timeout, now, timeout);
}

static void pa_lap_tellhcp(struct pa *pa, struct pa_lap *lap)
{
	// Tell hcp about that
		if(pa->fcb.updated_lap)
			pa->fcb.updated_lap(&lap->prefix, lap->iface->ifname,
					!lap->flooded, pa->fcb.priv);
}

static void pa_lap_telliface(struct pa *pa, struct pa_lap *lap)
{
	// Tell ifaces about that
	if(pa->ifcb.update_prefix)
		pa->ifcb.update_prefix(&lap->prefix, lap->iface->ifname,
				(lap->assigned)?lap->dp->valid_until:0,
						(lap->assigned)?lap->dp->preferred_until:0,
								pa->fcb.priv);
}

static void pa_lap_setflood(struct pa *pa, struct pa_lap *lap,
		bool enable)
{
	if(lap->delayed_flooding_time) {
		lap->delayed_flooding_time = 0;
		pa_lap_delayed_update_timeout(pa, lap, hnetd_time());
	}

	if(enable == lap->flooded)
		return;

	lap->flooded = enable;

	pa_lap_tellhcp(pa, lap);
}

static void pa_lap_setassign(struct pa *pa, struct pa_lap *lap,
		bool enable)
{
	if(lap->delayed_assign_time) {
		/* Cancel the existing delayed set. */
		lap->delayed_assign_time = 0;
		pa_lap_delayed_update_timeout(pa, lap, hnetd_time());
	}

	if(enable == lap->assigned)
		return;

	lap->assigned = enable;

	pa_lap_telliface(pa, lap);
}

static void pa_lap_setdp(struct pa *pa, struct pa_lap *lap,
		struct pa_dp *dp)
{
	if(lap->dp == dp)
		return;

	list_remove(&lap->dp_le);
	lap->dp = dp;
	list_add(&lap->dp_le, &dp->laps);

	if(lap->assigned)
		pa_lap_telliface(pa, lap);
}

static void pa_lap_destroy(struct pa *pa, struct pa_lap *lap)
{
	/* Unassign if assigned */
	pa_lap_setassign(pa, lap, false);

	/* Unflood if flooded */
	pa_lap_setflood(pa, lap, false);

	/* Cancel timer if set */
	uloop_timeout_cancel(&lap->delayed_timeout);

	list_remove(&lap->dp_le);
	list_remove(&lap->if_le);

	avl_delete(&pa->laps, &lap->avl_node);
	free(lap);

	pa_schedule(pa, PA_TODO_ALL);
}

/* This set of functions allows delayed actions.
 * Without flags, previous delayed action are always overridden.
 * It is also overriden when a direct assignment is made.
 * Flags allow to not do something in some particular cases. */
#define PA_DF_NOT_IF_LATER_AND_EQUAL 0x01 /* Do not update if same value and when is later */


static void pa_lap_setdelete_delayed(struct pa *pa, struct pa_lap *lap,
		hnetd_time_t when, hnetd_time_t now, int flags)
{
	if((flags & PA_DF_NOT_IF_LATER_AND_EQUAL) &&
			lap->delayed_delete_time &&
			when > lap->delayed_delete_time)
		return;

	lap->delayed_delete_time = when;
	pa_lap_delayed_update_timeout(pa, lap, now);
}

static void pa_lap_setassign_delayed(struct pa *pa, struct pa_lap *lap,
		hnetd_time_t when, hnetd_time_t now, bool assign, int flags)
{
	/* No change needed
	 * delayed value is always different than current value */
	if(assign == lap->assigned && !lap->delayed_assign_time)
		return;

	if((flags & PA_DF_NOT_IF_LATER_AND_EQUAL) &&
			(assign == lap->delayed_assign) &&
			lap->delayed_assign_time &&
				when > lap->delayed_assign_time)
			return;

	lap->delayed_assign_time = when;
	lap->delayed_assign = assign;
	pa_lap_delayed_update_timeout(pa, lap, now);
}

static void pa_lap_setflooding_delayed(struct pa *pa, struct pa_lap *lap,
		hnetd_time_t when, hnetd_time_t now, bool flood, int flags)
{
	/* No change needed
	 * delayed value is always different than current value */
	if(flood == lap->flooded && !lap->delayed_flooding_time)
		return;

	if((flags & PA_DF_NOT_IF_LATER_AND_EQUAL) &&
				(flood == lap->delayed_flooding) &&
				lap->delayed_flooding_time &&
					when > lap->delayed_flooding_time)
				return;

	lap->delayed_flooding_time = when;
	lap->delayed_flooding = flood;
	pa_lap_delayed_update_timeout(pa, lap, now);
}

static void pa_lap_delayed_cb(struct uloop_timeout *t)
{
	struct pa_lap *lap = container_of(t, struct pa_lap, delayed_timeout);
	struct pa *pa =  lap->pa;

	hnetd_time_t now = hnetd_time();

	if(lap->delayed_assign_time && lap->delayed_assign_time <= now)
		pa_lap_setassign(pa, lap, lap->delayed_assign);

	if(lap->delayed_flooding_time && lap->delayed_flooding_time <= now)
			pa_lap_setflood(pa, lap, lap->delayed_flooding);

	if(lap->delayed_delete_time && lap->delayed_delete_time <= now)
			pa_lap_destroy(pa, lap);

	pa_lap_delayed_update_timeout();
}

/**************************************************************/
/********************* dp managment **************************/
/**************************************************************/

struct pa_dp *pa_dp_get(struct pa *pa, const struct prefix *p,
		const struct pa_rid *rid)
{
	struct pa_dp *dp;

	list_for_each_entry(dp, &pa->dps, le) {
		if(!prefix_cmp(p, &dp->prefix) &&
				 ((rid)?(!PA_RIDCMP(&pa->rid, rid)):dp->local))
			return dp;
	}
	return NULL;
}

/* Creates an empty unused dp with the given prefix */
static struct pa_dp *pa_dp_create(struct pa *pa,
		const struct prefix *prefix,
		const struct pa_rid *rid)
{
	struct pa_dp *dp;
	if(!(dp = malloc(sizeof(struct pa_dp))))
		return NULL;

	memcpy(&dp->prefix, prefix, sizeof(struct prefix));
	list_init_head(&dp->laps);
	dp->valid_until = 0;
	dp->preferred_until = 0;
	if(!rid) {
		dp->local = 1;
	} else {
		dp->local = 0;
		memcpy(&dp->rid, rid, sizeof(struct pa_rid));
	}

	list_add(&dp->le, &pa->dps); /* Adding dp */

	/* Rerun algo. when new dp */
	pa_schedule(pa, PA_TODO_ALL);
	return dp;
}

static struct pa_dp *pa_dp_goc(struct pa *pa, const struct prefix *prefix,
		const struct pa_rid *rid)
{
	struct pa_dp *dp = pa_dp_get(pa, prefix, rid);

	if(dp)
		return dp;

	return pa_dp_create(pa, prefix, rid);
}

static void pa_dp_destroy(struct pa *pa, struct pa_dp *dp)
{
	struct pa_lap *lap;
	struct pa_lap *slap;
	struct pa_dp *s_dp;
	bool found;

	/* Destoy all laps attached to that dp.
	 * If we can't reattach the lap to another dp (temporarly) */
	list_for_each_entry_safe(lap, slap, &dp->laps, dp_le) {
		/* Find another dp that could temporarily accept that lap */
		found = false;
		list_for_each_entry(s_dp, &pa->dps, le) {
			if(s_dp != dp && prefix_contains(&s_dp->prefix, &lap->prefix)){
				found = true;
				break;
			}
		}
		if(found) {
			pa_lap_setdp(pa, lap, s_dp);
		} else {
			pa_lap_destroy(pa, lap);
		}
	}

	//Notify hcp iff local
	if(dp->local && pa->fcb.updated_ldp)
			pa->fcb.updated_ldp(&dp->prefix, 0,
					0, pa->fcb.priv);

	//Remove that dp from database
	list_remove(&dp->le);
	free(dp);

	/* Run algo again */
	pa_schedule(pa, PA_TODO_ALL);
}

static void pa_dp_update_raw(struct pa *pa, struct pa_dp *dp,
		hnetd_time_t valid_until,hnetd_time_t preferred_until)
{
	dp->valid_until = valid_until;
	dp->preferred_until = preferred_until;

	pa_schedule(pa, PA_TODO_ALL);

	/* Must tell hcp about changes */
	if(dp->local && pa->fcb.updated_ldp) {
		pa->fcb.updated_ldp(&dp->prefix, dp->valid_until,
				dp->preferred_until, pa->fcb.priv);
	}
}

static void pa_dp_update(struct pa *pa, struct pa_dp *dp,
		hnetd_time_t valid_until,hnetd_time_t preferred_until)
{
	if(valid_until == dp->valid_until &&
			preferred_until == dp->preferred_until)
		return;

	if(!dp->valid_until) {
		pa_dp_destroy(pa, dp);
	} else {
		pa_dp_update_raw(pa, dp, valid_until, preferred_until);
	}
}

static void pa_dp_cleanmaybe(struct pa *pa, struct pa_dp *dp,
		hnetd_time_t now)
{
	if(now >= dp->valid_until)
		pa_dp_destroy(pa, dp);
}

/**************************************************************/
/********************* PA algorithm ***************************/
/**************************************************************/

/* Check whether a foreign assignment exists on a link different than iface
 * with a higher or equal router id. */
static bool pa_prefix_checkcollision(struct pa *pa, struct prefix *prefix,
		struct pa_iface *exclude_iface, struct pa_rid *rid,
		bool check_foreign, bool check_local)
{
	struct pa_eap *eap;
	struct pa_eap *lap;

	if(check_foreign) {
		avl_for_each_element(&pa->eaps, eap, avl_node) {
			if((!exclude_iface || eap->iface != exclude_iface) &&
					prefix_contains(&eap->prefix, prefix) &&
					(!rid ||  PA_RIDCMP(&eap->rid, rid) > 0)) {
				return true;
			}
		}
	}

	if(check_local) {
		avl_for_each_element(&pa->laps, lap, avl_node) {
			if((!exclude_iface || lap->iface != exclude_iface) &&
					prefix_contains(&lap->prefix, prefix) &&
					(!rid || PA_RIDCMP(&pa->rid, rid) > 0)) {
				return true;
			}
		}
	}

	return false;
}

static int pa_get_newprefix_storage(struct pa *pa, struct pa_iface *iface,
		struct pa_dp *dp, struct prefix *new_prefix) {
	//TODO
	return -1;
}

static int pa_get_newprefix_random(struct pa *pa, struct pa_iface *iface,
		struct pa_dp *dp, struct prefix *new_prefix) {

	int i;
	uint8_t plen;

	if(dp->prefix.plen < 64) {
		plen = 64;
	} else if (dp->prefix.plen == 104) { //IPv4
		plen = 120;
	} else {
		L_WARN(PA_L_PX"Delegated prefix length (%d) not supported", dp->prefix.plen);
		return -1;
	}

	for(i=0; i<PA_MAX_RANDOM_ROUNDS; i++) {
		prefix_random(&dp->prefix, new_prefix, plen);
		if(!pa_prefix_checkcollision(pa, &new_prefix, NULL, NULL, true, true))
			return 0;
	}

	return -1;
}

/* Executes pa algorithm */
void pa_do(struct pa *pa)
{
	hnetd_time_t now, timeout;
	struct pa_iface *iface, *s_iface;
	struct pa_dp *dp, *s_dp;
	struct pa_lap *lap, *s_lap;
	struct pa_eap *eap, *s_eap;
	struct prefix *prefix;
	struct prefix new_prefix;
	bool found, own, link_highest_rid, wait_for_neigh;

	now = hnetd_time();

	/* This is at the beginning because any modification
	 * to laps should make the algorithm run again */
	if(!pa->todo_flags)
		return;
	pa->scheduled = false;
	pa->todo_flags = 0;

	/* Clean interfaces that should be destroyed
	 * (external with no eaps)*/
	list_for_each_entry_safe(iface, s_iface, &pa->ifaces, le) {
		pa_iface_cleanmaybe(pa, iface);
	}

	/* Clean dps that are outdated */
	list_for_each_entry_safe(dp, s_dp, &pa->dps, le) {
		pa_dp_cleanmaybe(pa, dp, now);
	}

	/* Get next dp timeout */
	timeout = 0;
	list_for_each_entry(dp, &pa->dps, le) {
		if(!timeout || timeout < dp->valid_until) {
			timeout = dp->valid_until;
		}
	}
	pa_uloop_set(&pa->pa_dp_timeout, now, timeout);


	/* TODO: Decide whether to generate ULAs or IPv4 */

	/* Mark all laps as invalid */
	avl_for_each_element(&pa->laps, lap, avl_node) {
		lap->invalid = true;
	}

	/* Go through all internal ifaces */
	list_for_each_entry(iface, &pa->ifaces, le) {
		/* SHOULD NOT DELETE IFACE HERE */

		if(!iface->internal)
			continue;

		/* Go through all dps */
		list_for_each_entry(dp, &pa->dps, le) {
			/* Check if the dp doesn't contain another smaller dp */
			found = false;
			list_for_each_entry(s_dp, &pa->dps, le) {
				if(s_dp != dp &&
						prefix_contains(&dp->prefix, &s_dp->prefix)) {
					found = true;
					break;
				}
			}

			/* Only use smaller dps
			 * Laps that are not in smaller dps will
			 * be removed due to invalid-labelling */
			if(found)
				continue;

			/* See whether we have a lap for this
			 * iface/dp pair */
			lap = NULL;
			list_for_each_entry(s_lap, &iface->laps, if_le) {
				/* Prefix ownership is not important here. */
				if(prefix_contains(&dp->prefix, &s_lap->prefix)) {
					lap = s_lap;
					/* lap is attached to a dp.
					 * This dp will be updated when
					 * lap->invalid is set to false (if it does) */
					break;
				}
			}

			/* See whether someone else made an assignment
			 * on that same link. Keep the highest rid. */
			eap = NULL;
			list_for_each_entry(s_eap, &iface->eaps, if_le) {
				if(prefix_contains(&dp->prefix, &s_eap->prefix) &&
						(!eap || PA_RIDCMP(&s_eap->rid, &eap->rid) > 0 )) {
					eap = s_eap;
				}
			}

			/* See whether we have highest router id on that link */
			link_highest_rid = true;
			list_for_each_entry(s_eap, &iface->eaps, if_le) {
				if(PA_RIDCMP(&s_eap->rid, &pa->rid) > 0) {
					link_highest_rid = false;
					break;
				}
			}


			/* See if someone overrides our assignment */
			if(lap && eap && PA_RIDCMP(&eap->rid, &pa->rid) &&
					prefix_cmp(&lap->prefix, &eap->prefix)) {
				/* We have a lap but a guy with higher priority
				 * disagrees with us. We need to override ours. */
				pa_lap_destroy(pa, lap);
				lap = NULL;
			}

			if(lap && lap->own &&
					pa_prefix_checkcollision(pa, &lap->prefix, iface, &pa->rid, true, false)) {
				/* This is case i. of algorithm
				 * We have an assignment but we need to check for collisions
				 * on other links. */
				pa_lap_destroy(pa, lap);
				lap = NULL;
			}

			if(!lap) {
				/* This is step 6 of the algorithm
				 * Assignment generation. */

				prefix = NULL;

				wait_for_neigh = false;
				if(eap) {
					/* Let's try to use that guy's eap.
					 * But only if its valid against all other links
					 * assignments. */
					if(!pa_prefix_checkcollision(pa, &eap->prefix, iface, &eap->rid,
							true, true)) {
						prefix = &eap->prefix;
#if PA_ALGO == PA_ALGO_ARKKO
						own = false; /* The other guy owns it */
#elif PA_ALGO == PA_ALGO_PFISTER
						/* If we do dhcp and we have highest link id
						 * we claim ownership of all prefixes so that
						 * it converges to a single owner per link. */
						own = (link_highest_rid && iface->do_dhcp);
#endif
					} else {
						/* We detected a collision, but just silently ignore it */
#if PA_ALGO == PA_ALGO_ARKKO
						wait_for_neigh = true;
#elif PA_ALGO == PA_ALGO_PFISTER
						wait_for_neigh = !iface->do_dhcp;
#endif
					}
				}

				if(!prefix && link_highest_rid && !wait_for_neigh) {
					/* Let's choose a prefix for our own assignment */
					if(!pa_get_newprefix_storage(pa, iface, dp, &new_prefix)) {
						/* Got one from stable storage */
						prefix = &new_prefix;
						own = true;
					} else if(!pa_get_newprefix_random(pa, iface, dp, &new_prefix)) {
						/* Got one from random choice */
						prefix = &new_prefix;
						own = true;
					}
				}

				if(prefix) {
					/* We can make an assignment. */
					lap = pa_lap_create(pa, prefix, iface, dp);
					lap->own = own; /* Important to know whether we are owner. */
				} else if (link_highest_rid && !wait_for_neigh) {
					L_WARN(PA_L_PX"Could not generate a prefix for interface %s", iface->ifname);
				}
			}

			/* Check iface assignment and flooding */
			if(lap) {

				/* If nobody else is advertising the prefix
				 * anymore, we need to become owner of it. */
				if(!lap->own) {
					eap = NULL;
					list_for_each_entry(s_eap, &iface->eaps, if_le) {
						if(!prefix_cmp(&lap->prefix, &s_eap->prefix)) {
							eap = s_eap;
						}
					}
					if(!eap)
						lap->own = true;
				}

				lap->invalid = false;
				pa_lap_setdp(pa, lap, dp);

				if(lap->own) /*No delayed flooding */
					pa_lap_setflood(pa, lap, true);

				if(pa->conf.commit_lap_delay) {
					timeout = now + pa->conf.commit_lap_delay;
					pa_lap_setassign_delayed(pa, lap, timeout, now, true,
							PA_DF_NOT_IF_LATER_AND_EQUAL);
				} else {
					pa_lap_setassign(pa, lap, true);
				}

			}

		}

	}

	/* Clean invalid laps */
	avl_for_each_element_safe(&pa->laps, lap, avl_node, s_lap) {
		if(lap->invalid)
			pa_lap_destroy(pa, lap);
	}

	/* Do interface ownership check */
	list_for_each_entry(iface, &pa->ifaces, le) {
		own = false;
		/* By now (arkko's), we are owner as soon as we have a owned
		 * prefix */
		list_for_each_entry(lap, &iface->laps, if_le) {
			if(lap->own) {
				own = true;
				break;
			}
		}

		pa_iface_set_dodhcp(pa, iface, own);
	}
}

static void pa_do_uloop(struct uloop_timeout *t)
{
	struct pa *pa = container_of(t, struct pa, pa_short_timeout);
	pa_do(pa);
}


/**************************************************************/
/********************* hcp interface **************************/
/**************************************************************/

void pa_set_rid(pa_t pat, const struct pa_rid *rid)
{
	struct pa *pa = (struct pa *)pat;
	if(!PA_RIDCMP(&pa->rid, rid))
		return;

	memcpy(&pa->rid, rid, sizeof(struct pa_rid));
	pa_schedule(pa, PA_TODO_ALL);
}

/* Called by hcp when it wants to update an eap */
int pa_update_eap(pa_t pat, const struct prefix *prefix,
		const struct pa_rid *rid,
		const char *ifname, bool to_delete)
{
	struct pa *pa = (struct pa *)pat;
	struct pa_eap *eap;

	if(!(eap = pa_eap_goc(pa, prefix, ifname, rid)))
		return -1;

	pa_eap_update(pa, eap, to_delete);
	return 0;
}

int pa_update_edp(pa_t pat, const struct prefix *prefix,
		const struct pa_rid *rid,
		hnetd_time_t valid_until, hnetd_time_t preferred_until)
{
	struct pa *pa = (struct pa *)pat;
	struct pa_dp *dp;

	if(!rid) /* Do not accept local dps */
		return -1;

	if(!(dp = pa_dp_goc(pa, prefix, rid)))
		return -1;

	pa_dp_update(pa, dp, valid_until, preferred_until);
	return 0;
}


/**************************************************************/
/********************* iface callbacks ************************/
/**************************************************************/

static void pa_ifu_intiface(struct iface_user *u,
		const char *ifname, bool enabled)
{
	struct pa *pa = container_of(u, struct pa, ifu);
	struct pa_iface *iface;

	iface = pa_iface_goc(pa, ifname);

	if(!iface)
		return;

	pa_iface_set_internal(pa, iface, enabled);
}

static void pa_ifu_pd(struct iface_user *u,
			const struct prefix *prefix,
			hnetd_time_t valid_until, hnetd_time_t preferred_until)
{
	struct pa *pa = container_of(u, struct pa, ifu);
	/* Null because local */
	struct pa_dp *dp = pa_dp_goc(pa, prefix, NULL);

	if(!dp)
		return;

	pa_dp_update(pa, dp, valid_until, preferred_until);
}

/**************************************************************/
/********************* main management ************************/
/**************************************************************/

int pa_set_conf(pa_t pat, const struct pa_conf *conf)
{
	struct pa *pa = (struct pa *)pat;

	if(conf->use_ula && !conf->use_random_ula &&
			!prefix_is_ipv6_ula(&conf->ula_prefix))
		return -1;

	memcpy(&pa->conf, conf, sizeof(struct pa_conf));
	return 0;
}

pa_t pa_create(const struct pa_conf *conf)
{
	struct pa *pa;

	if(!(pa = malloc(sizeof(struct pa))))
		return NULL;

	avl_init(&pa->eaps, pa_avl_prefix_cmp, true, NULL);
	avl_init(&pa->laps, pa_avl_prefix_cmp, false, NULL);
	list_init_head(&pa->dps);
	list_init_head(&pa->ifaces);

	pa->started = false;
	pa->todo_flags = 0;
	pa->scheduled = false;

	pa->ifu.cb_intiface = pa_ifu_intiface;
	pa->ifu.cb_prefix = pa_ifu_pd;

	pa->pa_short_timeout = (struct uloop_timeout) { .cb = pa_do_uloop };
	pa->pa_dp_timeout = (struct uloop_timeout) { .cb = pa_do_uloop };
	pa->rid = (struct pa_rid) {};

	if(pa_set_conf(pa, conf)) {
		free(pa);
		return NULL;
	}

	pa_schedule(pa, PA_TODO_ALL);

	return pa;
}

int pa_start(pa_t pat)
{
	struct pa *pa = (struct pa *)pat;

	if(pa->started)
		return -1;

	pa->started = true;
	/* Starts the pa if there is things to do */
	pa_schedule(pa, 0);

	/* Register to iface */
	if(pa->conf.iface_registration)
		pa->conf.iface_registration(&pa->ifu);

	return 0;
}

void pa_destroy(pa_t pat)
{
	struct pa *pa = (struct pa *)pat;
	struct pa_iface *iface;
	struct pa_dp *dp;
	struct pa_eap *eap;
	struct pa_eap *seap;

	/* Unregister everywhere */
	if(pa->conf.iface_unregistration)
			pa->conf.iface_unregistration(&pa->ifu);

	/* Destroy all interfaces
	 * This will also delete all laps */
	while((iface = list_first_entry(&pa->ifaces, struct pa_iface, le))) {
		pa_iface_destroy(pa, iface);
	}

	/* Destroy all dps */
	while((dp = list_first_entry(&pa->dps, struct pa_dp, le))) {
		pa_dp_destroy(pa, dp);
	}

	/* Destroy all eaps */
	avl_for_each_element_safe(&pa->eaps, eap, avl_node, seap) {
		pa_eap_destroy(pa, eap);
	}

	free(pa);
}

