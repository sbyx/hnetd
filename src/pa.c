#include "pa.h"

#include <stdlib.h>
#include <string.h>
#include <libubox/list.h>
#include <libubox/avl.h>

/* #of ms waiting when we want immediate pa run */
#define PA_SCHEDULE_RUNNEXT_MS  10

#define PA_RIDCMP(r1, r2) memcmp(r1, r2, PA_RIDLEN)

#define PA_CONF_DFLT_COMMIT_LAP_DELAY  20
#define PA_CONF_DFLT_DELETE_LAP_DELAY  240

#define PA_CONF_DFLT_USE_ULA             1
#define PA_CONF_DFLT_NO_ULA_IF_V6        1
#define PA_CONF_DFLT_USE_V4              1
#define PA_CONF_DFLT_NO_V4_IF_V6         0
#define PA_CONF_DFLT_USE_RDM_ULA         1

#define PA_CONF_DFLT_IFACE_REGISTER      iface_register_user

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

	bool flooded;             /* Whether it was given to hcp */
	bool assigned;            /* Whether it was assigned */
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
	bool scheduled; /* Wether a pa run is scheduled */
	struct uloop_timeout pa_timeout; /* PA algo scheduler */

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
		uloop_timeout_set(&pa->pa_timeout, PA_SCHEDULE_RUNNEXT_MS);
		pa->scheduled = true;
	}
}

void pa_conf_default(struct pa_conf *conf)
{
	conf->commit_lap_delay =
			PA_CONF_DFLT_COMMIT_LAP_DELAY;
	conf->delete_lap_delay =
			PA_CONF_DFLT_DELETE_LAP_DELAY;

	conf->use_ula = PA_CONF_DFLT_USE_ULA;
	conf->no_ula_if_glb_ipv6 = PA_CONF_DFLT_NO_ULA_IF_V6;
	conf->use_random_ula = PA_CONF_DFLT_USE_RDM_ULA;

	conf->use_ipv4 = PA_CONF_DFLT_USE_V4;
	conf->no_ipv4_if_glb_ipv6 = PA_CONF_DFLT_NO_V4_IF_V6;
	memcpy(&conf->v4_prefix, &PA_CONF_DFLT_V4, sizeof(conf->v4_prefix));

	conf->iface_registration = PA_CONF_DFLT_IFACE_REGISTER;
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
/******************* Lookup functions *************************/
/**************************************************************/



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

static struct pa_lap *pa_lap_create(struct pa *pa, const struct prefix *prefix,
		struct pa_iface *iface, struct pa_dp* dp)
{
	struct pa_lap *lap;

	if(!(lap = malloc(sizeof(struct pa_lap))))
		return NULL;

	lap->assigned = false;
	lap->flooded = false;
	memcpy(&lap->prefix, prefix, sizeof(struct prefix));

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

	return lap;
}

static void pa_lap_setflood(struct pa *pa, struct pa_lap *lap,
		bool enable)
{
	if(enable == lap->flooded)
		return;

	lap->flooded = enable;

	// Tell hcp about that
	if(pa->fcb.updated_lap)
		pa->fcb.updated_lap(&lap->prefix, lap->iface->ifname,
				!lap->flooded, pa->fcb.priv);
}

static void pa_lap_setassign(struct pa *pa, struct pa_lap *lap,
		bool enable)
{
	if(enable == lap->assigned)
		return;

	lap->assigned = enable;

	// Tell ifaces about that
	if(pa->ifcb.update_prefix)
		pa->ifcb.update_prefix(&lap->prefix, lap->iface->ifname,
				(lap->assigned)?lap->dp->valid_until:0,
				(lap->assigned)?lap->dp->preferred_until:0,
						pa->fcb.priv);
}

static void pa_lap_destroy(struct pa *pa, struct pa_lap *lap)
{
	/* Unassign if assigned */
	pa_lap_setassign(pa, lap, false);

	/* Unflood if flooded */
	pa_lap_setflood(pa, lap, false);

	list_remove(&lap->dp_le);
	list_remove(&lap->if_le);

	avl_delete(&pa->laps, &lap->avl_node);
	free(lap);
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

	/* Destroy all lap rattached to that dp
	 * because a lap needs a dp
	 * TODO: Manage orphan laps (i.e. find another compatible dp) */
	list_for_each_entry_safe(lap, slap, &dp->laps, dp_le) {
		pa_lap_destroy(pa, lap);
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

/**************************************************************/
/********************* PA algorithm ***************************/
/**************************************************************/


/* Executes pa algorithm */
void pa_do(struct pa *pa)
{

}

static void pa_do_uloop(struct uloop_timeout *t)
{
	struct pa *pa = container_of(t, struct pa, pa_timeout);
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

	pa->pa_timeout = (struct uloop_timeout) { .cb = pa_do_uloop };
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
	iface_register_user(&pa->ifu);

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
	iface_unregister_user(&pa->ifu);

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

