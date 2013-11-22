#include "pa.h"

#include <stdlib.h>
#include <string.h>
#include <libubox/list.h>
#include <libubox/avl.h>

/* #of ms waiting when we want immediate pa run */
#define PA_SCHEDULE_RUNNEXT_MS  10

#define PA_CONF_DFLT_COMMIT_LAP_DELAY  20
#define PA_CONF_DFLT_DELETE_LAP_DELAY  240

#define PA_CONF_DFLT_USE_ULA             1
#define PA_CONF_DFLT_NO_ULA_IF_V6        1
#define PA_CONF_DFLT_USE_V4              1
#define PA_CONF_DFLT_NO_V4_IF_V6         0
#define PA_CONF_DFLT_USE_RDM_ULA         1

static struct prefix PA_CONF_DFLT_V4 = {
	.prefix = { .s6_addr = {
			0x00,0x00, 0x00,0x00,  0x00,0x00, 0x00,0x00,
			0x00,0x00, 0xff,0xff,  0x0a }},
	.plen = 104 };


/* Externally assigned prefix */
struct pa_eap {
	struct avl_node avl_node;
	struct prefix prefix;
	char ifname[IFNAMSIZ];

	bool higher_priority; /* If we have higher priority */
	int to_delete; /* This eap is to be deleted */

	/* Must be checked against pa */
	bool updated;
};

/* A delegated prefix */
struct pa_dp {
	struct avl_node avl_node;
	struct prefix prefix;
	time_t valid_until;
	time_t prefered_until;
	bool local;

	/* That means the dp was modified and should be checked against
	 * pa algo during next schedule. */
	bool updated;
};

/* Locally assigned prefix */
struct pa_lap {
	struct avl_node avl_node;   /* Must be first */
	struct prefix prefix;	    /* The assigned prefix */
	char ifname[IFNAMSIZ];		/* lap's interface name */

	struct pa_dp *dp;
	bool owner;
	time_t flooded;  //When flooding started
	time_t assigned; //When assigned to iface
};

/* Represents an interface for pa */
struct pa_iface {
	struct list_head le;
	char ifname[IFNAMSIZ];

	/* run_pa can be set by iface.
	 * owner can be set by hcp.
	 * If both of them are null, we really don't care
	 * about that interface and it should be deleted.
	 */
	bool run_pa;

	/* Means that interface has been modified
	 * and must be checked against pa algorithm during
	 * next schedule. */
	bool updated;
};


struct pa {
	struct pa_conf conf;

	struct avl_tree laps; /* Locally assigned prefixes */
	struct avl_tree eaps; /* Externaly assigned prefixes */
	struct avl_tree dps;  /* Delegated prefixes db */

	struct list_head ifaces; /* List of interfaces known by pa */

	bool global_leadership; /* Whether we are global leader */

	struct pa_flood_callbacks fcb; /* flooder interface */
	struct pa_iface_callbacks ifcb; /* iface callbacks */

	/* Whether the pa is started */
	bool started;

#define PA_TODO_ULA    0x0001
#define PA_TODO_LAPS   0x0002
#define PA_TODO_IFACE  0x0004
#define PA_TODO_DP     0x0008
#define PA_TODO_LEADER 0x0010
#define PA_TODO_EAPS   0x0020
	uint32_t todo_flags;

	struct uloop_timeout pa_timeout;
};

static int pa_avl_prefix_cmp (const void *k1, const void *k2, void *ptr)
{
	int i = prefix_cmp((struct prefix *)k1, (struct prefix *)k2);
	if(!i)
		return 0;
	return (i>0)?1:-1;
}

#define pa_schedule_raw(pa) \
		uloop_timeout_set(&pa->pa_timeout, PA_SCHEDULE_RUNNEXT_MS)

static void pa_schedule(struct pa *pa, uint32_t todo_flags)
{
	if(!(todo_flags & ~pa->todo_flags))
		return;

	bool running = pa->todo_flags;

	pa->todo_flags |= todo_flags;

	if(pa->started && !running)
		pa_schedule_raw(pa);
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
}

void pa_flood_subscribe(pa_t pat, const struct pa_flood_callbacks *cb)
{
	struct pa *pa = (struct pa *)pat;
	memcpy(&pa->fcb, cb, sizeof(*cb));
}

/**************************************************************/
/******************* Lookup functions *************************/
/**************************************************************/

struct pa_dp *pa_dp_getbyprefix(struct pa *pa, const struct prefix *p,
		bool local)
{
	struct pa_dp *iter;
	struct pa_dp *first;
	struct pa_dp *last;

	first = avl_find_ge_element(&pa->dps, p, first, avl_node);
	last = avl_find_le_element(&pa->dps, p, first, avl_node);

	avl_for_element_range(first, last, iter, avl_node) {
		if(iter->local == local)
			return iter;
	}

	return NULL;
}

#define pa_lap_getbyprefix(pa, prefix) \
		(struct pa_lap *)avl_find(&pa->laps, prefix)

#define pa_eap_getbyprefix(pa, prefix) \
		(struct pa_eap *)avl_find(&pa->eaps, prefix)


/**************************************************************/
/********************* eap managment **************************/
/**************************************************************/

static struct pa_eap *pa_eap_create(struct pa *pa, const struct prefix *prefix,
		const char *ifname)
{
	struct pa_eap *eap;

	if(strlen(ifname) > IFNAMSIZ - 1)
		return NULL;

	if(!(eap = malloc(sizeof(struct pa_eap))))
		return NULL;

	eap->to_delete = 1;
	eap->higher_priority = 1;
	eap->updated = 0;
	strcpy(eap->ifname, ifname);
	memcpy(&eap->prefix, prefix, sizeof(struct prefix));

	if(avl_insert(&pa->eaps, &eap->avl_node)) {
		free(eap);
		return NULL;
	}

	return eap;
}

static void pa_eap_destroy(struct pa *pa, struct pa_eap *eap)
{
	avl_delete(&pa->eaps, &eap->avl_node);
	free(eap);
}

/* Called when an eap is modified */
static void pa_eap_modified(struct pa *pa, struct pa_eap *eap)
{
	eap->updated = 1;
	pa_schedule(pa, PA_TODO_EAPS);
}

/**************************************************************/
/********************* lap managment **************************/
/**************************************************************/

static struct pa_lap *pa_lap_create(struct pa *pa, const struct prefix *prefix,
		const char *ifname)
{
	struct pa_lap *lap;

	if(strlen(ifname) > IFNAMSIZ - 1)
		return NULL;

	if(!(lap = malloc(sizeof(struct pa_lap))))
		return NULL;

	lap->assigned = 0;
	lap->flooded = 0;
	strcpy(lap->ifname, ifname);
	memcpy(&lap->prefix, prefix, sizeof(struct prefix));

	if(avl_insert(&pa->laps, &lap->avl_node)) {
		free(lap);
		return NULL;
	}

	return lap;
}

static void pa_lap_destory(struct pa *pa, struct pa_lap *lap)
{
	avl_delete(&pa->laps, &lap->avl_node);
	free(lap);
}


/**************************************************************/
/********************* dp managment **************************/
/**************************************************************/

/* Creates an empty dp with the given prefix */
static struct pa_dp *pa_dp_create(struct pa *pa, const struct prefix *prefix,
		bool local)
{
	struct pa_dp *dp;
	if(!(dp = malloc(sizeof(struct pa_dp))))
		return NULL;

	//Init
	memcpy(&dp->prefix, prefix, sizeof(struct prefix));
	dp->valid_until = 0;
	dp->prefered_until = 0;
	dp->updated = 0;
	dp->local = local;

	if(avl_insert(&pa->dps, &dp->avl_node)) {
		free(dp);
		return NULL;
	}

	return dp;
}

/* Final and dummy destroy of a ldp */
static void pa_dp_destroy(struct pa *pa, struct pa_dp *dp)
{
	//TODO: Remove all laps poiting to that dp.

	avl_delete(&pa->dps, &dp->avl_node);
	free(dp);
}

/* A ldp has been modified */
static void pa_dp_modified(struct pa *pa, struct pa_dp *dp)
{
	dp->updated = 1;
	pa_schedule(pa, PA_TODO_DP);

	/* Notify hcp */
	if(pa->fcb.updated_ldp && dp->local)
		pa->fcb.updated_ldp(&dp->prefix, dp->valid_until,
				dp->prefered_until, pa->fcb.priv);
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

}


/**************************************************************/
/******************* iface managment **************************/
/**************************************************************/


static struct pa_iface *pa_iface_create(const char *ifname)
{
	struct pa_iface *iface;

	if(strlen(ifname) > IFNAMSIZ - 1)
		return NULL; //Name too long

	if(!(iface = malloc(sizeof(struct pa_iface))))
		return NULL;

	strcpy(iface->ifname, ifname);
	iface->run_pa = 0;
	iface->updated = 0;
	return iface;
}

/* Last dummy iface delete */
static void pa_iface_destroy(struct pa_iface *iface)
{
	list_del(&iface->le);
	free(iface);
}

static struct pa_iface *pa_iface_getbyname(struct pa *pa, const char *ifname)
{
	struct pa_iface *iface;
	list_for_each_entry(iface, &pa->ifaces, le) {
		if(!strcmp(ifname, iface->ifname))
				return iface;
	}
	return NULL;
}

static void pa_iface_modified(struct pa *pa, struct pa_iface *iface)
{
	/* Schedule new pa algo for iface change */
	iface->updated = 1;

	pa_schedule(pa, PA_TODO_IFACE);
}

/**************************************************************/
/********************* hcp interface **************************/
/**************************************************************/

void pa_set_global_leadership(pa_t pat, bool leadership)
{
	struct pa *pa = (struct pa *)pat;
	if(leadership == pa->global_leadership)
		return;

	pa->global_leadership = leadership;

	pa_schedule(pa, PA_TODO_LEADER);
}

/* Called by hcp when it wants to update an eap */
int pa_update_eap(pa_t pat, const struct prefix *prefix, const char *ifname,
					bool to_delete, bool higher_priority)
{
	struct pa *pa = (struct pa *)pat;
	struct pa_eap *eap = pa_eap_getbyprefix(pa, prefix);

	if(!eap) {
		if(to_delete)
			return 0;

		eap = pa_eap_create(pa, prefix, (ifname)?ifname:PA_NO_IFACE);
	}

	if(!eap)
		return -1;

	if(to_delete == eap->to_delete &&
			eap->higher_priority == higher_priority)
		return 0;

	eap->to_delete = to_delete;

	pa_eap_modified(pa, eap);

	return 0;
}

int pa_update_edp(pa_t pat, const struct prefix *prefix,
				time_t valid_until, time_t prefered_until)
{
	struct pa *pa = (struct pa *)pat;
	struct pa_dp *edp = pa_dp_getbyprefix(pa, prefix, false);

	if(!edp) {
		if(!valid_until)
			return 0;
		edp = pa_dp_create(pa, prefix, false);
	}

	if(!edp)
		return -1;

	if(edp->valid_until == valid_until && edp->prefered_until)
		return 0;

	edp->valid_until = valid_until;
	edp->prefered_until = prefered_until;

	pa_dp_modified(pa, edp);

	return 0;
}


/**************************************************************/
/********************* iface interface ************************/
/**************************************************************/

/* Called when iface.c wants us to run pa on an iface */
static void pa_iface_set_runpa(struct pa *pa, const char *ifname,
		bool run_pa)
{
	struct pa_iface *iface = pa_iface_getbyname(pa, ifname);

	if(!iface) {
		if(!run_pa)
			return;

		iface = pa_iface_create(ifname);
	}

	if(run_pa == iface->run_pa)
		return;

	iface->run_pa = run_pa;

	pa_iface_modified(pa, iface);
}


/* When a locally dedicated prefix needs to be updated */
static int pa_ldp_update(struct pa *pa, const struct prefix *prefix,
			time_t valid_until, time_t prefered_until)
{
	struct pa_dp *ldp;

	ldp = pa_dp_getbyprefix(pa, prefix, true);

	if(!ldp) {
		if(!valid_until) //Unknown ldp needs to be destroyed... That was easy.
			return 0;

		ldp = pa_dp_create(pa, prefix, 1);
	}

	if(!ldp)
		return -1;

	if(ldp->valid_until == valid_until &&
			ldp->prefered_until == prefered_until)
		return 0;

	ldp->valid_until = valid_until;
	ldp->prefered_until = prefered_until;

	pa_dp_modified(pa, ldp);

	return 0;
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

	memset(&pa, 0, sizeof(pa));

	avl_init(&pa->eaps, pa_avl_prefix_cmp, false, NULL);
	avl_init(&pa->laps, pa_avl_prefix_cmp, false, NULL);
	avl_init(&pa->dps, pa_avl_prefix_cmp, true, NULL);
	INIT_LIST_HEAD(&pa->ifaces);

	pa->started = 0;
	pa->todo_flags = 0;

	memset(&pa->pa_timeout, 0, sizeof(pa->pa_timeout));
	pa->pa_timeout.cb = pa_do_uloop;

	if(pa_set_conf(pa, conf)) {
		free(pa);
		return NULL;
	}

	pa_schedule(pa, PA_TODO_ULA);

	return pa;
}

int pa_start(pa_t pat)
{
	struct pa *pa = (struct pa *)pat;
	//TODO: register to iface.c for iface updates
	//TODO: register to iface.c for PDs updates

	if(!pa->started) {
		pa->started = 1;
		/* Starts the pa for real */
		pa_schedule_raw(pa);
	}

	return 0;
}

void pa_destroy(pa_t pat)
{
	struct pa *pa = (struct pa *)pat;
	//TODO: Destroy everything
	free(pa);
}

