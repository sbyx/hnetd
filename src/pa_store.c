#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL 7
#define L_PREFIX "pa-store - "

#include "pa_store.h"
#include "pa.h"

#define store_pa(store) (container_of(store, struct pa, store))
#define store_p(store, next) (&store_pa(store)->next)

/* Storage format constants */
#define PAS_TYPE_AP  0x00
#define PAS_TYPE_ULA 0x01

static int pas_ifname_write(char *ifname, FILE *f)
{
	if(fprintf(f, "%s", ifname) <= 0 || fputc('\0', f) < 0)
		return -1;
	return 0;
}

static int pas_ifname_read(char *ifname, FILE *f)
{
	int c;
	char *ptr = ifname;
	char *max = ifname + IFNAMSIZ; //First not valid
	while((c = fgetc(f))) {
		if(c < 0 || ptr == max)
			return -1;

		*(ptr++) = (char) c;
		if(!c)
			return 0;
	}

	return strlen(ifname)?0:-1;
}

static int pas_prefix_write(struct prefix *p, FILE *f)
{
	L_DEBUG("Writing prefix %s", PREFIX_REPR(p));
	if(fwrite(&p->prefix, sizeof(struct in6_addr), 1, f) != 1 ||
				fwrite(&p->plen, 1, 1, f) != 1)
				return -1;
		return 0;
}

static int pas_prefix_read(struct prefix *p, FILE *f)
{
	L_DEBUG("Trying to read prefix");
	if(fread(&p->prefix, sizeof(struct in6_addr), 1, f) != 1 ||
			fread(&p->plen, 1, 1, f) != 1)
			return -1;
	L_DEBUG("Read prefix %s", PREFIX_REPR(p));
	return 0;
}

static int pas_ula_load(struct pa_store *store)
{
	struct prefix p;
	if(pas_prefix_read(&p, store->f))
		return -1;

	memcpy(&store->ula, &p, sizeof(struct prefix));
	store->ula_valid = 1;
	return 0;
}

static int pas_ula_save(struct pa_store *store)
{
	if(pas_prefix_write(&store->ula, store->f))
		return -1;
	return 0;
}

static int pas_ap_load(struct pa_store *store)
{
	struct prefix p;
	char ifname[IFNAMSIZ] = {0}; //Init for valgrind tests
	if(pas_prefix_read(&p, store->f) ||
			pas_ifname_read(ifname, store->f))
		return -1;

	struct pa_iface *iface = pa_iface_get(store_p(store, data), ifname, true);
	if(!iface)
		return -2;

	struct pa_sp *sp = pa_sp_get(store_p(store, data), iface, &p, true);
	if(!sp)
		return -3;

	pa_sp_promote(store_p(store, data), sp);
	return 0;
}

static int pas_ap_save(struct pa_store *store, struct pa_sp *sp)
{
	if(pas_prefix_write(&sp->prefix, store->f) || pas_ifname_write(sp->iface->ifname, store->f))
		return -1;
	return 0;
}

static int pas_load(struct pa_store *store)
{
	uint8_t type;
	int err = 0;

	if(!store->f)
		return -1;

	if(!freopen(NULL, "r", store->f))
		return -2;

	while(!err) {
		/* Get type */
		if(fread(&type, 1, 1, store->f) != 1)
			break;

		switch (type) {
			case PAS_TYPE_AP:
				err = pas_ap_load(store);
				break;
			case PAS_TYPE_ULA:
				err = pas_ula_load(store);
				break;
			default:
				L_DEBUG("Invalid type");
				return -2;
		}
	}
	return err;
}


static int pas_save(struct pa_store *store)
{
	struct pa_sp *sp;
	char type;

	if(!store->f)
		return -1;

	if(!freopen(NULL, "w", store->f))
		return -1;

	type = PAS_TYPE_ULA;
	if(store->ula_valid &&
			((fwrite(&type, 1, 1, store->f) != 1) || pas_ula_save(store) ))
		return -2;

	type = PAS_TYPE_AP;
	pa_for_each_sp_reverse(sp, store_p(store, data)) {
		if((fwrite(&type, 1, 1, store->f) != 1) || pas_ap_save(store, sp))
			return -2;
	}

	return 0;
}

const struct prefix *pa_store_ula_get(struct pa_store *store)
{
	if(!store->ula_valid)
		return NULL;

	return &store->ula;
}

static void __pa_store_dps(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags) {
	struct pa_store *store = container_of(user, struct pa_store, data_user);
	if((flags & PADF_DP_CREATED) && dp->local && prefix_is_ipv6_ula(&dp->prefix)) {
		prefix_cpy(&store->ula, &dp->prefix);
		store->ula_valid = true;
		if(store->f)
			pas_save(store);
	}
}

static void __pa_store_cps(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags) {
	struct pa_store *store = container_of(user, struct pa_store, data_user);
	struct pa_data *data = &container_of(user, struct pa, store.data_user)->data;
	struct pa_sp *sp;
	if((flags & (PADF_CP_APPLIED | PADF_CP_IFACE)) && !(flags & PADF_CP_TODELETE) && cp->applied && cp->iface) {
		sp = pa_sp_get(data, cp->iface, &cp->prefix, true);
		if(sp) {
			pa_sp_promote(data, sp);
			if(store->f)
				pas_save(store);
		}
	}
}

void __pa_store_setfile(struct pa_store *store, FILE *f)
{
	if(store->f)
		fclose(store->f);
	store->f = f;
	if(store->started && store->f)
		pas_load(store);
}

int pa_store_setfile(struct pa_store *store, const char *filepath)
{
	if(filepath) {
		L_NOTICE("Opening file for stable storage %s", filepath);
	} else {
		L_NOTICE("Closing stable storage file");
	}
	__pa_store_setfile(store, fopen(filepath, "rw"));
	return ((filepath && store->f) || (!filepath && !store->f))?0:-1;
}

void pa_store_init(struct pa_store *store)
{
	store->started = false;
	store->f = NULL;
	store->ula_valid = false;
	memset(&store->data_user, 0, sizeof(struct pa_data_user));
	store->data_user.cps = __pa_store_cps;
	store->data_user.dps = __pa_store_dps;
}

void pa_store_start(struct pa_store *store)
{
	if(store->started)
		return;

	store->started = true;
	pa_data_subscribe(store_p(store, data), &store->data_user);
	if(store->f) {
		FILE *f = store->f;
		store->f = NULL;
		__pa_store_setfile(store, f);
	}
}

void pa_store_stop(struct pa_store *store)
{
	if(!store->started)
		return;

	if(store->f) {
		FILE *f = store->f;
		__pa_store_setfile(store, NULL);
		store->f = f;
	}
	pa_data_unsubscribe(&store->data_user);
	store->started = false;
}

void pa_store_term(struct pa_store *store)
{
	pa_store_stop(store);
}

