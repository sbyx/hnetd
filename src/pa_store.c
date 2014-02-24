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
#define PAS_TYPE_SP  0x00
#define PAS_TYPE_ULA 0x01
#define PAS_TYPE_SA 0x02

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

static int pas_address_write(struct in6_addr *addr, FILE *f)
{
	L_DEBUG("Writing address %s", ADDR_REPR(addr));
	if(fwrite(addr, sizeof(struct in6_addr), 1, f) != 1)
				return -1;
	return 0;
}

static int pas_address_read(struct in6_addr *addr, FILE *f)
{
	if(fread(addr, sizeof(struct in6_addr), 1, f) != 1)
			return -1;
	L_DEBUG("Read address %s", ADDR_REPR(addr));
	return 0;
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
	if(fread(&p->prefix, sizeof(struct in6_addr), 1, f) != 1 ||
			fread(&p->plen, 1, 1, f) != 1)
			return -1;
	L_DEBUG("Read prefix %s", PREFIX_REPR(p));
	return 0;
}

static int pas_ula_load(struct pa_store *store, FILE *f)
{
	struct prefix p;
	if(pas_prefix_read(&p, f))
		return -1;

	memcpy(&store->ula, &p, sizeof(struct prefix));
	store->ula_valid = 1;
	return 0;
}

static int pas_ula_save(struct pa_store *store, FILE *f)
{
	if(pas_prefix_write(&store->ula, f))
		return -1;
	return 0;
}

static int pas_sp_load(struct pa_store *store, FILE *f)
{
	struct prefix p;
	char ifname[IFNAMSIZ] = {0}; //Init for valgrind tests
	if(pas_prefix_read(&p, f) ||
			pas_ifname_read(ifname, f))
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

static int pas_sp_save(struct pa_sp *sp, FILE *f)
{
	if(pas_prefix_write(&sp->prefix, f) || pas_ifname_write(sp->iface->ifname, f))
		return -1;
	return 0;
}

static int pas_sa_load(struct pa_store *store, FILE *f)
{
	struct in6_addr addr;
	if(pas_address_read(&addr, f))
		return -1;

	struct pa_sa *sa = pa_sa_get(store_p(store, data), &addr, true);
	if(!sa)
		return -2;

	pa_sa_promote(store_p(store, data), sa);
	return 0;
}

static int pas_sa_save(struct pa_sa *sa, FILE *f)
{
	return pas_address_write(&sa->addr, f)?-1:0;
}

static int pas_load(struct pa_store *store)
{
	uint8_t type;
	FILE *f;
	int err = 0;

	if(!store->filename)
		return 0;

	if(!(f = fopen(store->filename, "r"))) {
		L_WARN("Cannot open file %s (write mode)", store->filename);
		return -1;
	}
	L_INFO("Loading prefixes and ULA");
	while(!err) {
		/* Get type */
		if(fread(&type, 1, 1, f) != 1)
			break;

		switch (type) {
			case PAS_TYPE_SP:
				err = pas_sp_load(store, f);
				break;
			case PAS_TYPE_ULA:
				err = pas_ula_load(store, f);
				break;
			case PAS_TYPE_SA:
				err = pas_sa_load(store, f);
				break;
			default:
				L_DEBUG("Invalid type");
				return -2;
		}
	}
	fclose(f);
	return err;
}


static int pas_save(struct pa_store *store)
{
	struct pa_sp *sp;
	struct pa_sa *sa;
	char type;
	FILE *f;

	if(!store->filename)
		return 0;

	if(!(f = fopen(store->filename, "w"))) {
		L_WARN("Cannot open file %s (write mode)", store->filename);
		return -1;
	}
	L_INFO("Saving prefixes and ULA");
	type = PAS_TYPE_ULA;
	if(store->ula_valid &&
			((fwrite(&type, 1, 1, f) != 1) || pas_ula_save(store, f) ))
		goto err;

	type = PAS_TYPE_SP;
	pa_for_each_sp_reverse(sp, store_p(store, data)) {
		if((fwrite(&type, 1, 1, f) != 1) || pas_sp_save(sp, f))
			goto err;
	}

	type = PAS_TYPE_SA;
	pa_for_each_sa_reverse(sa, store_p(store, data)) {
		if((fwrite(&type, 1, 1, f) != 1) || pas_sa_save(sa, f))
			goto err;
	}

	fclose(f);
	return 0;
err:
	L_WARN("Writing error");
	fclose(f);
	return -2;
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
			pas_save(store);
		}
	}
}

static void __pa_store_aas(struct pa_data_user *user, struct pa_aa *aa, uint32_t flags) {
	struct pa_store *store = container_of(user, struct pa_store, data_user);
	struct pa_data *data = store_p(store, data);
	struct pa_laa *laa;
	if(aa->local && (flags & PADF_LAA_APPLIED) && (laa = container_of(aa, struct pa_laa, aa))->applied) {
		struct pa_sa *sa = pa_sa_get(data, &aa->address, true);
		if(sa) {
			pa_sa_promote(data, sa);
			pas_save(store);
		}
	}
}

int pa_store_setfile(struct pa_store *store, const char *filepath)
{
	if(filepath) {
		L_NOTICE("Setting stable storage file %s", filepath);
	} else {
		L_NOTICE("Removing stable storage file");
	}

	if(store->filename) {
		free(store->filename);
		store->filename = NULL;
	}

	if(filepath) {
		if(!(store->filename = malloc(strlen(filepath) + 1))) {
			L_WARN("Could not allocate space for file path");
			return -1;
		}
		strcpy(store->filename, filepath);
		pas_load(store);
	}

	return 0;
}

void pa_store_init(struct pa_store *store)
{
	store->started = false;
	store->filename = NULL;
	store->ula_valid = false;
	memset(&store->data_user, 0, sizeof(struct pa_data_user));
	store->data_user.cps = __pa_store_cps;
	store->data_user.dps = __pa_store_dps;
	store->data_user.aas = __pa_store_aas;
}

void pa_store_start(struct pa_store *store)
{
	if(store->started)
		return;

	store->started = true;
	pa_data_subscribe(store_p(store, data), &store->data_user);
	pas_load(store);
}

void pa_store_stop(struct pa_store *store)
{
	if(!store->started)
		return;
	L_DEBUG("Stop");
	pa_store_setfile(store, NULL);
	pa_data_unsubscribe(&store->data_user);
	store->started = false;
}

void pa_store_term(struct pa_store *store)
{
	pa_store_stop(store);
}

