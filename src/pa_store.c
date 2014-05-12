#define L_PREFIX "pa-store - "

#include <arpa/inet.h>

#include "pa_store.h"
#include "pa.h"

#define store_pa(store) (container_of(store, struct pa, store))
#define store_p(store, next) (&store_pa(store)->next)

/* Storage format constants */
#define PAS_TYPE_SP  0x00
#define PAS_TYPE_ULA 0x01
#define PAS_TYPE_SA 0x02
#define PAS_TYPE_DELAY 0x03 /* Delay in min that was used for the previous write */

#define PAS_DELAY_MIN INT64_C(10*60)*HNETD_TIME_PER_SECOND
#define PAS_DELAY_MAX INT64_C(24*60*60)*HNETD_TIME_PER_SECOND /* 24h */

/* This algorithm will allow writes to stable storage if and only if no
 * modifications are made during an increasing delay. The delay is 5min when the
 * router is flashed, and will double at each writes up to 24h.
 * Todo: Be more clever about when it is needed to write the file. */
static hnetd_time_t pas_next_delay(hnetd_time_t prev)
{
	if(prev < PAS_DELAY_MIN)
		return PAS_DELAY_MIN;

	hnetd_time_t next = prev * 2;
	return (next > PAS_DELAY_MAX) ? PAS_DELAY_MAX : next;
}

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
	//L_DEBUG("Writing address %s", ADDR_REPR(addr));
	if(fwrite(addr, sizeof(struct in6_addr), 1, f) != 1)
				return -1;
	return 0;
}

static int pas_address_read(struct in6_addr *addr, FILE *f)
{
	if(fread(addr, sizeof(struct in6_addr), 1, f) != 1)
			return -1;
	//L_DEBUG("Read address %s", ADDR_REPR(addr));
	return 0;
}

static int pas_prefix_write(struct prefix *p, FILE *f)
{
	//L_DEBUG("Writing prefix %s", PREFIX_REPR(p));
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
	//L_DEBUG("Read prefix %s", PREFIX_REPR(p));
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

static int pas_delay_load(struct pa_store *store, FILE *f)
{
	uint32_t minutes;
	if(fread(&minutes, sizeof(minutes), 1, f) != 1)
		return -1;
	minutes = ntohl(minutes);
	store->save_delay = pas_next_delay(minutes * 60*HNETD_TIME_PER_SECOND);
	return 0;
}

static int pas_delay_save(struct pa_store *store, FILE *f)
{
	uint32_t minutes = htonl((uint32_t) (store->save_delay / (60*HNETD_TIME_PER_SECOND)));
	if(fwrite(&minutes, sizeof(minutes), 1, f) != 1)
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

	if(!store->filename || !store->started)
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
			case PAS_TYPE_DELAY:
				err = pas_delay_load(store, f);
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

	type = PAS_TYPE_DELAY;
	if(((fwrite(&type, 1, 1, f) != 1) || pas_delay_save(store, f) ))
			goto err;

	fclose(f);
	store->save_delay = pas_next_delay(store->save_delay); /* Getting next value */
	return 0;
err:
	L_WARN("Writing error");
	fclose(f);
	store->save_delay = pas_next_delay(store->save_delay); /* Getting next value */
	return -2;
}

void pas_save_cb(struct uloop_timeout *to)
{
	pas_save(container_of(to, struct pa_store, save_timeout));
}

void pas_save_schedule(struct pa_store *store)
{
	if(store->started) {
		uloop_timeout_set(&store->save_timeout, (int) store->save_delay);
	} else {
		store->save_timeout.pending = true;
	}
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
		if(!store->ula_valid || memcmp(&store->ula, &dp->prefix, sizeof(struct prefix))) {
			prefix_cpy(&store->ula, &dp->prefix);
			store->ula_valid = true;
			pas_save_schedule(store);
		}
	}
}

static void __pa_store_cps(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags) {
	if(cp->type != PA_CPT_L)
		return;

	struct pa_cpl *cpl = _pa_cpl(cp);
	struct pa_store *store = container_of(user, struct pa_store, data_user);
	struct pa_data *data = &container_of(user, struct pa, store.data_user)->data;
	struct pa_sp *sp;
	if(cpl && (flags & (PADF_CP_APPLIED)) && !(flags & PADF_CP_TODELETE) && cp->applied) {
		if(((sp = pa_sp_get(data, cpl->iface, &cp->prefix, false)) && (&sp->le != data->sps.next)) ||
				(sp = pa_sp_get(data, cpl->iface, &cp->prefix, true))) {
			pa_sp_promote(data, sp);
			pas_save_schedule(store);
		}
	}
}

static void __pa_store_aas(struct pa_data_user *user, struct pa_aa *aa, uint32_t flags) {
	struct pa_store *store = container_of(user, struct pa_store, data_user);
	struct pa_data *data = store_p(store, data);
	struct pa_laa *laa;
	struct pa_sa *sa;
	if(aa->local && (flags & PADF_LAA_APPLIED) && (laa = container_of(aa, struct pa_laa, aa))->applied) {
		if( ((sa = pa_sa_get(data, &aa->address, false)) && (&sa->le != data->sas.next)) ||
				(sa = pa_sa_get(data, &aa->address, true))) {
			pa_sa_promote(data, sa);
			pas_save_schedule(store);
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

static int pa_rule_try_storage(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		__attribute__((unused))struct pa_ap *strongest_ap,
		__attribute__((unused))struct pa_cpl *current_cpl)
{
	struct pa_sp *sp;

	if(!iface->designated)
		return -1;

	pa_for_each_sp_in_iface(sp, iface) {
		if(prefix_contains(&dp->prefix, &sp->prefix) &&
				!pa_prefix_getcollision(container_of(core, struct pa, core), &sp->prefix)) {
			prefix_cpy(&rule->prefix, &sp->prefix);
			//prio, auth and advertise are set at init
			return 0;
		}
	}

	return -1;
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
	store->save_delay = pas_next_delay(0);
	memset(&store->save_timeout, 0, sizeof(struct uloop_timeout));
	store->save_timeout.cb = pas_save_cb;
	pa_core_rule_init(&store->pa_rule, "Stable storage", PACR_PRIORITY_STORAGE, NULL, pa_rule_try_storage);
	store->pa_rule.priority = PA_PRIORITY_DEFAULT;
	store->pa_rule.authoriative = false;
	store->pa_rule.advertise = true;
}

void pa_store_start(struct pa_store *store)
{
	if(store->started)
		return;

	store->started = true;
	if(store->save_timeout.pending) {
		store->save_timeout.pending = false;
		pas_save_schedule(store);
	}
	pa_data_subscribe(store_p(store, data), &store->data_user);
	pas_load(store);
	pa_core_rule_add(store_p(store, core), &store->pa_rule);
}

void pa_store_stop(struct pa_store *store)
{
	if(!store->started)
		return;
	if(store->save_timeout.pending)
		uloop_timeout_cancel(&store->save_timeout);
	pa_store_setfile(store, NULL);
	pa_data_unsubscribe(&store->data_user);
	pa_core_rule_del(store_p(store, core), &store->pa_rule);
	store->started = false;
}

void pa_store_term(struct pa_store *store)
{
	pa_store_stop(store);
}

