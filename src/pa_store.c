/*
 * Author: Pierre Pfister
 *
 */

/* Loglevel redefinition */
#define PAS_L_LEVEL 7
#define PAS_L_PX
#ifdef PAS_L_LEVEL
#ifdef L_LEVEL
#undef L_LEVEL
#endif
#define L_LEVEL PAS_L_LEVEL
#endif

#define L_PREFIX "pa-store - "

#include "pa_store.h"

#include <libubox/list.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "hnetd.h"
#include "prefix_utils.h"

/* Storage format constants */

#define PAS_TYPE_AP  0x00
#define PAS_TYPE_ULA 0x01

struct pa_store {
	char *db_file;
	struct list_head ifaces;

	size_t ap_count;
	struct list_head aps;

	bool ula_valid;
	struct prefix ula;

	struct pa_store_conf conf;
};

struct pas_iface {
	char ifname[IFNAMSIZ];

	size_t ap_count;
	struct list_head aps;

	struct list_head le;
};

/* Assigned prefixes are linked both in iface and the
 * storage structure. */
struct pas_ap {
	struct prefix prefix;
	struct list_head st_le;
	struct list_head if_le;
	struct pas_iface *iface;
};

static void pas_ap_delete(struct pa_store *store, struct pas_ap *ap);

static void pas_iface_delete(struct pas_iface *iface)
{
	if(iface->ap_count) {
		L_ERR("Can't delete iface '%s' with %ld ap assigned", iface->ifname, iface->ap_count);
		return;
	}

	list_del(&iface->le);
	free(iface);
}

static inline void pas_iface_decr_ap_count(struct pas_iface *iface)
{
	if(!(--(iface->ap_count)))
		pas_iface_delete(iface);
}

static inline void pas_iface_incr_ap_count(struct pa_store *store,
		struct pas_iface *iface)
{
	if(store->conf.max_px_per_if && (iface->ap_count == store->conf.max_px_per_if)) {
		++(iface->ap_count);
		pas_ap_delete(store, list_last_entry(&iface->aps, struct pas_ap, if_le));
	} else {
		++(iface->ap_count);
	}
}

static inline void pas_store_decr_ap_count(struct pa_store *store)
{
	store->ap_count--;
}

static inline void pas_store_incr_ap_count(struct pa_store *store)
{
	if(store->conf.max_px && (store->ap_count == store->conf.max_px)) {
		++(store->ap_count);
		pas_ap_delete(store, list_last_entry(&store->aps, struct pas_ap, st_le));
	} else {
		++(store->ap_count);
	}
}

static struct pas_ap *pas_ap_get(const struct pa_store *store, const struct prefix *prefix)
{
	struct pas_ap *ap;
	list_for_each_entry(ap, &store->aps, st_le) {
		if(!prefix_cmp(prefix, &ap->prefix))
			return ap;
	}
	return NULL;
}

static struct pas_ap *pas_ap_add(struct pa_store *store,
		struct pas_iface *iface, const struct prefix *prefix)
{
	struct pas_ap *ap;
	if(!(ap = malloc(sizeof(struct pas_ap))))
			return NULL;

	memcpy(&ap->prefix, prefix, sizeof(struct prefix));

	ap->iface = iface;
	list_add(&ap->if_le, &iface->aps);
	pas_iface_incr_ap_count(store, ap->iface);

	list_add(&ap->st_le, &store->aps);
	pas_store_incr_ap_count(store);

	return ap;
}

static void pas_ap_delete(struct pa_store *store, struct pas_ap *ap)
{
	L_DEBUG("Deleting ap %s%%%s", PREFIX_REPR(&ap->prefix), ap->iface->ifname);
	list_del(&ap->st_le);
	list_del(&ap->if_le);
	pas_store_decr_ap_count(store);
	pas_iface_decr_ap_count(ap->iface);
	free(ap);
}

static void pas_ap_promote(struct pa_store *store, struct pas_ap *ap, struct pas_iface *new_iface) {
	list_move(&ap->st_le, &store->aps);
	if(new_iface && new_iface != ap->iface) {
		list_move(&ap->if_le, &new_iface->aps);
		pas_iface_decr_ap_count(ap->iface);
		ap->iface = new_iface;
		pas_iface_incr_ap_count(store, ap->iface);
	} else {
		list_move(&ap->if_le, &ap->iface->aps);
	}
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

static struct pas_iface *pas_iface_get(struct pa_store *store, const char *ifname)
{
	struct pas_iface *iface;
	list_for_each_entry(iface, &store->ifaces, le) {
		if(!strcmp(ifname, iface->ifname))
			return iface;
	}
	return NULL;
}

static struct pas_iface *pas_iface_add(struct pa_store *store, const char *ifname)
{
	struct pas_iface *iface;
	if(strlen(ifname) >= IFNAMSIZ)
		return NULL;

	if(!(iface = malloc(sizeof(struct pas_iface))))
		return NULL;

	strcpy(iface->ifname, ifname);
	iface->ap_count = 0;
	list_add(&iface->le, &store->ifaces);
	INIT_LIST_HEAD(&iface->aps);

	return iface;
}

int pas_ap_add_by_ifname(struct pa_store *store,
		const char *ifname, const struct prefix *prefix)
{
	struct pas_ap *ap;
	struct pas_iface *iface;

	if(!(iface = pas_iface_get(store, ifname)))
		iface = pas_iface_add(store, ifname);

	if(!iface)
		return -1;

	if((ap = pas_ap_get(store, prefix))) {
		L_DEBUG("Promoting prefix %s on iface %s", PREFIX_REPR(prefix), ifname);
		pas_ap_promote(store, ap, iface);
	} else {
		L_DEBUG("Adding prefix %s on iface %s", PREFIX_REPR(prefix), ifname);
		ap = pas_ap_add(store, iface, prefix);
	}

	return (ap)?0:-1;
}

/* Removes all entries from the storage */
static void pas_empty(struct pa_store *store)
{
	struct pas_ap *ap, *sap;

	list_for_each_entry_safe(ap, sap, &store->aps, st_le)
		pas_ap_delete(store, ap);

	/* Iface destruction is automatic when ap_count go to 0 */
	store->ula_valid = 0;
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

static int pas_ap_load(struct pa_store *store, FILE *f)
{
	struct prefix p;
	char ifname[IFNAMSIZ] = {0}; //Init for valgrind tests
	if(pas_prefix_read(&p, f) ||
			pas_ifname_read(ifname, f) ||
			pas_ap_add_by_ifname(store, ifname, &p))
		return -1;

	return 0;
}

static int pas_ap_save(struct pas_ap *ap, FILE *f)
{
	if(pas_prefix_write(&ap->prefix, f) || pas_ifname_write(ap->iface->ifname, f))
		return -1;
	return 0;
}

/* Loads the file.
 * returns -1 if the file cannot be written.
 * Entries are stored from the oldest to the newest. */
static int pas_load(struct pa_store *store)
{
	FILE *f;
	uint8_t type;
	int err = 0;

	/* Test file exists */
	if(access(store->db_file, F_OK)) {
		L_INFO("File %s doesn't exist", store->db_file);
		return 0;
	}

	if(!(f = fopen(store->db_file, "r"))) {
		L_WARN("Could not read file %s", store->db_file);
		return -1;
	}

	pas_empty(store);

	while(!err) {
		/* Get type */
		if(fread(&type, 1, 1, f) != 1)
			break;

		switch (type) {
			case PAS_TYPE_AP:
				err = pas_ap_load(store, f);
				break;
			case PAS_TYPE_ULA:
				err = pas_ula_load(store, f);
				break;
			default:
				L_DEBUG("Invalid type");
				return -2;
		}
	}

	fclose(f);
	return err;
}

/* Saves the cached data to the file.
 * returns -1 if the file cannot be written. */
static int pas_save(struct pa_store *store)
{
	L_DEBUG("Saving into file %s", store->db_file);

	FILE *f;
	struct pas_ap *ap;
	char type;
	if(!(f = fopen(store->db_file, "w"))) {
		L_WARN("Could not write to file %s", store->db_file);
		return -1;
	}

	type = PAS_TYPE_ULA;
	if(store->ula_valid &&
			((fwrite(&type, 1, 1, f) != 1) || pas_ula_save(store, f) ))
		goto err;

	type = PAS_TYPE_AP;
	list_for_each_entry_reverse(ap, &store->aps, st_le) {
		if((fwrite(&type, 1, 1, f) != 1) || pas_ap_save(ap, f))
			goto err;
	}
	fclose(f);
	return 0;
err:
	fclose(f);
	return -1;
}

struct pa_store *pa_store_create(const struct pa_store_conf *conf, const char *db_file_path) {

	if(!db_file_path)
		goto err;

	struct pa_store *store;
	if(!(store = malloc(sizeof(struct pa_store))))
		goto err;

	if(!(store->db_file = malloc(strlen(db_file_path) + 1)))
		goto namerr;

	strcpy(store->db_file, db_file_path);
	INIT_LIST_HEAD(&store->ifaces);
	INIT_LIST_HEAD(&store->aps);
	store->ap_count = 0;
	store->ula_valid = false;

	store->conf.max_px = (conf)?conf->max_px:PA_STORE_DFLT_MAX_PX;
	store->conf.max_px_per_if = (conf)?conf->max_px_per_if:PA_STORE_DFLT_MAX_PX;

	/* Loading given file */
	if(pas_load(store)) {
		pa_store_destroy(store);
		return NULL;
	}

	return store;

namerr:
	free(store);
err:
	return NULL;
}

void pa_store_destroy(struct pa_store *store) {
	pas_empty(store);
	free(store->db_file);
	free(store);
}

int pa_store_prefix_add(struct pa_store *store,
		const char *ifname, const struct prefix *prefix)
{
	if(pas_ap_add_by_ifname(store, ifname, prefix))
		return -1;

	return pas_save(store);
}

static int pas_matcher_prefix(const struct prefix *prefix,
		__attribute__((unused))const char *ifname, void *priv)
{
	if(!priv)
		return 1;

	return prefix_contains((struct prefix *)priv, prefix);
}

const struct prefix *pa_store_prefix_get(struct pa_store *store,
		const char *ifname, struct prefix *delegated)
{
	return pa_store_prefix_find(store, ifname, pas_matcher_prefix, delegated);
}

const struct prefix *pa_store_prefix_find(struct pa_store *store,
		const char *ifname, pa_store_matcher matcher, void *priv)
{
	struct pas_iface *iface;
	struct pas_ap *ap;
	if(ifname) {
		iface = pas_iface_get(store, ifname);
		if(!iface)
			return NULL;

		list_for_each_entry(ap, &iface->aps, if_le) {
			if((!matcher || matcher(&ap->prefix, ifname, priv)))
				return &ap->prefix;
		}
	} else {
		list_for_each_entry(ap, &store->aps, st_le) {
			if((!matcher || matcher(&ap->prefix, ifname, priv)))
				return &ap->prefix;
		}
	}

	return NULL;
}

int pa_store_ula_set(struct pa_store *store,
		const struct prefix *prefix)
{
	memcpy(&store->ula, prefix, sizeof(struct prefix));
	store->ula_valid = 1;
	return pas_save(store);
}

const struct prefix *pa_store_ula_get(struct pa_store *store)
{
	if(!store->ula_valid)
		return NULL;

	return &store->ula;
}

int pa_store_empty(struct pa_store *store)
{
	pas_empty(store);
	return pas_save(store);
}
