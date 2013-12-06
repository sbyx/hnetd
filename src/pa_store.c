/*
 * Author: Pierre Pfister
 *
 */

/* Loglevel redefinition */
#define PAS_L_LEVEL 7
#define PAS_L_PX "pa-store - "
#ifdef PAS_L_LEVEL
#ifdef L_LEVEL
	#undef L_LEVEL
#endif
	#define L_LEVEL PAS_L_LEVEL
#endif

#include "pa_store.h"

#include <libubox/list.h>
#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "hnetd.h"
#include "prefix_utils.h"

/* Storage format constants */

#define PAS_TYPE_AP  0x00
#define PAS_TYPE_ULA 0x01

struct pa_store {
	char *db_file;
	struct list_head ifaces;
	struct list_head aps;

	bool ula_valid;
	struct prefix ula;
};

/* An iface is linked in the storage structure
 * and contains a aps linked list */
struct pas_iface {
	char ifname[IFNAMSIZ];
	struct list_head aps;
	struct list_head le;
};

/* Assigned prefixes are linked both in iface and the
 * storage structure. */
struct pas_ap {
	struct prefix prefix;
	struct list_head if_le;
	struct list_head st_le;
	struct pas_iface *iface;
};

static inline void pas_iface_delete_raw(struct pas_iface *iface)
{
	list_del(&iface->le);
	free(iface);
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
	list_add(&ap->st_le, &store->aps);

	return ap;
}

static void pas_ap_delete(struct pas_ap *ap, bool iface_autoclean)
{
	list_del(&ap->if_le);
	list_del(&ap->st_le);
	if(iface_autoclean && list_empty(&ap->iface->aps)) {
		pas_iface_delete_raw(ap->iface);
	}
	free(ap);
}

/* Promoted an ap while note changing the iface */
static void pas_ap_promote(struct pa_store *store, struct pas_ap *ap, struct pas_iface *new_iface) {
	list_del(&ap->if_le);
	list_del(&ap->st_le);
	ap->iface = new_iface;
	list_add(&ap->if_le, &new_iface->aps);
	list_add(&ap->st_le, &store->aps);
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
	L_DEBUG(PAS_L_PX"Writing prefix %s", PREFIX_TOSTRING(p, 1));
	if(fwrite(&p->prefix, sizeof(struct in6_addr), 1, f) != 1 ||
				fwrite(&p->plen, 1, 1, f) != 1)
				return -1;
		return 0;
}

static int pas_prefix_read(struct prefix *p, FILE *f)
{
	L_DEBUG(PAS_L_PX"Trying to read prefix");
	if(fread(&p->prefix, sizeof(struct in6_addr), 1, f) != 1 ||
			fread(&p->plen, 1, 1, f) != 1)
			return -1;
	L_DEBUG(PAS_L_PX"Read prefix %s", PREFIX_TOSTRING(p, 1));
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
	INIT_LIST_HEAD(&iface->aps);
	list_add(&iface->le, &store->ifaces);

	return iface;
}

static struct pas_ap *pas_ap_add_by_ifname(struct pa_store *store,
		const char *ifname, const struct prefix *prefix)
{
	struct pas_ap *ap;
	struct pas_iface *iface;

	if(!(iface = pas_iface_get(store, ifname)))
		iface = pas_iface_add(store, ifname);

	if(!iface)
		return NULL;

	if((ap = pas_ap_get(store, prefix))) {
		pas_ap_promote(store, ap, iface);
	} else {
		ap = pas_ap_add(store, iface, prefix);
	}

	return ap;
}

static void pas_iface_delete(struct pas_iface *iface)
{
	struct pas_ap *ap, *sap;

	list_for_each_entry_safe(ap, sap, &iface->aps, if_le) {
		pas_ap_delete(ap, false);
	}

	pas_iface_delete_raw(iface);
}

/* Removes all entries from the storage */
static void pas_empty(struct pa_store *store)
{
	struct pas_iface *i, *si;
	list_for_each_entry_safe(i, si, &store->ifaces, le) {
		pas_iface_delete(i);
	}
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
	char ifname[IFNAMSIZ];
	if(pas_prefix_read(&p, f) ||
			pas_ifname_read(ifname, f) ||
			!pas_ap_add_by_ifname(store, ifname, &p))
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
	L_DEBUG(PAS_L_PX"Loading from file %s", store->db_file);

	FILE *f;
	uint8_t type;
	int err = 0;

	/* Test authorizations */

	if(!(f = fopen(store->db_file, "r"))) {
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
				L_DEBUG(PAS_L_PX"Invalid type");
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
	L_DEBUG(PAS_L_PX"Saving into file %s", store->db_file);

	FILE *f;
	struct pas_ap *ap;
	char type;
	if(!(f = fopen(store->db_file, "w")))
		return -1;
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

struct pa_store *pa_store_create(const char *db_file_path) {

	if(!db_file_path)
		goto err;

	struct pa_store *store;
	if(!(store = malloc(sizeof(struct pa_store))))
		goto err;

	if(!(store->db_file = malloc(strlen(db_file_path + 1))))
		goto namerr;

	strcpy(store->db_file, db_file_path);
	INIT_LIST_HEAD(&store->ifaces);
	INIT_LIST_HEAD(&store->aps);
	store->ula_valid = false;

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
	if(!pas_ap_add_by_ifname(store, ifname, prefix))
		return -1;

	return pas_save(store);
}

const struct prefix *pa_store_prefix_get(struct pa_store *store,
		const char *ifname, const struct prefix *delegated)
{
	struct pas_iface *iface;
	struct pas_ap *ap;
	if(ifname) {
		iface = pas_iface_get(store, ifname);
		if(!iface)
			return NULL;
		list_for_each_entry(ap, &iface->aps, if_le) {
			if(!delegated || prefix_contains(delegated, &ap->prefix))
				return &ap->prefix;
		}
	} else {
		list_for_each_entry(ap, &store->aps, st_le) {
			if(!delegated || prefix_contains(delegated, &ap->prefix))
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


