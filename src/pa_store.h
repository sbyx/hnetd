/*
 * Author: Pierre Pfister
 *
 * This file provide stable storage API for pa.c
 * It is used to store prefixes on a per interface basis,
 * and one ULA prefix.
 *
 */

#ifndef PA_STORE_H
#define PA_STORE_H

#include "prefix_utils.h"

#define PA_STORE_DFLT_MAX_PX      100
#define PA_STORE_DFLT_MAX_PX_P_IF 10

struct pa_store_conf {
	/* Maximum number of prefixes.
	 * 0 means unlimited.
	 * Default is PA_STORE_DFLT_MAX_PX. */
	size_t max_px;

	/* Maximum number of prefixes per interface.
	 * 0 means unlimited.
	 * Default is PA_STORE_DFLT_MAX_PX_P_IF. */
	size_t max_px_per_if;
};

/* Returns 1 if result matches and should be returned
 * by iterator. 0 if the iterator should look at next entry. */
typedef int (*pa_store_matcher)(const struct prefix *p, const char *ifname,  void *priv);

struct pa_store;

/* Creates a storage structure for pa
 * @arg db_file_path The path to the file that must be used as db
 * @arg conf Configuration paramaters for the storage. NULL means default.
 * @return A pointer to an initialized pa_store struct,
 *         NULL otherwise. */
struct pa_store *pa_store_create(const struct pa_store_conf *conf, const char *db_file_path);

/* Destroys a pa_store struct.
 * @arg store An initialized pa_store struct */
void pa_store_destroy(struct pa_store *store);

/* Save a prefix in stable storage.
 * @arg store An initialized pa_store struct.
 * @arg ifname The interface name associated to the assignment
 * @arg prefix The prefix to store.
 * @return 0 on success, -1 on error
 */
int pa_store_prefix_add(struct pa_store *store,
		const char *ifname, const struct prefix *prefix);

/* Look for a comp&tible prefix in the database.
 * @arg store An initialized pa_store struct.
 * @arg ifname An interface the prefix must be associated with.
 *             NULL if any interface can match.
 * @arg delegated A delegated prefix the returned prefix must be in.
 *                NULL if any prefix can match.
 * @return A prefix that matches request, or NULL of not found.
 */
const struct prefix *pa_store_prefix_get(struct pa_store *store,
		const char *ifname, const struct prefix *delegated);

const struct prefix *pa_store_prefix_find(struct pa_store *store,
		const char *ifname, pa_store_matcher matcher, void *priv);

/* Sets the saved ula value.
 * @arg store An initialized pa_store struct.
 * @arg prefix The ula prefix to save.
 * @return 0 on success, -1 on error
 */
int pa_store_ula_set(struct pa_store *store,
		const struct prefix *prefix);

/* Get the saved ula prefix value.
 * @arg An initialized pa_store struct.
 * @return The stored ula prefix, or NULL if not set.
 */
const struct prefix *pa_store_ula_get(struct pa_store *store);

/* Deletes all entries in memory and in db file
 * @arg store An initialized pa_store struct.
 * @return 0 on success, -1 on error */
int pa_store_empty(struct pa_store *store);

#endif
