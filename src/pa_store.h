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

struct pa_store;

/* Creates a storage structure for pa
 * @arg db_file_path The path to the file that must be used as db
 * @return A pointer to an initialized pa_store struct,
 *         NULL otherwise. */
struct pa_store *pa_store_create(const char *db_file_path);

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

/* Sets the saved ula value.
 * @arg store An initialized pa_store struct.
 * @arg prefix The ula prefix to save.
 */
void pa_store_ula_set(struct pa_store *store,
		const struct prefix *prefix);

/* Get the saved ula prefix value.
 * @arg An initialized pa_store struct.
 * @return The stored ula prefix, or NULL if not set.
 */
const struct prefix *pa_store_ula_get(struct pa_store *store);

#endif
