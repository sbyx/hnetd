/*
 * Author: Pierre Pfister
 *
 * This file provide stable storage interface for prefix assignment.
 * It is used to store prefixes on a per interface basis,
 * and one ULA prefix.
 *
 */

#ifndef PA_STORE_H
#define PA_STORE_H

#include <stdio.h>

#include "prefix_utils.h"
#include "pa_data.h"

struct pa_store {
	bool started;
	bool ula_valid;
	struct prefix ula;
	struct pa_data_user data_user;
	FILE *f;
};

void pa_store_init(struct pa_store *);
void pa_store_start(struct pa_store *store);
int pa_store_setfile(struct pa_store *, const char *filepath);
void pa_store_term(struct pa_store *);
const struct prefix *pa_store_ula_get(struct pa_store *);

#endif
