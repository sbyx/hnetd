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
#include <libubox/uloop.h>

#include "prefix_utils.h"
#include "pa_data.h"
#include "pa_core.h"
#include "pa_timer.h"

struct pa_store {
	struct pa_timer t;
	bool ula_valid;
	struct prefix ula;
	struct pa_data_user data_user;
	char *filename;
	hnetd_time_t save_delay;
	struct pa_rule pa_rule;
};

void pa_store_init(struct pa_store *);
void pa_store_start(struct pa_store *store);
void pa_store_stop(struct pa_store *store);
int pa_store_setfile(struct pa_store *, const char *filepath);
void pa_store_term(struct pa_store *);
const struct prefix *pa_store_ula_get(struct pa_store *);

#endif
