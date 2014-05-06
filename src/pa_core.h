/*
 * pa_core.h
 *
 * Author: Pierre Pfister
 *
 * Prefix assignment core.
 *
 * This file contains prefix assignment logic elements.
 *
 */

#ifndef PA_CORE_H_
#define PA_CORE_H_

#include "pa_data.h"
#include "pa_timer.h"
#include "hnetd.h"

struct pa_core {
	bool started;
	struct pa_timer paa_to;
	struct pa_timer aaa_to;
	struct pa_data_user data_user;
};

void pa_core_init(struct pa_core *);
void pa_core_start(struct pa_core *);
void pa_core_stop(struct pa_core *);
void pa_core_term(struct pa_core *);

/* Configures a new authoritative assignment on the given interface.
 * If the interface is destroyed or made external, the assignment will be destroyed.
 * If multiple authoritative assignments are made on the same link (either locally or by some other router),
 * only one of them will be used.
 * Returns 0 if the prefix is added. -1 if an error occurs or such prefix already existed on the given interface. */
int pa_core_static_prefix_add(struct pa_core *core, struct prefix *prefix, struct pa_iface *iface);

/* Removes a previously existing authoritative assignment.
 * Returns 0 if the prefix is removed, or -1 if no such authoritative prefix was assigned
 * on the given interface. */
int pa_core_static_prefix_remove(struct pa_core *core, struct prefix *prefix, struct pa_iface *iface);

#endif /* PA_CORE_H_ */
