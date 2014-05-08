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
	struct list_head rules;     /* Contains configured prefixes. */
};

/* A static prefix is a way to override normal prefix selection.
 * It will never be used if another prefix with higher priority is already used.
 * If authoritative is set. It can always be used.
 * But in any case, a prefix is never set if there is no associated dp. */
struct pa_core_rule {
	enum {
		PACR_PREFIX,                 /* Used to set a particular prefix */
		PACR_NUMBER                  /* Used to number an interface */
	} type;
	uint32_t rule_priority;          /* Rules are applied from higer to lower priority */
	char ifname[IFNAMSIZ];           /* The ifname, or a null string if can apply to any interface */
	uint8_t priority;                /* Prefix pa priority */
	bool authoritative;              /* Prefix pa authority */
	bool propose_if_not_designated;  /* Will be proposed even if the router is not designated */
	bool override;                   /* Will be proposed even if another prefix exists */
/* private to pa_core */
	struct list_head le;
	struct btrie cpls;
};

struct pa_core_static_prefix {
	struct pa_core_rule rule;        /* A rule with type PACR_PREFIX */
	struct prefix prefix;            /* The static prefix */
};

struct pa_core_static_number {
	struct pa_core_rule rule;        /* A rule with type PACR_NUMBER */
	uint32_t number;
	uint8_t number_len;
};

void pa_core_init(struct pa_core *);
void pa_core_start(struct pa_core *);
void pa_core_stop(struct pa_core *);
void pa_core_term(struct pa_core *);

void pa_core_rule_add(struct pa_core *core, struct pa_core_rule *rule);
void pa_core_rule_del(struct pa_core *core, struct pa_core_rule *rule);

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
