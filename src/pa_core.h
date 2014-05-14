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

struct pa_core;
struct pa_rule;

typedef int (*rule_try)(struct pa_core *core, struct pa_rule *rule,
		struct pa_dp *dp, struct pa_iface *iface,
		struct pa_ap *best_ap, struct pa_cpl *current_cpl);

/* Prefix selection uses rules. They are called in priority order
   each time the prefix assignment algorithm is run. */
struct pa_rule {
	const char *name;                /* Name of that rule, used for logging */

	uint32_t rule_priority;          /* Rules are applied in sorted order. */
#define PACR_PRIORITY_KEEP      1000  //Keep existing CPL if valid
#define PACR_PRIORITY_ACCEPT    2000  //Accept or update CPL from AP
#define PACR_PRIORITY_STORAGE   3000  //Priority used by stable storage prefix selection
#define PACR_PRIORITY_RANDOM    4000  //Priority used by random prefix selection
#define PACR_PRIORITY_SCARCITY  5000  //Random selection with reduced prefix length

	/* Called to try finding a prefix.
	 * Must return 0 if a prefix is found. A negative value otherwise.
	 * strongest_ap is the best valid concurrent ap on the iface.
	 * iface->designated must be taken into account as well.
	 * The proposed priority/auth value must be higher than strongest_ap's. */
	rule_try try;

	/* Elements that must be filled when try returns 0 */
	struct prefix prefix; //The prefix to be used
	uint8_t priority;     //The priority value
	bool authoritative;    //The authoritative bit

/* private to pa_core */
	struct list_head le;
	struct btrie cpls;

#define PA_RULE_L  "pa_rule [%s](prio %u)"
#define PA_RULE_LA(rule) (rule)->name?(rule)->name:"no-name", (rule)->rule_priority
};

/* A static prefix rule is a configuration entry
 * that will ask pa_core to use a particular prefix under
 * some circumstances.
 * A static prefix will only be used if an associated
 * delegated prefix is available.*/
struct pa_static_prefix_rule {
	struct pa_rule rule;
	struct prefix prefix;  //The prefix value
	char ifname[IFNAMSIZ]; //The interface the prefix is associated to
	bool hard;             // Whether that rule may remove a previously made assignment (of lower priority)
	char rule_name[40 + INET6_ADDRSTRLEN + IFNAMSIZ];

	struct list_head user; // private to user
};

/* A link id rule is a configuration entry that will
 * ask pa_core to use a deterministic prefix for every
 * delegated prefix.
 * By default, its algorithmic priority is lower than
 * a static prefix. */
struct pa_link_id_rule {
	struct pa_rule rule;
	char ifname[IFNAMSIZ]; // The interface the ID is associated to
	uint32_t link_id;      // The link ID
	uint8_t link_id_len;   // Minimal required length difference between dp length and ap length
	bool hard;             // Whether that rule may remove a previously made assignment (of lower priority)
	char rule_name[40 + IFNAMSIZ];
};


/* An iface id uses the same principle as a link id.
 * This is a way to *make a wish*, but the address won't be used if it is already used
 * by someone else. */
struct pa_iface_addr {
	struct list_head le;
	char ifname[IFNAMSIZ];     // The interface the address is associated to
	struct in6_addr address;   // The address itself. Only the later bits are used
	uint8_t mask;              // Maximal link prefix plen so that the addr entry may apply
	struct prefix filter;      // The address is only used if the link prefix is included in the mask

	/* For instance, if the address ::a:b:c:0:1 is provided with the mask 80,
	 * and the filter 2001::/16 is given.
	 * The address for the different prefixes will be:
	 *
	 * 2001:f00:ba:0::/64 -> 2001:f00:ba:0:b:c:0:1
	 * 2001:f00:ba:0::/80 -> 2001:f00:ba:0:0:c:0:1
	 * 2001:f00:ba:0::/96 -> Prefix is too small for the mask
	 * 2002:f00:ba:0::/64 -> Doesn't match the filter
	 *
	 * If the filter prefix length and the mask are the same, only one particular address
	 * may be used for one particular link prefix.
	 */
};

struct pa_core {
	bool started;
	struct pa_timer paa_to;
	struct pa_timer aaa_to;
	struct pa_data_user data_user;
	struct list_head rules;     /* Contains configured prefixes. */
	struct pa_rule keep_rule;
	struct pa_rule accept_rule;
	struct pa_rule random_rule;
	struct pa_rule random_scarcity_rule;
	struct list_head iface_addrs;
};

void pa_core_init(struct pa_core *);
void pa_core_start(struct pa_core *);
void pa_core_stop(struct pa_core *);
void pa_core_term(struct pa_core *);

void pa_core_rule_init(struct pa_rule *rule, const char *name, uint32_t rule_priority, rule_try try);
void pa_core_rule_add(struct pa_core *core, struct pa_rule *rule);
void pa_core_rule_del(struct pa_core *core, struct pa_rule *rule);

void pa_core_static_prefix_init(struct pa_static_prefix_rule *rule,
		const char *ifname, const struct prefix* p, bool hard);

void pa_core_link_id_init(struct pa_link_id_rule *lrule, const char *ifname,
		uint32_t link_id, uint8_t link_id_len, bool hard);

void pa_core_iface_addr_init(struct pa_iface_addr *addr,
		const char *ifname, 		//The ifname or NULL (or 0 len str) if may be applied to any iface
		struct in6_addr *address,	//The address (must not be NULL)
		uint8_t mask,               //The mask len
		struct prefix *filter);     //The prefix filter (or NULL if filter is ::/0)
void pa_core_iface_addr_add(struct pa_core *core, struct pa_iface_addr *addr);
void pa_core_iface_addr_del(struct pa_core *core, struct pa_iface_addr *addr);


#endif /* PA_CORE_H_ */
