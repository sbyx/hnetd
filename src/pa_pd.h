/*
 * pa_pd.h
 *
 * Author: Pierre Pfister
 *
 * Prefix delegation support in prefix assignment.
 *
 * This file provides an API for reserving delegated prefixes.
 *
 */


#ifndef PA_PD_H_
#define PA_PD_H_

#include "pa_data.h"

struct pa_pd_conf {
	uint8_t pd_min_len;       /* pd will not provide bigger prefixes : default = 62 */
	uint8_t pd_min_ratio_exp; /* pd will not provide more than 1/(2^x) of the dp size : default 3 (1/8) */
};

/* General structure for pa_pd management.
 * Put in pa structure. */
struct pa_pd {
	struct list_head leases;       /* List of known leases */
	struct pa_data_user data_user; /* Used to receive data updates */
	bool started;
	struct pa_pd_conf conf;
};

/* This structure keeps track of a given delegation lease. */
struct pa_pd_lease {
	/* Called whenever some modification is made, after a short delay elapsed (about half a second)
	 * so that if multiple modifications are made in a row, it is only called once. */
	void (*update_cb)(struct pa_pd_lease *lease);

	/* Contains a list of pa_cpds (see pa_data.h).
	 * A cpd may be delegated only if (cpd->cp.valid == true && cpd->cp.dp != NULL).
	 * It is false initially and becomes true after some time (depending on hncp speed).
	 * cpd->cp.dp is the associated delegated prefix. If null, it means the element is not valid
	 * and will be removed.
	 * Lifetimes may be found there: cpd->cp.dp->valid_lifetime (or preferred).
	 * Dhcp data may be found here: cpd->cp.dp->dhcp_data/len. */
	struct list_head cpds;

	/****** Private *****/
	struct list_head le;        /* Linked in pa_pd structure */
	struct uloop_timeout cb_to;
	struct pa_pd *pd;
	uint8_t preferred_len;
	uint8_t max_len;
};

#define pa_pd_for_each_lease(lease, pa_pd) list_for_each_entry(lease, &(pa_pd)->leases, le)
#define pa_pd_for_each_cpd(pa_cpd, lease) list_for_each_entry(pa_cpd, &(lease)->cpds, lease_le)
#define pa_pd_for_each_cpd_safe(pa_cpd, cpd2, lease) list_for_each_entry_safe(pa_cpd, cpd2, &(lease)->cpds, lease_le)

/* Adds a new lease request.
 * When the function returns, the prefix list is empty. It is updated later and the  */
void pa_pd_lease_init(struct pa_pd *, struct pa_pd_lease *, uint8_t preferred_len, uint8_t max_len);

/* Terminates an existing lease. */
void pa_pd_lease_term(struct pa_pd *, struct pa_pd_lease *);

void pa_pd_conf_defaults(struct pa_pd_conf *);

void pa_pd_init(struct pa_pd *, const struct pa_pd_conf *);
void pa_pd_start(struct pa_pd *);
void pa_pd_stop(struct pa_pd *);
void pa_pd_term(struct pa_pd *);

#endif /* PA_PD_H_ */
