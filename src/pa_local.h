/*
 * pa_data.h
 *
 * Author: Pierre Pfister
 *
 * ULA and IPv4 prefix generation for
 * prefix algorithm.
 *
 */

#ifndef PA_LOCAL_H_
#define PA_LOCAL_H_

#include <stdbool.h>
#include <libubox/uloop.h>

#include "prefix_utils.h"
#include "hnetd.h"
#include "pa_data.h"

struct pa_local;

struct pa_local_elem {
	hnetd_time_t create_start;
	hnetd_time_t timeout;
	struct pa_ldp *ldp;

	uint8_t (*get_status)(struct pa_local *, struct pa_local_elem *);
	void (*create)(struct pa_local *, struct pa_local_elem *);
	hnetd_time_t (*update)(struct pa_local *, struct pa_local_elem *elem, hnetd_time_t now);
};

struct pa_local {
	struct pa_local_elem ula;
	struct pa_local_elem ipv4;

	hnetd_time_t start_time;
	hnetd_time_t current_timeout;
	struct uloop_timeout timeout;

	struct pa_data_user data_user;
};

void pa_local_init(struct pa_local *);
void pa_local_start(struct pa_local *);
void pa_local_stop(struct pa_local *);
void pa_local_term(struct pa_local *);

#endif /* PA_LOCAL_H_ */
