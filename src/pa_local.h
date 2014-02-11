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

#include "hnetd.h"

struct pa_local {
	struct {
		bool available;
		void *dhcp_data;
		size_t dhcp_len;
	} ipv4;

	bool started;
	hnetd_time_t when;
	struct uloop_timeout timeout;
};

#include "pa.h"

void pa_local_init(struct pa_local *);
void pa_local_start(struct pa_local *);
void pa_local_stop(struct pa_local *);
void pa_local_term(struct pa_local *);

void pa_local_update_ipv4(struct pa_local *, bool available, const void *dhcp_data, size_t dhcp_len);

/* Scheduled whenever
 * - A dp is modified
 * - The rid is modified
 */
void pa_local_schedule(struct pa_local *);

#endif /* PA_LOCAL_H_ */
