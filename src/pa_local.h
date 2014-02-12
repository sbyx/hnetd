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

struct pa_local_elem {
	hnetd_time_t create_start;
	hnetd_time_t timeout;
	bool enabled;
	struct prefix prefix;

#define PA_LOCAL_CAN_CREATE 0x01
#define PA_LOCAL_CAN_KEEP	0x02
	uint8_t (*get_status)(struct pa_local_elem *);
	void (*create)(struct pa_local_elem *);
	hnetd_time_t (*update)(struct pa_local_elem *elem, hnetd_time_t now);
};

struct pa_local {

	struct pa_local_elem ula;
	struct pa_local_elem ipv4;

	struct {
		bool available;
		void *dhcp_data;
		size_t dhcp_len;
	} ipv4_access;

	hnetd_time_t start_time;
	hnetd_time_t current_timeout;
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
