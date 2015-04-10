/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 */

/*
 * This module provides the hnetd time/timeout abstractions.
 *
 * We use this (as opposed to inlined functions) so they can be
 * overridden by net_sim in a cleaner way than what the old fake_uloop
 * approach did (re-#define, #include foo.c). #include foo.c is still
 * valid idea, but if and only if needed (for example) to mock
 * something else than time. This way we can use 'production' code, if
 * it's only external dependency is {dncp,hncp}_io* and this.
 */

#pragma once

#include <libubox/uloop.h>

typedef int64_t hnetd_time_t;
#define HNETD_TIME_MAX INT64_MAX
#define HNETD_TIME_PER_SECOND INT64_C(1000)

/* Get current monotonic clock with millisecond granularity */
hnetd_time_t hnetd_time(void);

int hnetd_time_timeout_add(struct uloop_timeout *timeout);
int hnetd_time_timeout_set(struct uloop_timeout *timeout, int msecs);
int hnetd_time_timeout_cancel(struct uloop_timeout *timeout);
int hnetd_time_timeout_remaining(struct uloop_timeout *timeout);

#ifndef NO_REDEFINE_ULOOP_TIMEOUT
#define uloop_timeout_add(x) hnetd_time_timeout_add(x)
#define uloop_timeout_set(x,y) hnetd_time_timeout_set(x,y)
#define uloop_timeout_cancel(x) hnetd_time_timeout_cancel(x)
#define uloop_timeout_remaining(x) hnetd_time_timeout_remaining(x)
#endif /* !NO_REDEFINE_ULOOP_TIMEOUT */
