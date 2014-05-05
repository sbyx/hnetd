/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 * Author: Pierre Pfister
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#ifndef HNETD_H
#define HNETD_H

/* Anything up to INFO is compiled in by default; syslog can be used
 * to filter them out. DEBUG can be quite spammy and isn't enabled by
 * default. */
#define HNETD_DEFAULT_L_LEVEL 6

#ifndef L_LEVEL
#define L_LEVEL HNETD_DEFAULT_L_LEVEL
#endif /* !L_LEVEL */

#ifndef L_PREFIX
#define L_PREFIX ""
#endif /* !L_PREFIX */

#ifdef __APPLE__

/* Haha. Got to love advanced IPv6 socket API being disabled by
 * default. */
#define __APPLE_USE_RFC_3542

#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP

/* LIST_HEAD macro in sys/queue.h, argh.. */

#include <sys/queue.h>
#ifdef LIST_HEAD
#undef LIST_HEAD
#endif /* LIST_HEAD */

#endif /* __APPLE__ */

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <libubox/utils.h>

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)

typedef int64_t hnetd_time_t;
#define HNETD_TIME_MAX INT64_MAX
#define HNETD_TIME_PER_SECOND INT64_C(1000)

// Get current monotonic clock with millisecond granularity
static inline hnetd_time_t hnetd_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((hnetd_time_t)ts.tv_sec * HNETD_TIME_PER_SECOND) +
			((hnetd_time_t)ts.tv_nsec / (1000000000 / HNETD_TIME_PER_SECOND));
}


// Logging macros
#if L_LEVEL >= LOG_ERR
#define L_ERR(...)	syslog(LOG_ERR, L_PREFIX __VA_ARGS__)
#else
#define L_ERR(...) do {} while(0)
#endif

#if L_LEVEL >= LOG_WARNING
#define L_WARN(...)	syslog(LOG_WARNING, L_PREFIX __VA_ARGS__)
#else
#define L_WARN(...) do {} while(0)
#endif

#if L_LEVEL >= LOG_NOTICE
#define L_NOTICE(...)	syslog(LOG_NOTICE, L_PREFIX __VA_ARGS__)
#else
#define L_NOTICE(...) do {} while(0)
#endif

#if L_LEVEL >= LOG_INFO
#define L_INFO(...)	syslog(LOG_INFO, L_PREFIX __VA_ARGS__)
#else
#define L_INFO(...) do {} while(0)
#endif

#if L_LEVEL >= LOG_DEBUG
#define L_DEBUG(...)	syslog(LOG_DEBUG, L_PREFIX __VA_ARGS__)
#else
#define L_DEBUG(...) do {} while(0)
#endif


// Some C99 compatibility
#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#endif /* !HNETD_H */
