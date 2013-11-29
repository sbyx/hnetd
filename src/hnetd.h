#ifndef HNETD_H
#define HNETD_H

#ifdef __APPLE__

/* Haha. Got to love advanced IPv6 socket API being disabled by
 * default. */
#define _DARWIN_C_SOURCE
#define __APPLE_USE_RFC_3542

#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP

#endif /* __APPLE__ */

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <libubox/utils.h>


typedef int64_t hnetd_time_t;
#define HNETD_TIME_MAX INT64_MAX
#define HNETD_TIME_PER_SECOND 1000

// Get current monotonic clock with millisecond granularity
static inline hnetd_time_t hnetd_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((hnetd_time_t)ts.tv_sec * HNETD_TIME_PER_SECOND) +
			((hnetd_time_t)ts.tv_nsec / (1000000000 / HNETD_TIME_PER_SECOND));
}


// Logging macros
#if L_LEVEL >= 3
	#define L_ERR(format, ...)	syslog(LOG_ERR, format, __VA_ARGS__)
#else
	#define L_ERR
#endif

#if L_LEVEL >= 4
	#define L_WARN(format, ...)	syslog(LOG_WARNING, format, __VA_ARGS__)
#else
	#define L_WARN
#endif

#if L_LEVEL >= 5
	#define L_NOTICE(format, ...)	syslog(LOG_NOTICE, format, __VA_ARGS__)
#else
	#define L_NOTICE
#endif

#if L_LEVEL >= 6
	#define L_INFO(format, ...)	syslog(LOG_INFO, format, __VA_ARGS__)
#else
	#define L_INFO
#endif

#if L_LEVEL >= 7
	#define L_DEBUG(format, ...)	syslog(LOG_DEBUG, format, __VA_ARGS__)
#else
	#define L_DEBUG
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
