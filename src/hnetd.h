#ifndef HNETD_H
#define HNETD_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
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
