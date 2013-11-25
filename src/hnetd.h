#ifndef HNETD_H
#define HNETD_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <libubox/utils.h>

// Get current monotonic clock with millisecond granularity
typedef int64_t hnetd_time_t;
static inline hnetd_time_t hnetd_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((hnetd_time_t)ts.tv_sec * 1000) +
			((hnetd_time_t)ts.tv_nsec / 1000000);
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
