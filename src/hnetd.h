#ifndef HNETD_H
#define HNETD_H

#include <stddef.h>
#include <time.h>
#include <sys/types.h>
#include <libubox/utils.h>

// Get current monotonic clock with second granularity
static inline time_t hnetd_time(void) {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
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
