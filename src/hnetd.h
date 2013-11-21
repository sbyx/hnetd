#pragma once
#include <stddef.h>

// Get current monotonic clock with second granularity
time_t hnetd_time(void);

// Get a number of random bytes from /dev/urandom
ssize_t hnetd_random(void *buf, size_t len);



// Some C99 compatibility

#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifndef _unused
#define __unused __attribute__((unused))
#endif
