/*
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 */


#define NO_REDEFINE_ULOOP_TIMEOUT

/* Wrapper functions for time and timeouts. */
#include "hnetd_time.h"
#include "hnetd.h"

hnetd_time_t hnetd_time(void)
{
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ((hnetd_time_t)ts.tv_sec * HNETD_TIME_PER_SECOND) +
    ((hnetd_time_t)ts.tv_nsec / (1000000000 / HNETD_TIME_PER_SECOND));
}

int hnetd_time_timeout_add(struct uloop_timeout *timeout)
{
  return uloop_timeout_add(timeout);
}

int hnetd_time_timeout_set(struct uloop_timeout *timeout, int msecs)
{
  return uloop_timeout_set(timeout, msecs);
}

int hnetd_time_timeout_cancel(struct uloop_timeout *timeout)
{
  return uloop_timeout_cancel(timeout);
}

int hnetd_time_timeout_remaining(struct uloop_timeout *timeout)
{
  return uloop_timeout_remaining(timeout);
}
