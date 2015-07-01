/*
 * $Id: fake_log.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Jun  8 09:54:52 2015 mstenber
 * Last modified: Wed Jul  1 11:18:05 2015 mstenber
 * Edit time:     18 min
 *
 */

#pragma once

#include "hnetd.h"

#include "sput.h"

#include <stdio.h>
#include <stdarg.h>

static void fake_log(int priority, const char *format, ...)
{
  va_list a;

  printf("[%d]", priority);
  va_start(a, format);
  vprintf(format, a);
  va_end(a);
  printf("\n");
}

void fake_log_check(int priority __unused,
                    const char *format, ...)
{
  va_list a;
  char buf[1024];

  va_start(a, format);
  vsnprintf(buf, sizeof(buf), format, a);
  va_end(a);
}

void fake_log_disable(int priority __unused,
                    const char *format __unused, ...)
{
}


int log_level = 7;
void (*hnetd_log)(int priority, const char *format, ...) = fake_log;

#define fake_log_init()                         \
do {                                            \
  bool quiet = true;                            \
  if (getenv("FAKE_LOG_CHECK"))                 \
    hnetd_log = fake_log_check;                 \
  else if (getenv("FAKE_LOG_DISABLE"))          \
    hnetd_log = fake_log_disable;               \
  else                                          \
    quiet = false;                              \
  if (quiet)                                    \
    {                                           \
      FILE *f = fopen("/dev/null", "w");        \
      sput_set_output_stream(f);                \
    }                                           \
} while(0)
