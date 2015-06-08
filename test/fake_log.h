/*
 * $Id: fake_log.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Jun  8 09:54:52 2015 mstenber
 * Last modified: Mon Jun  8 10:00:19 2015 mstenber
 * Edit time:     6 min
 *
 */

#pragma once

#include "hnetd.h"

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

int log_level = 9;
void (*hnetd_log)(int priority, const char *format, ...) = fake_log;
