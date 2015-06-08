/*
 * $Id: udp46_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Tue May 26 08:28:45 2015 mstenber
 * Last modified: Mon Jun  8 12:19:59 2015 mstenber
 * Edit time:     8 min
 *
 */

#pragma once

#include "hnetd.h"
#include "dncp_util.h"
#include "udp46.h"

#undef __unused
/* In linux some system includes have fields with __unused. Argh. */
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <fcntl.h>
#define __unused __attribute__((unused))

/* This is just cut-n-paste from minimalist-pcproxy shared.h ; most
 * likely won't compile on it's own, so just use it in udp46.c :p*/

#define IN_ADDR_TO_MAPPED_IN6_ADDR(a, a6)       \
do {                                            \
  memset(a6, 0, sizeof(*(a6)));                 \
  (a6)->s6_addr[10] = 0xff;                     \
  (a6)->s6_addr[11] = 0xff;                     \
  ((uint32_t *)a6)[3] = *((uint32_t *)a);       \
 } while (0)

#define MAPPED_IN6_ADDR_TO_IN_ADDR(a6, a)       \
do {                                            \
  *((uint32_t *)a) = ((uint32_t *)a6)[3];       \
 } while (0)

#define SOCKADDR_IN6_REPR(sa) SA6_D(sa)
