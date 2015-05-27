/*
 * $Id: udp46_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Tue May 26 08:28:45 2015 mstenber
 * Last modified: Wed May 27 16:38:25 2015 mstenber
 * Edit time:     1 min
 *
 */

#pragma once

#include "hnetd.h"

#include "udp46.h"

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>

/* This is just cut-n-paste from minimalist-pcproxy shared.h ; most
 * likely won't compile on it's own, so just use it in udp46.c :p*/

static inline void sockaddr_in6_set(struct sockaddr_in6 *sin6,
                                    struct in6_addr *a6,
                                    uint16_t port)
{
  memset(sin6, 0, sizeof(*sin6));
#ifdef SIN6_LEN
  sin6->sin6_len = sizeof(*sin6);
#endif /* SIN6_LEN */
  sin6->sin6_family = AF_INET6;
  if (a6)
    sin6->sin6_addr = *a6;
  sin6->sin6_port = htons(port);
}

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

#define IN6_ADDR_REPR(a6) \
  inet_ntop(AF_INET6, a6, alloca(INET6_ADDRSTRLEN), INET6_ADDRSTRLEN)

static inline const char *_sockaddr_in6_repr(const struct sockaddr_in6 *sa,
                                             char *buf, size_t buf_len)
{
  char host[123];
  char serv[123];

  if (!buf)
    return NULL;
  if (getnameinfo((const struct sockaddr *)sa, sizeof(*sa),
                  host, sizeof(host), serv, sizeof(serv),
                  NI_NUMERICHOST|NI_NUMERICSERV))
    {
      perror("getnameinfo");
      return NULL;
    }
  snprintf(buf, buf_len, "%s:%s", host, serv);
  return buf;
}

#define SOCKADDR_IN6_REPR(sin6) _sockaddr_in6_repr(sin6, alloca(123), 123)

