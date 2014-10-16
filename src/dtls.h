/*
 * $Id: dtls.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:50:18 2014 mstenber
 * Last modified: Thu Oct 16 10:59:29 2014 mstenber
 * Edit time:     6 min
 *
 */

#ifndef DTLS_H
#define DTLS_H

#include "hnetd.h"

#include <netinet/in.h>

/*
 * This is 'dtls' module, which hides most of the ugliness of OpenSSL
 * (DTLS) API with simple, socket-like API.
 *
 * It assumes uloop is available to juggle the various file
 * descriptors.
 *
 * The API is more or less same as what hncp_io provides; however,
 * underneath, a number of sockets are juggled.
 */

typedef struct dtls_struct *dtls;
typedef void (*dtls_readable_callback)(dtls d, void *context);

/* Create/destroy instance. */
dtls dtls_create(uint16_t port, dtls_readable_callback cb, void *cb_context);
void dtls_destroy(dtls d);

/* Send/receive data. */
ssize_t dtls_recvfrom(dtls d, void *buf, size_t len,
                      char *ifname,
                      struct in6_addr *src,
                      uint16_t *src_port,
                      struct in6_addr *dst);
ssize_t dtls_sendto(dtls o, void *buf, size_t len,
                    const char *ifname,
                    const struct in6_addr *to,
                    uint16_t to_port);

#endif /* DTLS_H */
