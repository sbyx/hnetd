/*
 * $Id: dtls.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:50:18 2014 mstenber
 * Last modified: Thu Oct 23 09:03:29 2014 mstenber
 * Edit time:     9 min
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
void dtls_start();
void dtls_destroy(dtls d);

/* Set local authentication information */
bool dtls_set_local_cert(dtls d, const char *certfile, const char *pkfile);

bool dtls_set_psk(dtls d, const char *psk, size_t psk_len);

/* Send/receive data. */
ssize_t dtls_recvfrom(dtls d, void *buf, size_t len,
                      struct sockaddr_in6 *src);
ssize_t dtls_sendto(dtls o, void *buf, size_t len,
                    const struct sockaddr_in6 *dst);

#endif /* DTLS_H */
