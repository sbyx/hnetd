/*
 * $Id: dtls.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:50:18 2014 mstenber
 * Last modified: Wed Dec 30 14:17:42 2015 mstenber
 * Edit time:     42 min
 *
 */

#pragma once

#include "hnetd.h"

#include <netinet/in.h>

/*
 * This is 'dtls' module, which hides most of the ugliness of OpenSSL
 * (DTLS) API with simple, socket-like API.
 *
 * It assumes uloop is available to juggle the various file
 * descriptors.
 *
 * The API is more or less same as what dncp_io provides; however,
 * underneath, a number of sockets are juggled.
 *
 * Basic usage:
 * 1. create
 * 2. .. configure things (psk/cert, callbacks, ..)
 * 3. start
 * 4. .. do things .. (send, or recvfrom as needed, possibly triggered by cb)
 * 5. destroy
 */

#if defined(DTLS_OPENSSL)
typedef struct x509_st *dtls_cert;
#elif defined(DTLS_MBEDTLS)
typedef struct mbedtls_x509_crt *dtls_cert;
#else
#error "Unknown DTLS variant - add support please, patches welcome! :->"
#endif

typedef struct dtls_struct *dtls;
typedef void (*dtls_readable_cb)(dtls d, void *context);
typedef bool (*dtls_unknown_cb)(dtls d, dtls_cert cert, void *context);

/* Create/destroy instance. */
dtls dtls_create(uint16_t port);
void dtls_start();
void dtls_destroy(dtls d);

typedef struct {
  /*
   * All limits specified here are 'non-zero => enforce, zero => use default'.
   */

  /*
   * Per-packet processing limits (which is easy attack vector, given we do
   * relatively expensive operations even on first packet due to
   * braindeath that is the DTLS API).
   */

  /*
   * Set the acceptable packets per second to process. Anything more
   * than this will be silently dropped.
   */
  int input_pps;

  /*
   * How many seconds a connection can be idle before it is eliminated.
   */
  int connection_idle_limit_seconds;

  /*
   * Maximum number of connections in non-DATA state
   */
  int num_non_data_connections;

  /*
   * Maximum number of connections in DATA state
   */
  int num_data_connections;

} dtls_limits_s, *dtls_limits;

void dtls_set_limits(dtls d, dtls_limits limits);


/* Callback to call when dtls has new data. */
void dtls_set_readable_cb(dtls d, dtls_readable_cb cb, void *cb_context);

/* Authentication scheme 1 - PSK */

/* Set 'global' pre-shared key to use / expect other side to use. */
bool dtls_set_psk(dtls d, const char *psk, size_t psk_len);

/* Authentication scheme 2/3 shared requirement - local side setup */

/* Set local authentication information */
bool dtls_set_local_cert(dtls d, const char *certfile, const char *pkfile);

/* Authentication scheme 2 - PKI approach - provide either single file
 * with trusted cert(s), or directory with trusted certs. */
bool dtls_set_verify_locations(dtls d, const char *path, const char *dir);

/* Authentication scheme 3 - instead of using PKI, declare verdicts on
 * certificates on our own. The return value of 'true' from the
 * callback indicates we trust a certificate. */
void dtls_set_unknown_cert_cb(dtls d, dtls_unknown_cb cb, void *cb_context);



/* Send/receive data. */
ssize_t dtls_recv(dtls d,
                  struct sockaddr_in6 **src,
                  struct sockaddr_in6 **dst,
                  void *buf, size_t len);

ssize_t dtls_send(dtls o,
                  const struct sockaddr_in6 *src,
                  const struct sockaddr_in6 *dst,
                  void *buf, size_t len);

/* Certificate handling utilities */
bool dtls_cert_to_pem_buf(dtls_cert cert, char *buf, int buf_len);
int dtls_cert_to_der_buf(dtls_cert cert, unsigned char *buf, int buf_len);
void dtls_cert_hash_sha256(dtls_cert cert, unsigned char *buf);
