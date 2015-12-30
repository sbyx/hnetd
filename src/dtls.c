/*
 * $Id: dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:42 2014 mstenber
 * Last modified: Wed Dec 30 18:55:21 2015 mstenber
 * Edit time:     519 min
 *
 */

/*
 * Ongoing effort to get DTLS wrapped in some sane way.
 *
 * Current version is inspired by
 * http://www.net-snmp.org/wiki/index.php/DTLS_Implementation_Notes
 *
 * Notable points:
 *
 * - In OpenSSL case, wrap OpenSSL's DTLS instances with their own
 * memory-BIOs, and do NOT let them deal with actual sockets at all.
 *
 * The I/O code should be adoptable easily enough to DTLS
 * implementations that provide some way of dealing with not-quite-raw
 * sockets (and with some effort, again on raw sockets). For example,
 * MatrixSSL should probably work fairly straightforwardly. The
 * certificate code, on the other hand, may be painful to adapt to
 * non-OpenSSL.
 *
 */


#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <libubox/list.h>
#include <libubox/md5.h>
#include <errno.h>
#include <net/if.h>
/* In linux, fcntl.h includes something with __unused. Argh. So
 * include this before anything hnetd-specific.*/
#include <fcntl.h>

#include "dtls.h"
#if L_LEVEL >= LOG_DEBUG
/* HEX_REPR */
#include "tlv.h"
#endif /* L_LEVEL >= LOG_DEBUG */
#include "udp46.h"

/* Do we want to use arbitrary client ports? */
/* In practise, this is actually mandatory:
 * Otherwise there is a race condition between client- and server
 * connection with a remote IP, and in worst case, the socket bind order
 * for the (localip, localport, remoteip, remoteport) is 'wrong way around'
 * so the client socket will get remote party's client traffic, and
 * server socket gets nothing (for example).
 */
#define USE_FLOATING_CLIENT_PORT

/* Try to use one context for both client and server connections
 * ( does it matter? it seems one context is enough. ) */
#define USE_ONE_CONTEXT

/* Maximum raw packet size. DTLS does not define it's own
 * fragmentation; MUST fit within single datagram, SHOULD match
 * PMTU. For now, we assume nobody does jumbograms and assume 1500
 * bytes is it. We keep one extra byte around to catch 'too large'
 * packets going in or out. */
#define DTLS_MAXIMUM_PAYLOAD_SIZE_PLUS_1 1501

/* How large random string key we use as base for cookies */
#define COOKIE_SECRET_LENGTH 10

/* 16 = size of md5 hash */
#define COOKIE_LENGTH (sizeof(time_t) + 16)

/* How long cookies are valid (in seconds) */
#define COOKIE_VALIDITY_PERIOD 10

#ifdef DTLS_OPENSSL

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/debug.h>

#define SSL_read(ctx, buf, len) mbedtls_ssl_read(&ctx, buf, len)
#define SSL_write(ctx, buf, len) mbedtls_ssl_write(&ctx, buf, len)
#endif /* DTLS_MBEDTLS */

/* These lurk in queue, waiting for connection to finish (outbound). */
typedef struct {
  struct list_head in_queued_buffers;
  int len;
  int ofs;
  unsigned char buf[0];
} *dtls_queued_buffer;

typedef struct {
  struct list_head in_connections;

  struct list_head send_queued_buffers;

  dtls d;

  struct sockaddr_in6 remote_addr;

  bool has_local_addr;
  struct sockaddr_in6 local_addr;

  enum {
    STATE_ACCEPT,
    STATE_CONNECT,
    STATE_DATA,
    STATE_SHUTDOWN
  } state;

  struct uloop_timeout uto;

  bool is_client;

  time_t last_use;

#ifdef DTLS_OPENSSL
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;
#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS
  /* mbedtls I/O 'BIO' abstraction is just 3 callbacks; therefore we
   * have to keep track of the data read from network so that it is
   * available when we play with SSL_read.
   *
   * TBD: should there be some size limit for this list? In practise,
   * the library _should_ drain it rapidly, but who knows..?
   */
  struct list_head recv_queued_buffers;

  mbedtls_ssl_context ssl;

  /* Intermediate timer */
  struct uloop_timeout uto_int;

  /* Is the timer set by us? */
  bool uto_valid;
#endif /* DTLS_MBEDTLS */

} dtls_connection_s, *dtls_connection;

typedef struct dtls_struct {
  /* Client provided - (optional) callback to call when something
   * readable available. */
  dtls_readable_cb readable_cb;
  void *readable_cb_context;

  dtls_unknown_cb unknown_cb;
  void *unknown_cb_context;

  udp46 u46_server;

  udp46 u46_client;

  struct list_head connections;

  bool readable;
  bool started;

  char *psk;
  unsigned int psk_len;

  dtls_limits_s limits;

  int num_non_data_connections;
  int num_data_connections;

  time_t t;
  int pps;

  unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

#ifdef DTLS_OPENSSL
  /* We keep this around, just for re-binding of new received connections. */
  SSL_CTX *ssl_client_ctx;

  SSL_CTX *ssl_server_ctx;

#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS
  mbedtls_ssl_config ssl_server_config;
  mbedtls_ssl_config ssl_client_config;
#endif /* DTLS_MBEDTLS */

} dtls_s;

static dtls_limits_s _default_limits = {
  .input_pps = 100,
  .connection_idle_limit_seconds = 1800,
  .num_non_data_connections = 10,
  .num_data_connections = 100,
};

#define DTLS_LIMIT(x) (d->limits.x ? d->limits.x : _default_limits.x)

static bool _ssl_initialized = false;

static void _cookie_gen_fixed_time(dtls d,
                                   const unsigned char *info,
                                   unsigned int ilen,
                                   unsigned char *cookie,
                                   unsigned int *cookie_len,
                                   time_t t)
{
  md5_ctx_t ctx;
  unsigned char result[COOKIE_LENGTH];

  /* Store timestamp in the beginning */
  *((time_t *)result) = t;
  md5_begin(&ctx);
  md5_hash(d->cookie_secret, COOKIE_SECRET_LENGTH, &ctx);
  md5_hash(info, ilen, &ctx);
  md5_hash(result, sizeof(time_t), &ctx);
  md5_end(&result[sizeof(time_t)], &ctx);

  memcpy(cookie, result, sizeof(result));
  *cookie_len = sizeof(result);
}

static bool _cookie_valid(dtls d, const unsigned char *info, size_t ilen,
                          const unsigned char *cookie)
{
  unsigned char tbuf[COOKIE_LENGTH];
  unsigned int tbuf_len = sizeof(tbuf);
  time_t nt, ct;

  nt = time(NULL);
  ct = *((time_t *)cookie);

  /* If our clock is really moving backwards, we might as well pretend
   * it is fake, for now. (Little loss, UDP _is_ lossy after all.)*/
  if (ct > nt)
    {
      L_ERR("_cookie_verify_cb: received time > current time");
      return 0;
    }

  if ((nt - ct) > COOKIE_VALIDITY_PERIOD)
    {
      L_ERR("_cookie_verify_cb: received time too old");
      return 0;
    }
  _cookie_gen_fixed_time(d, info, ilen, tbuf, &tbuf_len, ct);
  if (memcmp(tbuf, cookie, tbuf_len) != 0)
    {
      L_ERR("_cookie_verify_cb: data mismatch");
      return 0;
    }
  L_DEBUG("_cookie_verify_cb succeeded");
  return 1;

}


#ifdef DTLS_OPENSSL

static bool _drain_errors()
{
  if (!ERR_peek_error())
    return false;

  BIO *bio_stderr = BIO_new(BIO_s_file());
  BIO_set_fp(bio_stderr, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
  ERR_print_errors(bio_stderr);
  BIO_free(bio_stderr);

  /* Clear stack */
  while (ERR_peek_error())
    ERR_get_error();

  return true;
}

static int _cookie_gen_cb(SSL *ssl,
                          unsigned char *cookie, unsigned int *cookie_len)
{
  dtls_connection dc = SSL_get_ex_data(ssl, 0);
  struct sockaddr_in6 *sin6 = &dc->remote_addr;
  _cookie_gen_fixed_time(dc, (void*)sin6, sizeof(*sin6),
                         cookie, cookie_len, time(NULL));
  return 1;
}

static int _cookie_verify_cb(SSL *ssl,
                             unsigned char *cookie, unsigned int cookie_len)
{
  /* If it is of different size than what we produce, clearly not ours. */
  if (cookie_len != COOKIE_LENGTH)
    {
      L_ERR("_cookie_verify_cb: invalid cookie length: %d", (int) cookie_len);
      return 0;
    }
  dtls_connection dc = SSL_get_ex_data(ssl, 0);
  struct sockaddr_in6 *sin6 = &dc->remote_addr;
  return _cookie_valid(dc, (void*)sin6, sizeof(*sin6), cookie) ? 1 : 0;
}

#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS

static void _mbedtls_debug(void *o __unused, int level,
                           const char *filename, int line,
                           const char *message)
{
  /* Remove absolute path from filename */
  const char *d = strrchr(filename, '/');
  if (d)
    filename = d;

  /* Remove trailing newline from message */
  int len = strlen(message);
  char *buf = alloca(len);
  memcpy(buf, message, len);
  buf[len-1]=0;
  message = buf;

  L_DEBUG("[mbed:%d@%s:%d]%s",
          level, filename, line, message);
}

static int _mbedtls_random(void *o __unused, unsigned char *buf, size_t len)
{
  size_t i;

  for (i = 0 ; i < len ;i++)
    buf[i] = random();
  return 0;
}

static int _mbedtls_cookie_write(void *o, unsigned char **p,
                                 unsigned char *end,
                                 const unsigned char *info,
                                 size_t ilen)
{
  dtls d = o;
  unsigned int cookie_len;
  size_t available = end - *p;

  if (available < COOKIE_LENGTH)
    {
      L_ERR("not enough space for cookie");
      return -1;
    }
  _cookie_gen_fixed_time(d, info, ilen, *p, &cookie_len, time(NULL));
  *p += cookie_len;
  return 0;
}

static int _mbedtls_cookie_check(void *o,
                                 const unsigned char *cookie, size_t clen,
                                 const unsigned char *info, size_t ilen)
{
  dtls d = o;

  if (clen != COOKIE_LENGTH)
    {
      L_DEBUG("_mbedtls_cookie_check: invalid cookie length: %d", (int) clen);
      return -1;
    }
  return _cookie_valid(d, info, ilen, cookie) ? 0 : -1;
}

#endif /* DTLS_MBEDTLS */

static void _qb_free(dtls_queued_buffer qb)
{
  list_del(&qb->in_queued_buffers);
  free(qb);
}

static void _qb_list_free(struct list_head *lh)
{
  dtls_queued_buffer qb, qb2;

  list_for_each_entry_safe(qb, qb2, lh, in_queued_buffers)
    _qb_free(qb);
}

static void _connection_free(dtls_connection dc)
{
  L_DEBUG("_connection_free %p", dc);
  if (dc->state != STATE_SHUTDOWN)
    {
      if (dc->state == STATE_DATA)
        dc->d->num_data_connections--;
      else
        dc->d->num_non_data_connections--;
    }
  _qb_list_free(&dc->send_queued_buffers);
  list_del(&dc->in_connections);

#ifdef DTLS_OPENSSL
  SSL_free(dc->ssl);
#endif /* DTLS_OPENSSL */
#ifdef DTLS_MBEDTLS
  _qb_list_free(&dc->recv_queued_buffers);
  mbedtls_ssl_free(&dc->ssl);
  uloop_timeout_cancel(&dc->uto_int);
#endif /* DTLS_MBEDTLS */
  uloop_timeout_cancel(&dc->uto);
  free(dc);
}

static bool _connection_poll_write(dtls_connection dc __unused)
{
#ifdef DTLS_OPENSSL
  while (BIO_ctrl_pending(dc->wbio) > 0)
    {
      char buf[DTLS_MAXIMUM_PAYLOAD_SIZE_PLUS_1];
      int outsize = BIO_read(dc->wbio, buf, sizeof(buf));
      if (outsize == DTLS_MAXIMUM_PAYLOAD_SIZE_PLUS_1)
        {
          L_ERR("attempted to send too long packet: %d(+) bytes", outsize);
          continue;
        }
      udp46 s = dc->is_client ? dc->d->u46_client : dc->d->u46_server;
      int r = udp46_send(s, dc->has_local_addr ? &dc->local_addr : NULL,
                         &dc->remote_addr, buf, outsize);
      if (r != outsize)
        {
          if (r < 0)
            L_DEBUG("send error");
          else
            L_DEBUG("short send?!? %d != %d", r, outsize);
        }
    }
#endif /* DTLS_OPENSSL */
  /* We do not close sockets here. */
  return true;
}

static bool _connection_poll_read(dtls_connection dc);

static bool _connection_shutdown(dtls_connection dc)
{
  if (dc->state == STATE_SHUTDOWN)
    return true;
  if (dc->state == STATE_DATA)
    dc->d->num_data_connections--;
  else
    dc->d->num_non_data_connections--;
  dc->state = STATE_SHUTDOWN;

#ifdef DTLS_OPENSSL
  /* The SSL_shutdown needs to be called 2+ times; first time, it
   * does local bookkeeping, and second time confirms receipt of
   * ack from remote side (eventually). */
  (void)SSL_shutdown(dc->ssl);
#endif /* DTLS_OPENSSL */

  /* Initially write the shutdown, and then wait for it to complete if
   * we feel like it. */
  return _connection_poll_write(dc) && _connection_poll_read(dc);
}

static void _connection_drop(dtls d, bool is_data)
{
  dtls_connection dc, dc2, lru = NULL;
  int dropped = 0;

  list_for_each_entry_safe(dc, dc2, &d->connections, in_connections)
    {
      if (dc->state == STATE_SHUTDOWN)
        continue;
      if ((d->t - dc->last_use) >= DTLS_LIMIT(connection_idle_limit_seconds))
        {
          if ((dc->state == STATE_DATA) == !!is_data)
            dropped++;
          _connection_shutdown(dc);
          continue;
        }
      if ((dc->state == STATE_DATA) == !is_data)
        continue;
      if (lru && lru->last_use <= dc->last_use)
        continue;
      lru = dc;
    }
  if (dropped || !lru)
    return;
  _connection_shutdown(lru);
}

static void _connection_poll(dtls_connection dc)
{
  /*
   * If _connection_poll_read returns false, dc pointer is no longer valid
   * -> do nothing here.
   */
  if (!_connection_poll_read(dc))
    return;
  (void)_connection_poll_write(dc);
}

static void _connection_uto_cb(struct uloop_timeout *t)
{
  dtls_connection dc = container_of(t, dtls_connection_s, uto);

  L_DEBUG("_connection_uto_cb %p", dc);
#ifdef DTLS_OPENSSL
  DTLSv1_handle_timeout(dc->ssl);
#endif /* DTLS_OPENSSL */

  /* reset the timeout */
  _connection_poll(dc);
}

#ifdef DTLS_MBEDTLS
static void _connection_uto_int_cb(struct uloop_timeout *t)
{
  dtls_connection dc = container_of(t, dtls_connection_s, uto_int);

  L_DEBUG("_connection_uto_int_cb %p", dc);

  /* reset the timeout */
  _connection_poll(dc);
}
#endif /* DTLS_MBEDTLS */

static dtls_connection
_connection_find(dtls d, int is_client, const struct sockaddr_in6 *dst)
{
  dtls_connection dc;

  L_DEBUG("_connection_find dst:%s", HEX_REPR(dst, sizeof(*dst)));
  list_for_each_entry(dc, &d->connections, in_connections)
    if (dc->state != STATE_SHUTDOWN
        && (is_client < 0 || (!is_client == !dc->is_client)))
      if (memcmp(dst, &dc->remote_addr, sizeof(*dst)) == 0)
        {
          dc->last_use = d->t;
          return dc;
        }
  return NULL;
}

static void _dtls_update_t(dtls d)
{
  time_t t = time(NULL);

  if (t == d->t)
    return;

  d->t = t;
  d->pps = 0;
}

#ifdef DTLS_MBEDTLS
int _mbedtls_send(void *o, const unsigned char *buf, size_t len)
{
  dtls_connection dc = o;
  udp46 s = dc->is_client ? dc->d->u46_client : dc->d->u46_server;

  return udp46_send(s, dc->has_local_addr ? &dc->local_addr : NULL,
                    &dc->remote_addr, (void *)buf, len);
}

int _mbedtls_recv(void *o, unsigned char *buf, size_t len)
{
  dtls_connection dc = o;
  dtls_queued_buffer qb;

  list_for_each_entry(qb, &dc->recv_queued_buffers, in_queued_buffers)
    {
      size_t got = qb->len - qb->ofs;
      if (got > len)
        {
          memcpy(buf, qb->buf+qb->ofs, len);
          qb->ofs += len;
          return len;
        }
      memcpy(buf, qb->buf+qb->ofs, got);
      _qb_free(qb);
      return got;
    }
  return MBEDTLS_ERR_SSL_WANT_READ;
}

void _mbedtls_set_timer(void *o, uint32_t int_ms, uint32_t fin_ms)
{
  dtls_connection dc = o;

  if (fin_ms)
    {
      uloop_timeout_set(&dc->uto, fin_ms);
      uloop_timeout_set(&dc->uto_int, int_ms);
      dc->uto_valid = true;
    }
  else
    {
      uloop_timeout_cancel(&dc->uto);
      dc->uto_valid = false;
    }
}

int _mbedtls_get_timer(void *o)
{
  dtls_connection dc = o;

  if (!dc->uto_valid)
    return -1;
  /* Final delay expired */
  if (!dc->uto.pending)
    return 2;
  /* Intermediate delay expired */
  if (!dc->uto_int.pending)
    return 1;
  return 0;
}

#endif /* DTLS_MBEDTLS */

static dtls_connection
_connection_create(dtls d, bool is_client,
                   const struct sockaddr_in6 *remote_addr)
{
  dtls_connection dc = calloc(1, sizeof(*dc));

  if (!dc)
    return NULL;
  if (d->num_non_data_connections == DTLS_LIMIT(num_non_data_connections))
    _connection_drop(d, false);
  INIT_LIST_HEAD(&dc->send_queued_buffers);
  dc->d = d;
  _dtls_update_t(d);
  dc->last_use = d->t;
  dc->uto.cb = _connection_uto_cb;
#ifdef DTLS_MBEDTLS
  dc->uto_int.cb = _connection_uto_int_cb;
  INIT_LIST_HEAD(&dc->recv_queued_buffers);
#endif /* DTLS_MBEDTLS */
  dc->remote_addr = *remote_addr;
  dc->is_client = is_client;
  d->num_non_data_connections++;
  if (is_client)
    dc->state = STATE_CONNECT;
  else
    dc->state = STATE_ACCEPT;

#ifdef DTLS_OPENSSL

  SSL *ssl = SSL_new(is_client ? d->ssl_client_ctx : d->ssl_server_ctx);
  if (!ssl)
    {
      L_ERR("SSL_new failed for %s", is_client ? "client" : "server");
      free(dc);
      return NULL;
    }
  SSL_set_ex_data(ssl, 0, dc);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

  dc->rbio = BIO_new(BIO_s_mem());
  dc->wbio = BIO_new(BIO_s_mem());
  BIO_set_mem_eof_return(dc->rbio, -1);
  BIO_set_mem_eof_return(dc->wbio, -1);

  SSL_set_bio(ssl, dc->rbio, dc->wbio);

  dc->ssl = ssl;
#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS
  if (mbedtls_ssl_setup(&dc->ssl, is_client ? &d->ssl_client_config
                        : &d->ssl_server_config))
    {
      L_ERR("mbedtls_ssl_setup failed for %s", is_client ? "client" : "server");
      free(dc);
      return NULL;
    }
  if (!is_client)
    {

      if (mbedtls_ssl_set_client_transport_id(&dc->ssl,
                                              (void *)remote_addr,
                                              sizeof(*remote_addr)))
        {
          L_ERR("unable to mbedtls_ssl_set_client_transport_id");
        }
    }
  mbedtls_ssl_set_bio(&dc->ssl, dc, _mbedtls_send, _mbedtls_recv, NULL);
  mbedtls_ssl_set_timer_cb(&dc->ssl, dc, _mbedtls_set_timer, _mbedtls_get_timer);
#endif /* DTLS_MBEDTLS */

  list_add(&dc->in_connections, &d->connections);

  L_DEBUG("Created new %s connection %p to %s",
          is_client ? "client[connect]" : "server[accept]",
          dc, HEX_REPR(remote_addr, sizeof(*remote_addr)));
  return dc;
}

static void _dtls_poll(dtls d, bool is_client)
{
  struct sockaddr_in6 remote_addr, local_addr;
  int rv;
  char buf[DTLS_MAXIMUM_PAYLOAD_SIZE_PLUS_1];
  udp46 s = is_client ? d->u46_client : d->u46_server;

  if ((rv = udp46_recv(s, &remote_addr, &local_addr, buf, sizeof(buf))) <= 0)
    {
      L_DEBUG("recvfrom did not return anything");
      return;
    }

  if (rv == DTLS_MAXIMUM_PAYLOAD_SIZE_PLUS_1)
    {
      L_ERR("received too long packet: %d(+) bytes", rv);
      return;
    }

  _dtls_update_t(d);
  if (d->pps++ >= DTLS_LIMIT(input_pps))
    {
      L_DEBUG("dropping packet due to too big pps (%d > %d)",
              d->pps, DTLS_LIMIT(input_pps));
      return;
    }

  dtls_connection dc = _connection_find(d, is_client, &remote_addr);
  if (!dc)
    {
      /* No new connections on client port */
      if (is_client)
        {
          L_DEBUG("ignoring %d bytes from unknown source on client port", rv);
          return;
        }
      /* If it's server, let's make sure it is not DTLS alert to
       * already closed connection. Those have funny replay
       * properties.. */
      if (rv > 0 && buf[0] == 21)
        return;
      dc = _connection_create(d, false, &remote_addr);
      if (!dc)
        return;
    }
  dc->has_local_addr = true;
  dc->local_addr = local_addr;

#if defined(DTLS_OPENSSL)
  /* Feed in the data to the BIO */
  L_DEBUG("adding %d bytes to rbio", rv);
  BIO_write(dc->rbio, buf, rv);
#elif defined(DTLS_MBEDTLS)
  dtls_queued_buffer qb = calloc(1, sizeof(*qb) + rv);
  if (!qb)
    {
      L_ERR("calloc qbuf");
    }
  memcpy(qb->buf, buf, rv);
  qb->len = rv;
  list_add(&qb->in_queued_buffers, &dc->recv_queued_buffers);
#endif

  /* Let the connection do what it feels like. */
  _connection_poll(dc);
}

static void
_dtls_server_cb(udp46 s __unused, void *context)
{
  dtls d = context;

  L_DEBUG("_dtls_server_cb");
  _dtls_poll(d, false);
}

static void
_dtls_client_cb(udp46 s __unused, void *context)
{
  dtls d = context;

  L_DEBUG("_dtls_ufd_client_cb");
  _dtls_poll(d, true);
}

void dtls_set_readable_cb(dtls d,
                          dtls_readable_cb cb, void *cb_context)
{
  d->readable_cb = cb;
  d->readable_cb_context = cb_context;
}

void dtls_set_unknown_cert_cb(dtls d,
                              dtls_unknown_cb cb,
                              void *cb_context)
{
  d->unknown_cb = cb;
  d->unknown_cb_context = cb_context;
}

/* Create/destroy instance. */
dtls dtls_create(uint16_t port)
{
  dtls d = calloc(1, sizeof(*d));

  if (!_ssl_initialized)
    {
      _ssl_initialized = true;
#ifdef DTLS_OPENSSL
      SSL_load_error_strings();
      SSL_library_init();
#endif /* DTLS_OPENSSL */
    }
  if (!d)
    goto fail;
  if (!(d->u46_server = udp46_create(port)))
    goto fail;
  INIT_LIST_HEAD(&d->connections);

  if (!(d->u46_client = udp46_create(0)))
    goto fail;

  int i;
  for (i = 0 ; i < COOKIE_SECRET_LENGTH ; i++)
    d->cookie_secret[i] = random();

#ifdef DTLS_OPENSSL
#ifdef USE_ONE_CONTEXT
  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_method());
#else
  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_server_method());
#endif /* USE_ONE_CONTEXT */
  if (!ctx)
    {
      L_ERR("unable to create server SSL_CTX");
      goto fail;
    }
  SSL_CTX_set_ex_data(ctx, 0, d);
  SSL_CTX_set_read_ahead(ctx, 1);
  SSL_CTX_set_cookie_generate_cb(ctx, _cookie_gen_cb);
  SSL_CTX_set_cookie_verify_cb(ctx, _cookie_verify_cb);
  d->ssl_server_ctx = ctx;

#ifndef USE_ONE_CONTEXT
  ctx = SSL_CTX_new(DTLSv1_client_method());
  if (!ctx)
    {
      L_ERR("unable to create client SSL_CTX");
      goto fail;
    }
  SSL_CTX_set_ex_data(ctx, 0, d);
  SSL_CTX_set_read_ahead(ctx, 1);
#endif /* !USE_ONE_CONTEXT */
  d->ssl_client_ctx = ctx;
#endif /* DTLS_OPENSSL */

#ifdef DTLS_MBEDTLS
  mbedtls_ssl_config_init(&d->ssl_server_config);
  if (mbedtls_ssl_config_defaults(&d->ssl_server_config,
                                  MBEDTLS_SSL_IS_SERVER,
                                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                  0))
    {
      L_ERR("unable to create server context");
      goto fail;
    }
  mbedtls_ssl_conf_dbg(&d->ssl_server_config, _mbedtls_debug, NULL);
  mbedtls_ssl_conf_rng(&d->ssl_server_config, _mbedtls_random, NULL);
  mbedtls_ssl_conf_dtls_cookies(&d->ssl_server_config,
                                _mbedtls_cookie_write, _mbedtls_cookie_check,
                                d);

  mbedtls_ssl_config_init(&d->ssl_client_config);
  if (mbedtls_ssl_config_defaults(&d->ssl_client_config,
                                  MBEDTLS_SSL_IS_CLIENT,
                                  MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                  0))
    {
      L_ERR("unable to create client context");
      goto fail;
    }
  mbedtls_ssl_conf_dbg(&d->ssl_client_config, _mbedtls_debug, NULL);
  mbedtls_ssl_conf_rng(&d->ssl_client_config, _mbedtls_random, NULL);

  mbedtls_debug_set_threshold(2);

#endif /* DTLS_MBEDTLS */

  L_DEBUG("dtls_create succeeded for (server) port %d", port);
  return d;

 fail:
  if (d)
    dtls_destroy(d);
  return NULL;
}

void dtls_set_limits(dtls d, dtls_limits limits)
{
  d->limits = *limits;
}


void dtls_start(dtls d)
{
  if (d->started) return;
  d->started = true;
  udp46_set_readable_cb(d->u46_server, _dtls_server_cb, d);
  udp46_set_readable_cb(d->u46_client, _dtls_client_cb, d);
}

void dtls_destroy(dtls d)
{
  dtls_connection dc, dc2;

  if (d->psk)
    free(d->psk);
#ifdef DTLS_OPENSSL
  SSL_CTX_free(d->ssl_server_ctx);
#ifndef USE_ONE_CONTEXT
  SSL_CTX_free(d->ssl_client_ctx);
#endif /* USE_ONE_CONTEXT */
#endif /* DTLS_OPENSSL */

  list_for_each_entry_safe(dc, dc2, &d->connections, in_connections)
    _connection_free(dc);

#ifdef DTLS_MBEDTLS
  mbedtls_ssl_config_free(&d->ssl_server_config);
  mbedtls_ssl_config_free(&d->ssl_client_config);
#endif /* DTLS_MBEDTLS */

  udp46_destroy(d->u46_server);
  udp46_destroy(d->u46_client);
  free(d);
}

/* Send/receive data. */
ssize_t dtls_recv(dtls d,
                  struct sockaddr_in6 **src,
                  struct sockaddr_in6 **dst,
                  void *buf, size_t len)
{
  dtls_connection dc;

  L_DEBUG("dtls_recvfrom");
  d->readable = false;
  list_for_each_entry(dc, &d->connections, in_connections)
    {
      ssize_t rv = SSL_read(dc->ssl, buf, len);
      if (rv > 0)
        {
          L_DEBUG(" .. winner from s-connection %p: %d bytes", dc, (int)rv);
          *src = &dc->remote_addr;
          if (dc->has_local_addr)
            *dst = &dc->local_addr;
          else
            *dst = NULL;
          return rv;
        }
#ifdef DTLS_MBEDTLS
      if (rv == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
          (void)_connection_shutdown(dc);
          break;
        }
#endif /* DTLS_MBEDTLS */
    }
  return -1;
}

ssize_t dtls_send(dtls d,
                  const struct sockaddr_in6 *src __unused,
                  const struct sockaddr_in6 *dst,
                  void *buf, size_t len)
{
  L_DEBUG("dtls_sendto");
  _dtls_update_t(d);
  dtls_connection dc = _connection_find(d, -1, dst);
  if (dc)
    {
      if (dc->state == STATE_DATA)
        {
          size_t rv = SSL_write(dc->ssl, buf, len);
          if (rv > 0)
            {
              if (rv != len)
                {
                  L_ERR("partial write?!?");
#ifdef DTLS_OPENSSL
                  _drain_errors();
#endif /* DTLS_OPENSSL */
                  return -1;
                }
              _connection_poll_write(dc);
              return rv;
            }
        }
      L_DEBUG("had existing connection");
    }

  if (!dc)
    {
      /* Create new connection object */
      dc = _connection_create(d, true, dst);
      if (!dc)
        return -1;
      _connection_poll(dc);
      /* This may cause the connection to be invalidated. So make sure
       * it is still ok (although new connections almost never should
       * be killed outright, but API-wise it is possible). */
      dc = _connection_find(d, true, dst);
      if (!dc)
        return -1;
    }
  dtls_queued_buffer qb = calloc(1, sizeof(*qb) + len);
  if (!qb)
    {
      L_ERR("calloc qbuf");
      return -1;
    }
  memcpy(qb->buf, buf, len);
  qb->len = len;
  list_add(&qb->in_queued_buffers, &dc->send_queued_buffers);
  return len;
}

/******************************* Implementation-specific authentication code */

/* Note that setting up o f e.g. PSK or certificate things is very
 * much implementation dependant. So instead of having common methods
 * with bunch of ifdefs, we have simply few ifdef'd functions here. */

#ifdef DTLS_OPENSSL


static bool _connection_poll_read(dtls_connection dc)
{
  unsigned char buf[1];
  int rv;
  dtls_queued_buffer qb, qb2;
  dtls d = dc->d;

  L_DEBUG("_connection_poll_read %p @%d", dc, dc->state);
 redo:
  switch (dc->state)
    {
    case STATE_ACCEPT:
      if ((rv = SSL_accept(dc->ssl)) > 0)
        {
          L_DEBUG("connection %p accept->data", dc);
        to_data:
          if (dc->d->num_data_connections == DTLS_LIMIT(num_data_connections))
            _connection_drop(d, true);
          dc->d->num_non_data_connections--;
          dc->d->num_data_connections++;
          dc->state = STATE_DATA;
          goto redo;
        }
      break;
    case STATE_CONNECT:
      if ((rv = SSL_connect(dc->ssl)) > 0)
        {
          L_DEBUG("connection %p connect->data", dc);
          goto to_data;
        }
      break;
    case STATE_DATA:
      /* Initially try to flush writes. Then try to flush reads. */
      list_for_each_entry_safe(qb, qb2, &dc->send_queued_buffers,
                               in_queued_buffers)
        {
          rv = SSL_write(dc->ssl, qb->buf, qb->len);
          if (rv > 0)
            {
              if (rv != qb->len)
                L_ERR("partial write from queue?!?");
              else
                L_DEBUG("wrote %d from queue", (int)rv);
              _qb_free(qb);
            }
          else
            {
              L_DEBUG("queued data write of %d failed", (int)qb->len);
              _drain_errors();
              return true;
            }
        }
      if (SSL_get_shutdown(dc->ssl) == SSL_RECEIVED_SHUTDOWN)
        {
          L_DEBUG(" .. shutdown flag is set");
          return _connection_shutdown(dc);
        }
      if (dc->d->readable)
        {
          L_DEBUG("already readable, no need for further polling of ready");
          return true;
        }
      if (SSL_peek(dc->ssl, buf, 1) <= 0)
        {
          L_DEBUG("nothing in queue according to SSL_peek");
          return true;
        }
      dc->d->readable = true;
      if (dc->d->readable_cb)
        dc->d->readable_cb(dc->d, dc->d->readable_cb_context);
      else
        L_DEBUG("no readable callback on ready connection %p", dc);
      return true;
    case STATE_SHUTDOWN:
      rv = SSL_shutdown(dc->ssl);
      if (rv == 1)
        {
          L_DEBUG("SSL_shutdown 2-step done");
          _connection_free(dc);
          return false;
        }
      return true;
    }
  /* Shared handling of errors for accept/listen */
  if (rv == 0)
    {
      L_DEBUG(" got 0 => terminating connection");
      _connection_free(dc);
      return false;
    }
  /* Non-0, but probably timeout */
  int err = SSL_get_error(dc->ssl, rv);
  _drain_errors();
  if (err != SSL_ERROR_WANT_READ)
    {
      if (dc->state != STATE_SHUTDOWN)
        {
          L_DEBUG("shutting down connection due to error");
          return _connection_shutdown(dc);
        }
      else
        {
          /* Shutdown itself failed somehow. Just pretend it succeeded. */
          L_DEBUG(" shutdown failed? -> killing connection");
          _connection_free(dc);
          return false;
        }
    }

  /* Handle the timeout here too */
  struct timeval tv = { 0, 0 };
  if (DTLSv1_get_timeout(dc->ssl, &tv) == 1)
    {
      L_DEBUG("c-timeout in %d/%d", (int)tv.tv_sec, (int)tv.tv_usec);
      uloop_timeout_set(&dc->uto, tv.tv_usec / 1000 + 1000 * tv.tv_sec);
    }
  else
    uloop_timeout_cancel(&dc->uto);
  return true;
}

#define R1(where, x) do                                 \
    {                                                   \
      int rv = (x);                                     \
      if (rv != 1)                                      \
        {                                               \
          L_ERR("error in %s:%d/%d", where, rv, errno); \
          _drain_errors();                              \
          goto fail;                                    \
        }                                               \
    } while(0)

static int _verify_cert_cb(int ok, X509_STORE_CTX *ctx)
{
  dtls d = CRYPTO_get_ex_data(&ctx->ctx->ex_data, 0);

  if (!d)
    {
      L_ERR("unable to find dtls instance");
      return 0;
    }

  /* If OpenSSL says it is ok, not much to add. */
  if (ok)
    {
      L_DEBUG("certificate ok according to SSL library");
      return 1;
    }

  X509 *cert = X509_STORE_CTX_get_current_cert(ctx);

  if (d->unknown_cb && cert)
    {
      if (d->unknown_cb(d, cert, d->unknown_cb_context))
        return 1;
    }
#if L_LEVEL >= LOG_ERR
  int depth = X509_STORE_CTX_get_error_depth(ctx);
  int error = X509_STORE_CTX_get_error(ctx);

  char buf[256];
  L_ERR("error %d:%s with certificate at depth %d",
        error, X509_verify_cert_error_string(error), depth);
  if (cert)
    {
      X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
      if (*buf)
        L_ERR("- issuer:%s", buf);
      X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
      if (*buf)
        L_ERR("- subject:%s", buf);
    }
#endif /* L_LEVEL >= LOG_ERR */
  return 0;
}

bool dtls_set_local_cert(dtls d, const char *certfile, const char *pkfile)
{
  R1("server cert",
     SSL_CTX_use_certificate_chain_file(d->ssl_server_ctx, certfile));
  R1("server private key",
     SSL_CTX_use_PrivateKey_file(d->ssl_server_ctx, pkfile, SSL_FILETYPE_PEM));
  SSL_CTX_set_verify(d->ssl_server_ctx, SSL_VERIFY_PEER
                     |SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                     , _verify_cert_cb);
  CRYPTO_set_ex_data(&d->ssl_server_ctx->cert_store->ex_data, 0, d);

#ifndef USE_ONE_CONTEXT
  R1("client cert",
     SSL_CTX_use_certificate_chain_file(d->ssl_client_ctx, certfile));
  R1("client private key",
     SSL_CTX_use_PrivateKey_file(d->ssl_client_ctx, pkfile, SSL_FILETYPE_PEM));
  SSL_CTX_set_verify(d->ssl_client_ctx, SSL_VERIFY_PEER
                     |SSL_VERIFY_PEER_FAIL_IF_NO_PEER_CERT
                     , _verify_cert_cb);
  CRYPTO_set_ex_data(&d->ssl_client_ctx->cert_store->ex_data, 0, d);
#endif /* !USE_ONE_CONTEXT */

  return true;
 fail:
  return false;
}

bool dtls_set_verify_locations(dtls d, const char *path, const char *dir)
{
  if (SSL_CTX_load_verify_locations(d->ssl_server_ctx, path, dir) != 1)
    {
      _drain_errors();
      return false;
    }
#ifndef USE_ONE_CONTEXT
  if (SSL_CTX_load_verify_locations(d->ssl_client_ctx, path, dir) != 1)
    {
      _drain_errors();
      return false;
    }
#endif /* !USE_ONE_CONTEXT */
  return true;
}

static unsigned int
_server_psk(SSL *ssl __unused, const char *identity __unused,
            unsigned char *psk, unsigned int max_psk_len)
{
  dtls_connection dc = SSL_get_ex_data(ssl, 0);

  if (!dc)
    {
      L_ERR("NULL ex_data 0?!?");
      return 0;
    }
  dtls d = dc->d;
  if (!d->psk)
    return 0;
  if (d->psk_len > max_psk_len)
    return 0;
  max_psk_len = d->psk_len;
  memcpy(psk, d->psk, max_psk_len);
  return max_psk_len;
}

static unsigned int
_client_psk(SSL *ssl,
            const char *hint __unused,
            char *identity, unsigned int max_identity_len __unused,
            unsigned char *psk, unsigned int max_psk_len)
{
  /* We don't have identity for the key. */
  *identity = 0;
  return _server_psk(ssl, NULL, psk, max_psk_len);
}


bool dtls_set_psk(dtls d, const char *psk, size_t psk_len)
{
  free(d->psk);
  d->psk = malloc(psk_len);
  if (!d->psk)
    return false;
  d->psk_len = psk_len;
  memcpy(d->psk, psk, psk_len);
  SSL_CTX_set_psk_client_callback(d->ssl_client_ctx, _client_psk);
  SSL_CTX_set_psk_server_callback(d->ssl_server_ctx, _server_psk);
  return true;
}

bool dtls_cert_to_pem_buf(dtls_cert cert, char *buf, int buf_len)
{
  BIO *bio = BIO_new(BIO_s_mem());
  int r;

  PEM_write_bio_X509(bio, cert);
  r = BIO_read(bio, buf, buf_len);
  if (r < 0 || r >= buf_len)
    return false;
  buf[r] = 0; /* Make sure it is null terminated */
  BIO_free(bio);
  return true;
}

int dtls_cert_to_der_buf(dtls_cert cert, unsigned char *buf, int buf_len)
{
  unsigned char *p = NULL;
  int r = i2d_X509(cert, &p);
  if (r > 0 && r <= buf_len)
    memcpy(buf, p, r);
  else
    r = -1;
  if (p)
    free(p);
  return r;
}

#endif /* DTLS_OPENSSL */


#ifdef DTLS_MBEDTLS

static bool _connection_poll_read(dtls_connection dc)
{
  int rv;
  dtls_queued_buffer qb, qb2;
  dtls d = dc->d;

  L_DEBUG("_connection_poll_read %p @%d", dc, dc->state);
 redo:
  switch (dc->state)
    {
    case STATE_ACCEPT:
    case STATE_CONNECT:
      if ((rv = mbedtls_ssl_handshake(&dc->ssl)) == 0)
        {
          L_DEBUG("handshake %p ->data", dc);
          if (dc->d->num_data_connections == DTLS_LIMIT(num_data_connections))
            _connection_drop(d, true);
          dc->d->num_non_data_connections--;
          dc->d->num_data_connections++;
          dc->state = STATE_DATA;
          goto redo;
        }
      else if ((rv == MBEDTLS_ERR_SSL_WANT_READ))
        {
          /* NOP */
        }
      else if (dc->state == STATE_ACCEPT
               && rv == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED)
        {
          L_DEBUG(" client did not give us a cookie, resetting sesssion");
          mbedtls_ssl_session_reset(&dc->ssl);
          return true;
        }
      else
        {
          L_DEBUG("got -0x%x from handshake => terminating connection", -rv);
          _connection_free(dc);
          return false;
        }
      return true;
      break;
    case STATE_DATA:
      /* Initially try to flush writes. Then try to flush reads. */
      list_for_each_entry_safe(qb, qb2, &dc->send_queued_buffers,
                               in_queued_buffers)
        {
          int left = qb->len-qb->ofs;

          rv = mbedtls_ssl_write(&dc->ssl, qb->buf+qb->ofs, left);
          if (rv == left)
            {
              L_DEBUG("wrote %d from queue", (int)rv);
              _qb_free(qb);
            }
          else if (rv > 0)
            {
              L_DEBUG("partial write of %d bytes succeeded", rv);
              qb->ofs += rv;
              return true;
            }
          else
            {
              L_DEBUG("queued data write of %d failed", (int)qb->len);
              return true;
            }
        }
      if (dc->d->readable)
        {
          L_DEBUG("already readable, no need for further polling of ready");
          return true;
        }
      dc->d->readable = true;
      if (dc->d->readable_cb)
        dc->d->readable_cb(dc->d, dc->d->readable_cb_context);
      else
        L_DEBUG("no readable callback on ready connection %p", dc);
      return true;

    case STATE_SHUTDOWN:
      rv = mbedtls_ssl_close_notify(&dc->ssl);
      L_DEBUG("SSL_shutdown 2-step done");
      _connection_free(dc);
      return false;
    }

  /* Probably not reached.. */
  return true;
}

bool dtls_set_psk(dtls d, const char *psk, size_t psk_len)
{
  unsigned char *dummy_id = (unsigned char *)"x";
  int dummy_id_len = strlen((char *)dummy_id);

  /* TBD: Should we use conf_psk_cb() instead for server? */
  if (mbedtls_ssl_conf_psk(&d->ssl_server_config,
                           (void *)psk, psk_len, dummy_id, dummy_id_len))
    {
      L_ERR("error setting server psk");
      return false;
    }
  if (mbedtls_ssl_conf_psk(&d->ssl_client_config,
                           (void *)psk, psk_len, dummy_id, dummy_id_len))
    {
      L_ERR("error setting client psk");
      return false;
    }
  return true;
}

bool dtls_cert_to_pem_buf(dtls_cert cert __unused, char *buf __unused,
                          int buf_len __unused)
{
  return false;
}

int dtls_cert_to_der_buf(dtls_cert cert __unused, unsigned char *buf __unused,
                         int buf_len __unused)
{
  return -1;
}

bool dtls_set_local_cert(dtls d __unused, const char *certfile __unused,
                         const char *pkfile __unused)
{
  L_ERR("certificates not supported with mbedtls currently");
  return false;
}

bool dtls_set_verify_locations(dtls d __unused, const char *path __unused,
                               const char *dir __unused)
{
  L_ERR("certificates not supported with mbedtls currently");
  return false;
}


#endif /* DTLS_MBEDTLS */
