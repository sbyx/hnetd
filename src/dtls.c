/*
 * $Id: dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:42 2014 mstenber
 * Last modified: Wed Nov  5 16:45:03 2014 mstenber
 * Edit time:     406 min
 *
 */

#include "dtls.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#ifdef DTLS_CYASSL
#include <cyassl/options.h>
#endif /* DTLS_CYASSL */
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <libubox/list.h>
#include <libubox/md5.h>
#include <libubox/uloop.h>
#include <errno.h>
#include <net/if.h>
/* In linux, fcntl.h includes something with __unused. Argh. */
#include <fcntl.h>
#define __unused __attribute__((unused))

#ifdef DTLS_OPENSSL

/* How large random string key we use as base for cookies */
#define COOKIE_SECRET_LENGTH 10

/* 16 = size of md5 hash */
#define COOKIE_LENGTH (sizeof(time_t) + 16)

/* How long cookies are valid (in seconds) */
#define COOKIE_VALIDITY_PERIOD 10

#endif /* DTLS_OPENSSL */

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

/* Except in case of CYASSL - it does not define DTLSv1_method */
#ifdef DTLS_CYASSL
#ifdef USE_ONE_CONTEXT
#undef USE_ONE_CONTEXT
#endif /* USE_ONE_CONTEXT */

/* CyaSSL 3.2.0 compatibility fixes */
#ifndef BIO_new_dgram
#define BIO_new_dgram(s,f) BIO_new_socket(s,f)
#endif /* !BIO_new_dgram */
#define _dtls_listen(d)

#undef SSL_get_ex_data
#define SSL_get_ex_data(ssl,n) _dtls
#undef SSL_set_ex_data
#define SSL_set_ex_data(ssl,n,d)                                        \
do                                                                      \
  {                                                                     \
    if (_dtls && _dtls != d)                                            \
      {                                                                 \
        L_ERR("more than one DTLS context is not supported in CyaSSL"); \
      }                                                                 \
    _dtls = d;                                                          \
  } while(0)

dtls _dtls = NULL;

#endif /* DTLS_CYASSL */

/* These lurk in queue, waiting for connection to finish (outbound). */
typedef struct {
  struct list_head in_queued_buffers;
  int len;
  unsigned char buf[0];
} *dtls_queued_buffer;

typedef struct {
  struct list_head in_connections;

  struct list_head queued_buffers;

  dtls d;

  struct sockaddr_in6 remote_addr;

  enum {
    STATE_ACCEPT,
    STATE_CONNECT,
    STATE_DATA
  } state;

  struct uloop_fd ufd;
  struct uloop_timeout uto;

  SSL *ssl;

} dtls_connection_s, *dtls_connection;

typedef struct dtls_struct {
  /* Client provided - (optional) callback to call when something
   * readable available. */
  dtls_readable_callback cb;
  void *cb_context;

  /* We keep this around, just for re-binding of new received connections. */
  struct sockaddr_in6 local_addr;

  SSL_CTX *ssl_client_ctx;

  SSL_CTX *ssl_server_ctx;

  struct uloop_fd ufd;
  struct uloop_timeout uto;
  int listen_socket;
#ifdef DTLS_OPENSSL
  BIO *listen_bio;
  SSL *listen_ssl;
#endif /* DTLS_OPENSSL */

  struct list_head connections;
#ifdef DTLS_OPENSSL
  unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
#endif /* DTLS_OPENSSL */

  bool readable;
  bool started;

  char *psk;
  unsigned int psk_len;
} dtls_s;

static bool _ssl_initialized = false;

static bool _drain_errors()
{
  if (!ERR_peek_error())
    return false;

#ifndef DTLS_CYASSL
  BIO *bio_stderr = BIO_new(BIO_s_file());
  BIO_set_fp(bio_stderr, stderr, BIO_NOCLOSE|BIO_FP_TEXT);
  ERR_print_errors(bio_stderr);
  BIO_free(bio_stderr);

  /* Clear stack */
  while (ERR_peek_error())
    ERR_get_error();
#endif /* !DTLS_CYASSL */
  return true;
}

#ifdef DTLS_OPENSSL


/* OpenSSL needs this */

static int _cookie_gen_fixed_time(SSL *ssl,
                                  unsigned char *cookie,
                                  unsigned int *cookie_len,
                                  time_t t)
{
  dtls d = SSL_get_ex_data(ssl, 0);
  struct sockaddr_storage ss;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
  md5_ctx_t ctx;
  unsigned char result[COOKIE_LENGTH];

  if (!d)
    {
      L_ERR("NULL ex_data 0?!?");
      return 0;
    }

  (void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &ss);

  /* If it is wrong AF, we do not care. */
  if (sin6->sin6_family != AF_INET6)
    {
      L_ERR("got ipv4 remote peer address?!?");
      return 0;
    }

  /* Store timestamp in the beginning */
  *((time_t *)result) = t;
  md5_begin(&ctx);
  md5_hash(d->cookie_secret, COOKIE_SECRET_LENGTH, &ctx);
  md5_hash(&sin6->sin6_addr, sizeof(sin6->sin6_addr), &ctx);
  md5_hash(&sin6->sin6_port, sizeof(sin6->sin6_port), &ctx);
  md5_hash(result, sizeof(time_t), &ctx);
  md5_end(&result[sizeof(time_t)], &ctx);

  memcpy(cookie, result, sizeof(result));
  *cookie_len = sizeof(result);

  return 1;
}

static int _cookie_gen_cb(SSL *ssl,
                          unsigned char *cookie, unsigned int *cookie_len)
{
  return _cookie_gen_fixed_time(ssl, cookie, cookie_len, time(NULL));
}

static int _cookie_verify_cb(SSL *ssl,
                             unsigned char *cookie, unsigned int cookie_len)
{
  unsigned char tbuf[COOKIE_LENGTH];
  unsigned int tbuf_len = sizeof(tbuf);
  time_t nt, ct;

  /* If it is of different size than what we produce, clearly not ours. */
  if (cookie_len != COOKIE_LENGTH)
    {
      L_ERR("_cookie_verify_cb: invalid cookie length: %d", (int) cookie_len);
      return 0;
    }

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
  if (!_cookie_gen_fixed_time(ssl, tbuf, &tbuf_len, ct))
    {
      L_ERR("_cookie_verify_cb: generate failed");
      return 0;
    }
  if (memcmp(tbuf, cookie, cookie_len) != 0)
    {
      L_ERR("_cookie_verify_cb: data mismatch");
      return 0;
    }
  L_DEBUG("_cookie_verify_cb succeeded");
  return 1;
}

static void _dtls_listen(dtls d);

#endif /* DTLS_OPENSSL */

static void _qb_free(dtls_queued_buffer qb)
{
  list_del(&qb->in_queued_buffers);
  free(qb);
}

static void _connection_free(dtls_connection dc)
{
  dtls_queued_buffer qb, qb2;

  L_DEBUG("_connection_free %p", dc);
  list_for_each_entry_safe(qb, qb2, &dc->queued_buffers, in_queued_buffers)
    _qb_free(qb);
  list_del(&dc->in_connections);
  SSL_free(dc->ssl);
  uloop_fd_delete(&dc->ufd);
  uloop_timeout_cancel(&dc->uto);
  free(dc);
}

static void _connection_poll(dtls_connection dc)
{
  unsigned char buf[1];
  int rv;
  dtls_queued_buffer qb, qb2;

  L_DEBUG("_connection_poll %p @%d", dc, dc->state);
  switch (dc->state)
    {
    case STATE_ACCEPT:
      if ((rv = SSL_accept(dc->ssl)) > 0)
        {
          L_DEBUG("connection %p accept->data", dc);
          dc->state = STATE_DATA;
          _connection_poll(dc);
          return;
        }
      break;
    case STATE_CONNECT:
      if ((rv = SSL_connect(dc->ssl)) > 0)
        {
          L_DEBUG("connection %p connect->data", dc);
          dc->state = STATE_DATA;
          _connection_poll(dc);
          return;
        }
      break;
    case STATE_DATA:
      /* Initially try to flush writes. Then try to flush reads. */
      list_for_each_entry_safe(qb, qb2, &dc->queued_buffers, in_queued_buffers)
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
              return;
            }
        }

      if (dc->d->readable)
        {
          L_DEBUG("already readable, no need for further polling of ready");
          return;
        }
      if (SSL_peek(dc->ssl, buf, 1) <= 0)
        {
          L_DEBUG("nothing in queue according to SSL_peek");
          return;
        }
      dc->d->readable = true;
      if (dc->d->cb)
        dc->d->cb(dc->d, dc->d->cb_context);
      else
        L_DEBUG("no readable callback on ready connection %p", dc);
      return;
    }
  /* Shared handling of errors for accept/listen */
  if (rv == 0)
    {
      L_DEBUG(" got 0 => terminating connection");
      _connection_free(dc);
      return;
    }
  /* Non-0, but probably timeout */
  int err = SSL_get_error(dc->ssl, rv);
  if (err != SSL_ERROR_WANT_READ)
    _drain_errors();

  /* Handle the timeout here too */
  struct timeval tv = { 0, 0 };
#ifdef DTLS_OPENSSL
  if (DTLSv1_get_timeout(dc->ssl, &tv) == 1)
#else
#ifdef DTLS_CYASSL
  if ((tv.tv_sec = CyaSSL_dtls_get_current_timeout(dc->ssl)) > 0)
#else
#error
#endif /* DTLS_CYASSL */
#endif /* DTLS_OPENSSL */
    {
      L_DEBUG("c-timeout in %d/%d", (int)tv.tv_sec, (int)tv.tv_usec);
      uloop_timeout_set(&dc->uto, tv.tv_usec / 1000 + 1000 * tv.tv_sec);
    }
  else
    uloop_timeout_cancel(&dc->uto);
}

static int _socket_connect(const struct sockaddr_in6 *local_addr,
                           const struct sockaddr_in6 *remote_addr)
{
  int s = socket(AF_INET6, SOCK_DGRAM, 0);
  int on = 1;

  if (s < 0)
    {
      L_ERR("unable to create IPv6 socket");
      return -1;
    }
  fcntl(s, F_SETFL, O_NONBLOCK);
  if (local_addr)
    {
#ifdef SO_REUSEPORT
      setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif /* SO_REUSEPORT */
      setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
      if (bind(s, (struct sockaddr *)local_addr, sizeof(*local_addr))<0)
        {
          L_ERR("unable to bind [client]");
          goto fail;
        }
    }
  if (connect(s, (struct sockaddr *)remote_addr, sizeof(*remote_addr))<0)
    {
      L_ERR("unable to connect [client]");
      goto fail;
    }
  return s;
 fail:
  close(s);
  return -1;
}

void _connection_ufd_cb(struct uloop_fd *u, unsigned int events __unused)
{
  dtls_connection dc = container_of(u, dtls_connection_s, ufd);

  L_DEBUG("_connection_ufd_cb %p", dc);
  _connection_poll(dc);
}

void _connection_uto_cb(struct uloop_timeout *t)
{
  dtls_connection dc = container_of(t, dtls_connection_s, uto);

  L_DEBUG("_connection_uto_cb %p", dc);
#ifdef DTLS_OPENSSL
  DTLSv1_handle_timeout(dc->ssl);
#endif /* DTLS_OPENSSL */
#ifdef DTLS_CYASSL
  CyaSSL_dtls_got_timeout(dc->ssl);
#endif /* DTLS_CYASSL */

  /* reset the timeout */
  _connection_poll(dc);
}

static dtls_connection _connection_find(dtls d, const struct sockaddr_in6 *dst)
{
  dtls_connection dc;

  list_for_each_entry(dc, &d->connections, in_connections)
    if (memcmp(dst, &dc->remote_addr, sizeof(*dst)) == 0)
      return dc;
  return NULL;
}

static dtls_connection _connection_create(dtls d, int s)
{
  dtls_connection dc = calloc(1, sizeof(*dc));
  if (!dc)
    return NULL;
  INIT_LIST_HEAD(&dc->queued_buffers);
  dc->d = d;
  dc->uto.cb = _connection_uto_cb;
  dc->ufd.cb = _connection_ufd_cb;
  dc->ufd.fd = s;
  uloop_fd_add(&dc->ufd, ULOOP_READ);
  list_add(&dc->in_connections, &d->connections);
  /* ssl, state are NOT set here but by client. */
  return dc;
}

static void _dtls_poll(dtls d)
{
  struct sockaddr_in6 remote_addr;
  int rv;
  dtls_connection dc = NULL;

#ifdef DTLS_OPENSSL

  if ((rv = DTLSv1_listen(d->listen_ssl, &remote_addr)) <= 0)
    {
      if (rv < 0)
        {
          int err = SSL_get_error(d->listen_ssl, rv);
          if (err != SSL_ERROR_WANT_READ)
            _drain_errors();
          else
            L_DEBUG("DTLSv1_listen wanted more");
        }
      else
        L_DEBUG("DTLSv1_listen returned 0");
      goto wait;
    }
  L_DEBUG("_dtls_poll: new connection accepted");
  /* seems like it sometimes returns 0 even if it does not really mean
   * it, grr */
  if (_drain_errors())
    goto wait;
#endif /* DTLS_OPENSSL */
#ifdef DTLS_CYASSL
  /* There is no elegant way of handling the no-DTLSv1_listen case
   * that is both secure, and works instantly. So we simply recvfrom
   * (_without_ peek) from the socket, and let the resend set up the
   * connection.
   *
   * (In principle, PEEK + some socket juggling would work, unless
   * there are in queue packets from multiple parties and in that case
   * SSL state machine would get horribly confused. Sigh.)
   */
  char buf[1];
  socklen_t remote_len = sizeof(remote_addr);

  if ((rv = recvfrom(d->listen_socket, buf, sizeof(buf), 0,
                     &remote_addr, &remote_len)) <= 0)
    {
      L_DEBUG("recvfrom did not return anything");
      goto wait;
    }

#endif /* DTLS_CYASSL */

  int s = _socket_connect(&d->local_addr, &remote_addr);
  if (s < 0)
    goto fail;

  dc = _connection_create(d, s);
  if (!dc)
    goto fail;
  dc->remote_addr = remote_addr;
  dc->state = STATE_ACCEPT;
#ifdef DTLS_OPENSSL
  BIO_set_fd(d->listen_bio, s, 0);
  BIO_ctrl(d->listen_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);
  dc->ssl = d->listen_ssl;
#endif /* DTLS_OPENSSL */
#ifdef DTLS_CYASSL
  SSL *ssl = SSL_new(d->ssl_server_ctx);
  if (!ssl)
    {
      L_ERR("CyaSSL SSL_new");
      goto fail;
    }
  SSL_set_ex_data(ssl, 0, d);
  CyaSSL_set_fd(ssl, s);
  CyaSSL_set_using_nonblock(ssl, 1);
  rv =
    CyaSSL_dtls_set_peer(ssl, &dc->remote_addr, sizeof(dc->remote_addr));
  if (rv != SSL_SUCCESS)
    {
      L_ERR("CyaSSL_dtls_set_peer");
      goto fail;
    }
  dc->ssl = ssl;
#endif /* DTLS_CYASSL */
  /* Poll the connection to mark it 'live' */
  _connection_poll(dc);

  /* Re-initialize new SSL context on listening socket. */
  _dtls_listen(d);
  return;
 fail:
  if (dc)
    free(dc);
  close(s);
  return;

 wait:
  {
#ifdef DTLS_OPENSSL
    /* Set up the timeout */
    struct timeval tv;
    if (DTLSv1_get_timeout(d->listen_ssl, &tv) == 1)
      {
        L_DEBUG("l-timeout in %d/%d", (int)tv.tv_sec, (int)tv.tv_usec);
        uloop_timeout_set(&d->uto, tv.tv_usec / 1000 + 1000 * tv.tv_sec);
      }
    else
      uloop_timeout_cancel(&d->uto);
#endif /* DTLS_OPENSSL */
  }
}

#ifdef DTLS_OPENSSL
static void _dtls_listen(dtls d)
{
  d->listen_bio = BIO_new_dgram(d->listen_socket, BIO_NOCLOSE);
  SSL *ssl = SSL_new(d->ssl_server_ctx);
  if (!ssl)
    {
      L_ERR("SSL_new failed");
      _drain_errors();
      return;
    }
  SSL_set_ex_data(ssl, 0, d);
  d->listen_ssl = ssl;
  SSL_set_bio(ssl, d->listen_bio, d->listen_bio);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  _dtls_poll(d);
}
#endif /* DTLS_OPENSSL */

void _dtls_ufd_cb(struct uloop_fd *u, unsigned int events __unused)
{
  dtls d = container_of(u, dtls_s, ufd);

  L_DEBUG("_dtls_ufd_cb");
  _dtls_poll(d);
}

void _dtls_uto_cb(struct uloop_timeout *t)
{
  dtls d = container_of(t, dtls_s, uto);

  L_DEBUG("_dtls_uto_cb");
#ifdef DTLS_OPENSSL
  DTLSv1_handle_timeout(d->listen_ssl);
#endif /* DTLS_OPENSSL */
  _dtls_poll(d);
}

void dtls_set_readable_callback(dtls d,
                                dtls_readable_callback cb, void *cb_context)
{
  d->cb = cb;
  d->cb_context = cb_context;
}

/* Create/destroy instance. */
dtls dtls_create(uint16_t port)
{
  int s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s<0)
    {
      L_ERR("unable to create IPv6 UDP socket");
      return NULL;
    }
  fcntl(s, F_SETFL, O_NONBLOCK);

  dtls d = calloc(1, sizeof(*d));

  if (!_ssl_initialized)
    {
      _ssl_initialized = true;
      SSL_load_error_strings();
      SSL_library_init();
    }
  if (!d)
    goto fail;
  INIT_LIST_HEAD(&d->connections);

  memset(&d->local_addr, 0, sizeof(d->local_addr));
  d->local_addr.sin6_family = AF_INET6;
  d->local_addr.sin6_port = htons(port);

  int on = 1;
#ifdef SO_REUSEPORT
  setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif /* SO_REUSEPORT */
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (bind(s, (struct sockaddr *)&d->local_addr, sizeof(d->local_addr))<0)
    {
      L_ERR("unable to bind to port %d", port);
      goto fail;
    }
#if 0
  /* needed? */
  if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
    {
      L_ERR("unable to setsockopt IPV6_RECVPKTINFO:%s", strerror(errno));
      goto fail;
    }
#endif /* 0 */
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
#ifdef DTLS_OPENSSL
  SSL_CTX_set_read_ahead(ctx, 1);
  SSL_CTX_set_cookie_generate_cb(ctx, _cookie_gen_cb);
  SSL_CTX_set_cookie_verify_cb(ctx, _cookie_verify_cb);
  RAND_bytes(d->cookie_secret, COOKIE_SECRET_LENGTH);
#endif /* DTLS_OPENSSL */
  d->ssl_server_ctx = ctx;

#ifndef USE_ONE_CONTEXT
  ctx = SSL_CTX_new(DTLSv1_client_method());
  if (!ctx)
    {
      L_ERR("unable to create client SSL_CTX");
      goto fail;
    }
#ifdef DTLS_OPENSSL
  SSL_CTX_set_read_ahead(ctx, 1);
#endif /* DTLS_OPENSSL */
#endif /* !USE_ONE_CONTEXT */
  d->ssl_client_ctx = ctx;
  d->listen_socket = s;
  d->uto.cb = _dtls_uto_cb;
  d->ufd.cb = _dtls_ufd_cb;
  d->ufd.fd = s;
  L_DEBUG("dtls_create succeeded - fd %d @ port %d", s, port);
  return d;

 fail:
  if (s>0)
    close(s);
  free(d);
  return NULL;
}

void dtls_start(dtls d)
{
  if (d->started) return;
  d->started = true;
  uloop_fd_add(&d->ufd, ULOOP_READ);
  _dtls_listen(d);
}

void dtls_destroy(dtls d)
{
  dtls_connection dc, dc2;

  if (d->psk)
    free(d->psk);
#ifdef DTLS_OPENSSL
  SSL_free(d->listen_ssl);
#endif /* DTLS_OPENSSL */
  SSL_CTX_free(d->ssl_server_ctx);
#ifndef USE_ONE_CONTEXT
  SSL_CTX_free(d->ssl_client_ctx);
#endif /* USE_ONE_CONTEXT */
  list_for_each_entry_safe(dc, dc2, &d->connections, in_connections)
    {
      _connection_free(dc);
    }
  /* XXX - get rid of client connections too */
  uloop_fd_delete(&d->ufd);
  uloop_timeout_cancel(&d->uto);
  free(d);
}

/* Send/receive data. */
ssize_t dtls_recvfrom(dtls d, void *buf, size_t len,
                      struct sockaddr_in6 *src)
{
  dtls_connection dc;

  L_DEBUG("dtls_recvfrom");
  d->readable = false;
  list_for_each_entry(dc, &d->connections, in_connections)
    {
      ssize_t rv = SSL_read(dc->ssl, buf, len);
      if (rv > 0)
        {
          L_DEBUG(" .. winner from connection %p: %d bytes", dc, (int)rv);
          *src = dc->remote_addr;
          return rv;
        }
    }
  return -1;
}

ssize_t dtls_sendto(dtls d, void *buf, size_t len,
                    const struct sockaddr_in6 *dst)
{
  L_DEBUG("dtls_sendto");
  dtls_connection dc = _connection_find(d, dst);
  if (dc && memcmp(dst, &dc->remote_addr, sizeof(*dst)) == 0)
    {
      if (dc->state == STATE_DATA)
        {
          size_t rv = SSL_write(dc->ssl, buf, len);
          if (rv > 0)
            {
              if (rv != len)
                {
                  L_ERR("partial write?!?");
                  _drain_errors();
                  return -1;
                }
              L_DEBUG("had existing connection in good state, write ok");
              return rv;
            }
        }
      L_DEBUG("had existing connection");
    }

  if (!dc)
    {
      /* Create new connection object */
      L_DEBUG("creating new client connection");
#ifdef USE_FLOATING_CLIENT_PORT
      int s = _socket_connect(NULL, dst);
#else
      int s = _socket_connect(&d->local_addr, dst);
#endif /* USE_FLOATING_CLIENT_PORT */
      if (s < 0)
        {
          return -1;
        }

      dc = _connection_create(d, s);
      if (!dc)
        return -1;
      dc->remote_addr = *dst;
      dc->state = STATE_CONNECT;

      SSL *ssl = SSL_new(d->ssl_client_ctx);
      if (!ssl)
        return -1;
      SSL_set_ex_data(ssl, 0, d);
#ifdef DTLS_OPENSSL
      BIO *bio = BIO_new_dgram(s, 0);
      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, (void *)dst);
      SSL_set_bio(ssl, bio, bio);
#endif /* DTLS_OPENSSL */

#ifdef DTLS_CYASSL
      CyaSSL_set_fd(ssl, s);
      CyaSSL_set_using_nonblock(ssl, 1);
      int rv =
      CyaSSL_dtls_set_peer(ssl, &dc->remote_addr, sizeof(dc->remote_addr));
      if (rv != SSL_SUCCESS)
        {
          L_ERR("CyaSSL_dtls_set_peer");
          return -1;
        }
#endif /* DTLS_CYASSL */

      dc->ssl = ssl;

      _connection_poll(dc);
    }
  dtls_queued_buffer qb = calloc(1, sizeof(*qb) + len);
  if (!qb)
    {
      L_ERR("calloc qbuf");
      return -1;
    }
  memcpy(qb->buf, buf, len);
  qb->len = len;
  list_add(&qb->in_queued_buffers, &dc->queued_buffers);
  return len;
}

#define R1(where, x) do                                 \
{                                                       \
  int rv = (x);                                         \
  if (rv != 1)                                          \
    {                                                   \
      L_ERR("error in %s:%d/%d", where, rv, errno);     \
      _drain_errors();                                  \
      goto fail;                                        \
    }                                                   \
} while(0)

static int _verify_cert(int ok __unused, X509_STORE_CTX *ctx __unused)
{
  /* TBD */
  return 1;
}

bool dtls_set_local_cert(dtls d, const char *certfile, const char *pkfile)
{
  R1("server cert",
     SSL_CTX_use_certificate_chain_file(d->ssl_server_ctx, certfile));
  R1("server private key",
     SSL_CTX_use_PrivateKey_file(d->ssl_server_ctx, pkfile, SSL_FILETYPE_PEM));
  SSL_CTX_set_verify(d->ssl_server_ctx, SSL_VERIFY_PEER
#ifdef DTLS_OPENSSL
                     |SSL_VERIFY_FAIL_IF_NO_PEER_CERT
#endif /* DTLS_OPENSSL */
                     , _verify_cert);

#ifndef USE_ONE_CONTEXT
  R1("client cert",
     SSL_CTX_use_certificate_chain_file(d->ssl_client_ctx, certfile));
  R1("client private key",
     SSL_CTX_use_PrivateKey_file(d->ssl_client_ctx, pkfile, SSL_FILETYPE_PEM));
  SSL_CTX_set_verify(d->ssl_client_ctx, SSL_VERIFY_PEER
#ifdef DTLS_OPENSSL
                     |SSL_VERIFY_PEER_FAIL_IF_NO_PEER_CERT
#endif /* DTLS_OPENSSL */
                     , _verify_cert);
#endif /* !USE_ONE_CONTEXT */
  return true;
 fail:
  return false;
}

unsigned int _server_psk(SSL *ssl, const char *identity __unused,
                         unsigned char *psk, unsigned int max_psk_len)
{
  dtls d = SSL_get_ex_data(ssl, 0);

  if (!d)
    {
      L_ERR("NULL ex_data 0?!?");
      return 0;
    }
  if (!d->psk)
    return 0;
  if (d->psk_len > max_psk_len)
    return 0;
  max_psk_len = d->psk_len;
  memcpy(psk, d->psk, max_psk_len);
  return max_psk_len;
}

unsigned int _client_psk(SSL *ssl,
                         const char *hint __unused,
                         char *identity,
                         unsigned int max_identity_len __unused,
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
#ifdef DTLS_CYASSL
  /* CyaSSL does not seem to realize that non-PSK ciphersuites are bad
   * idea if you do not have certs.. */
  if (CyaSSL_CTX_set_cipher_list(d->ssl_client_ctx,
                                 "PSK-AES128-CBC-SHA256") != SSL_SUCCESS)
    {
      L_ERR("unable to set cipher list");
      return false;
    }
  if (CyaSSL_CTX_set_cipher_list(d->ssl_server_ctx,
                                 "PSK-AES128-CBC-SHA256") != SSL_SUCCESS)
    {
      L_ERR("unable to set cipher list");
      return false;
    }
#endif /* DTLS_CYASSL */

  return true;
}
