/*
 * $Id: dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:42 2014 mstenber
 * Last modified: Thu Oct 16 14:57:34 2014 mstenber
 * Edit time:     159 min
 *
 */

#include "dtls.h"
#include <unistd.h>
#include <stdlib.h>
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

/* How large random string key we use as base for cookies */
#define COOKIE_SECRET_LENGTH 10

/* 16 = size of md5 hash */
#define COOKIE_LENGTH (sizeof(time_t) + 16)

/* How long cookies are valid (in seconds) */
#define COOKIE_VALIDITY_PERIOD 10

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
    STATE_ACCEPT=1,
    STATE_CONNECT=2,
    STATE_DATA=3
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

  SSL_CTX *ssl_ctx;

  struct uloop_fd ufd;
  int listen_socket;
  BIO *listen_bio;
  SSL *listen_ssl;

  struct list_head connections;
  unsigned char cookie_secret[COOKIE_SECRET_LENGTH];

  bool readable;
} dtls_s;

static bool _ssl_initialized = false;


static int _cookie_gen_fixed_time(SSL *ssl,
                                  unsigned char *cookie,
                                  unsigned int *cookie_len,
                                  time_t t)
{
  /* CRYPTO_set_ex_data(ssl->ex_data, 0, d); */
  dtls d = CRYPTO_get_ex_data(&ssl->ex_data, 0);
  struct sockaddr_storage ss;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
  md5_ctx_t ctx;
  unsigned char result[COOKIE_LENGTH];

  /* If it is wrong AF, we do not care. */
  if (sin6->sin6_family != AF_INET6)
    return 0;

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
    return 0;

  nt = time(NULL);
  ct = *((time_t *)cookie);

  /* If our clock is really moving backwards, we might as well pretend
   * it is fake, for now. (Little loss, UDP _is_ lossy after all.)*/
  if (ct > nt)
    return 0;

  if ((nt - ct) > COOKIE_VALIDITY_PERIOD)
    return 0;
  return cookie_len == COOKIE_LENGTH
    && _cookie_gen_fixed_time(ssl, tbuf, &tbuf_len, ct)
    && memcmp(tbuf, cookie, cookie_len) == 0;
}

static void _dtls_listen(dtls d);

static void _qb_free(dtls_queued_buffer qb)
{
  list_del(&qb->in_queued_buffers);
  free(qb->buf);
  free(qb);
}

static void _connection_free(dtls_connection dc)
{
  dtls_queued_buffer qb, qb2;

  list_for_each_entry_safe(qb, qb2, &dc->queued_buffers, in_queued_buffers)
    _qb_free(qb);
  list_del(&dc->in_connections);
  SSL_free(dc->ssl);
  uloop_fd_delete(&dc->ufd);
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
                {
                  L_ERR("partial write from queue?!?");
                }
              _qb_free(qb);
            }
          else
            {
              L_DEBUG("queued data write failed");
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
      dc->d->cb(dc->d, dc->d->cb_context);
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
    L_DEBUG("SSL_{accept/connect} => error %d", err);

  /* Handle the timeout here too */
  DTLSv1_get_timeout(dc->ssl, &dc->uto.time);
  uloop_timeout_add(&dc->uto);
}

static int _socket_connect(struct sockaddr_in6 *local_addr,
                         struct sockaddr_in6 *remote_addr)
{
  int s = socket(AF_INET6, SOCK_DGRAM, 0);
  int on = 1;

  if (s < 0)
    {
      L_ERR("unable to create IPv6 socket");
      return -1;
    }
  fcntl(s, F_SETFL, O_NONBLOCK);
#ifdef SO_REUSEPORT
  setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif /* SO_REUSEPORT */
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  if (bind(s, (struct sockaddr *)local_addr, sizeof(*local_addr))<0)
    {
      L_ERR("unable to bind [client]");
      goto fail;
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
  DTLSv1_handle_timeout(dc->ssl);
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

  if ((rv = DTLSv1_listen(d->listen_ssl, &remote_addr)) <= 0)
    {
      if (rv < 0)
        {
          int err = SSL_get_error(d->listen_ssl, rv);
          if (err != SSL_ERROR_WANT_READ)
            L_DEBUG("DTLSv1_listen error:%d", err);
        }
      return;
    }
  int s = _socket_connect(&d->local_addr, &remote_addr);
  if (s < 0)
    goto fail;
  BIO_set_fd(d->listen_bio, s, 0);
  BIO_ctrl(d->listen_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr);

  dc = _connection_create(d, s);
  if (!dc)
    goto fail;
  dc->remote_addr = remote_addr;
  dc->ssl = d->listen_ssl;
  dc->state = STATE_ACCEPT;

  /* Poll the connection to mark it 'live' */
  _connection_poll(dc);

  /* Re-initialize new SSL context on listening socket. */
  _dtls_listen(d);
  return;
 fail:
  if (dc)
    free(dc);
  close(s);
}

static void _dtls_listen(dtls d)
{
  d->listen_bio = BIO_new_dgram(d->listen_socket, BIO_NOCLOSE);
  SSL *ssl = SSL_new(d->ssl_ctx);
  if (!ssl)
    {
      L_ERR("SSL_new failed");
      return;
    }
  d->listen_ssl = ssl;
  SSL_set_bio(ssl, d->listen_bio, d->listen_bio);
  SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
  _dtls_poll(d);
}

void _dtls_ufd_cb(struct uloop_fd *u, unsigned int events __unused)
{
  dtls d = container_of(u, dtls_s, ufd);

  L_DEBUG("_dtls_ufd_cb");
  _dtls_poll(d);
}

/* Create/destroy instance. */
dtls dtls_create(uint16_t port, dtls_readable_callback cb, void *cb_context)
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
  d->cb = cb;
  d->cb_context = cb_context;
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
  SSL_CTX *ctx = SSL_CTX_new(DTLSv1_method());
  if (!ctx)
    {
      L_ERR("unable to create SSL_CTX");
      goto fail;
    }
  /* XXX - load certificates + private key? */
  SSL_CTX_set_cookie_generate_cb(ctx, _cookie_gen_cb);
  SSL_CTX_set_cookie_verify_cb(ctx, _cookie_verify_cb);
  RAND_bytes(d->cookie_secret, COOKIE_SECRET_LENGTH);
  /* XXX - set up verify callback? */

  d->ssl_ctx = ctx;
  d->listen_socket = s;
  _dtls_listen(d);

  d->ufd.cb = _dtls_ufd_cb;
  d->ufd.fd = s;
  uloop_fd_add(&d->ufd, ULOOP_READ);
  L_DEBUG("dtls_create succeeded - fd %d @ port %d", s, port);
  return d;

 fail:
  if (s>0)
    close(s);
  free(d);
  return NULL;
}

void dtls_destroy(dtls d)
{
  uloop_fd_delete(&d->ufd);
  free(d);
}

/* Send/receive data. */
ssize_t dtls_recvfrom(dtls d, void *buf, size_t len,
                      char *ifname,
                      struct in6_addr *src,
                      uint16_t *src_port,
                      struct in6_addr *dst)
{
  L_DEBUG("dtls_recvfrom");
  return -1;
}

ssize_t dtls_sendto(dtls d, void *buf, size_t len,
                    const char *ifname,
                    const struct in6_addr *to,
                    uint16_t to_port)
{
  struct sockaddr_in6 dst;

  L_DEBUG("dtls_sendto");
  memset(&dst, 0, sizeof(dst));
  if (!(dst.sin6_scope_id = if_nametoindex(ifname)))
    {
      L_ERR("unable to send on %s - if_nametoindex: %s",
            ifname, strerror(errno));
      return -1;
    }
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons(to_port);
  dst.sin6_addr = *to;

  /* Try to find existing connection */
  dtls_connection idc, dc = NULL;
  list_for_each_entry(idc, &d->connections, in_connections)
    {
      if (memcmp(&dst, &idc->remote_addr, sizeof(dst)) == 0)
        {
          if (idc->state == STATE_DATA)
            {
              size_t rv = SSL_write(idc->ssl, buf, len);
              if (rv > 0)
                {
                  if (rv != len)
                    {
                      L_ERR("partial write?!?");
                      return -1;
                    }
                  L_DEBUG("had existing connection in good state, write ok");
                  return rv;
                }
            }
          L_DEBUG("had existing connection");
          dc = idc;
          break;
        }
    }

  if (!dc)
    {
      /* Create new connection object */
      L_DEBUG("creating new client connection");
      int s = _socket_connect(&d->local_addr, &dst);
      if (s < 0)
        {
          return -1;
        }

      dc = _connection_create(d, s);
      if (!dc)
        return -1;
      dc->remote_addr = dst;
      dc->state = STATE_CONNECT;

      BIO *bio = BIO_new_dgram(s, 0);
      BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &dst);

      SSL *ssl = SSL_new(d->ssl_ctx);
      SSL_set_bio(ssl, bio, bio);

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
  list_add(&qb->in_queued_buffers, &dc->queued_buffers);
  return len;
}
