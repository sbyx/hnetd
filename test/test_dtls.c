/*
 * $Id: test_dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:31 2014 mstenber
 * Last modified: Tue May 26 17:08:09 2015 mstenber
 * Edit time:     137 min
 *
 */

/*
 * TBD: Write some tests that ensure the handling of limits is sane.
 *
 * TBD: Write test which makes sure that e.g. 3rd connection attempt
 * can still change the verdict for a cert.
 */

#include "dtls.c"
#include "udp46.c"
#include "sput.h"
#include "smock.h"

#include <net/if.h>
#include <libubox/uloop.h>
#include <arpa/inet.h>
#include <ctype.h>

/* in ms */
#define SINGLE_TEST_ERROR_TIMEOUT 2000

int log_level = LOG_DEBUG;
void (*hnetd_log)(int priority, const char *format, ...) = syslog;

dtls d1, d2;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

void _timeout(struct uloop_timeout *t)
{
  L_INFO("test failed - timeout");
  sput_fail_unless(false, "test timed out");
  uloop_end();
}

void _no_connections_timeout(struct uloop_timeout *t)
{
  uloop_timeout_set(t, 100);
  L_DEBUG("waiting for closure: %d/%d <> %d/%d",
          d1->num_data_connections,
          d1->num_non_data_connections,
          d2->num_data_connections,
          d2->num_non_data_connections);
  if (d1->num_data_connections ||
      d1->num_non_data_connections ||
      d2->num_data_connections ||
      d2->num_non_data_connections)
    return;
  uloop_end();
}

int pending_readable;

void _readable_cb(dtls d, void *context)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  struct sockaddr_in6 *src, *dst;

  r = dtls_recv(d, &src, &dst, buf, len);
  L_DEBUG("_readable_cb - %d", r);
  smock_pull_int_is("dtls_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("dtls_recvfrom_buf");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      struct in6_addr *a = smock_pull("dtls_recv_src_in6");
      sput_fail_unless(memcmp(a, &src->sin6_addr, sizeof(*a))==0, "src mismatch");
    }
  if (!--pending_readable)
    uloop_end();
  sput_fail_unless(pending_readable >= 0, "too many reads");
}

int pending_unknown;
int dumped = 0;

bool _cert_same(const char *pem1, const char *pem2)
{
  const char *c = pem1, *d = pem2;

  if (!pem1)
    return false;
  if (!pem2)
    return false;
  /* Just skip newlines/whitespace */
  while (*c && *d)
    {
      while (*c && isspace(*c)) c++;
      while (*d && isspace(*d)) d++;
      if (!*c)
        break;
      if (*c != *d)
        break;
      c++;
      d++;
    }
  return *c == 0 && *d == 0;
}

bool _unknown_cb(dtls d, dtls_cert cert, void *context)
{
  const char *s = smock_pull("dtls_unknown_pem");
  char pem[2048];
  char filename[128];
  FILE *f;

  dtls_cert_to_pem_buf(cert, pem, sizeof(pem));
  sput_fail_unless(*pem, "pem encoding error");
  sprintf(filename, "/tmp/unknown%d.pem", dumped++);
  f = fopen(filename, "w");
  fwrite(pem, strlen(pem), 1, f);
  fclose(f);
  L_DEBUG("_unknown_cb: %s", pem);
  sput_fail_unless(_cert_same(s, pem), "cert mismatch");
  if (!--pending_unknown)
    uloop_end();
  sput_fail_unless(pending_unknown >= 0, "too many unknown");
  /* Override that we trust this -> no error messages should show up. */
  return true;
}

static void _test_basic_i(int i)
{
  int pbase = 49000 + i * 2;
  d1 = dtls_create(pbase);
  dtls_set_readable_callback(d1, _readable_cb, NULL);
  d2 = dtls_create(pbase+1);
  dtls_set_readable_callback(d2, _readable_cb, NULL);
  int rv;
  char *msg = "foo";
  struct uloop_timeout t = { .cb = _timeout };
  bool rb;
  struct sockaddr_in6 src = {.sin6_family = AF_INET6 };
  struct sockaddr_in6 dst = {.sin6_family = AF_INET6 };
#ifdef __APPLE__
  src.sin6_len = sizeof(src);
  dst.sin6_len = sizeof(dst);
#endif /* __APPLE__ */
  if (i & 1)
    {
      rb = dtls_set_local_cert(d1, "test/cert1.pem", "test/key1.pem");
      sput_fail_unless(rb, "dtls_set_local_cert 1");
      rb = dtls_set_verify_locations(d1, "test/cert2.pem", NULL);
      sput_fail_unless(rb, "dtls_set_verify_locations 1");

      rb = dtls_set_local_cert(d2, "test/cert2.pem", "test/key2.pem");
      sput_fail_unless(rb, "dtls_set_local_cert 2");
      rb = dtls_set_verify_locations(d2, "test/cert1.pem", NULL);
      sput_fail_unless(rb, "dtls_set_verify_locations 2");
    }
  else
    {
      rb = dtls_set_psk(d1, "foo", 3);
      sput_fail_unless(rb, "dtls_set_psk");

      rb = dtls_set_psk(d2, "foo", 3);
      sput_fail_unless(rb, "dtls_set_psk");
    }

  /* Start the instances once they have been configured */
  dtls_start(d1);
  dtls_start(d2);

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &src.sin6_addr);
  (void)inet_pton(AF_INET6, "::1", &dst.sin6_addr);
  src.sin6_port = htons(pbase);
  dst.sin6_port = htons(pbase+1);
  smock_push_int("dtls_recvfrom", 3);
  smock_push("dtls_recvfrom_src_in6", &src.sin6_addr);
  smock_push("dtls_recvfrom_buf", msg);
  rv = dtls_send(d1, NULL, &dst, msg, strlen(msg));
  L_DEBUG("sendto => %d", rv);
  sput_fail_unless(rv == 3, "sendto failed?");
  pending_readable = 1;

  uloop_timeout_set(&t, SINGLE_TEST_ERROR_TIMEOUT);
  uloop_run();
  sput_fail_unless(!pending_readable, "readable left");

  /* Do shutdown on one side, and expect other to behave accordingly */
  if (!(i & 2))
    {
      dtls_connection dc = list_first_entry(&d2->connections,
                                            dtls_connection_s, in_connections);
      sput_fail_unless(dc, "no connection at dst");
      L_DEBUG("shutdown (server-side)");
      _connection_shutdown(dc);
    }
  else
    {
      dtls_connection dc = _connection_find(d1, -1, &dst);
      sput_fail_unless(dc, "no connection at src");
      L_DEBUG("shutdown (client-side)");
      _connection_shutdown(dc);
    }
  struct uloop_timeout t2 = { .cb = _no_connections_timeout };
  uloop_timeout_set(&t2, 5);
  uloop_run();

  L_DEBUG("killing dtls instances");

  dtls_destroy(d1);
  dtls_destroy(d2);
  uloop_timeout_cancel(&t);
  uloop_timeout_cancel(&t2);
}

static void _test_unknown_i(int i)
{
  char cert1[2048];
  FILE *f;
  char cert2[2048];
  int len;

  f = fopen("test/cert1.pem", "r");
  len = fread(cert1, 1, sizeof(cert1), f);
  cert1[len] = 0;
  fclose(f);
  f = fopen("test/cert2.pem", "r");
  len = fread(cert2, 1, sizeof(cert2), f);
  cert2[len] = 0;
  fclose(f);

  int pbase = 49100 + i * 2;
  d1 = dtls_create(pbase);
  dtls_set_unknown_cert_callback(d1, _unknown_cb, NULL);
  d2 = dtls_create(pbase+1);
  dtls_set_unknown_cert_callback(d2, _unknown_cb, NULL);
  int rv;
  char *msg = "foo";
  struct uloop_timeout t = { .cb = _timeout };
  bool rb;
  struct sockaddr_in6 src = {.sin6_family = AF_INET6 };
  struct sockaddr_in6 dst = {.sin6_family = AF_INET6 };
#ifdef __APPLE__
  src.sin6_len = sizeof(src);
  dst.sin6_len = sizeof(dst);
#endif /* __APPLE__ */
  rb = dtls_set_local_cert(d1, "test/cert1.pem", "test/key1.pem");
  sput_fail_unless(rb, "dtls_set_local_cert 1");

  if (i == 1)
    {
      rb = dtls_set_verify_locations(d1, "test/cert2.pem", NULL);
      sput_fail_unless(rb, "dtls_set_verify_locations 1");
    }
  else
    smock_push("dtls_unknown_pem", cert2);

  rb = dtls_set_local_cert(d2, "test/cert2.pem", "test/key2.pem");
  sput_fail_unless(rb, "dtls_set_local_cert 2");

  if (i == 0)
    {
      rb = dtls_set_verify_locations(d2, "test/cert1.pem", NULL);
      sput_fail_unless(rb, "dtls_set_verify_locations 2");
    }
  else
    smock_push("dtls_unknown_pem", cert1);

  /* Start the instances once they have been configured */
  dtls_start(d1);
  dtls_start(d2);

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &src.sin6_addr);
  (void)inet_pton(AF_INET6, "::1", &dst.sin6_addr);
  src.sin6_port = htons(pbase);
  dst.sin6_port = htons(pbase+1);

  rv = dtls_send(d1, NULL, &dst, msg, strlen(msg));
  L_DEBUG("sendto => %d", rv);
  sput_fail_unless(rv == 3, "sendto failed?");
  pending_unknown = 1;

  uloop_timeout_set(&t, SINGLE_TEST_ERROR_TIMEOUT);
  uloop_run();

  dtls_destroy(d1);
  dtls_destroy(d2);
  uloop_timeout_cancel(&t);

  sput_fail_unless(!pending_unknown, "no unknown left");
}

static void dtls_basic_sc_cert()
{
  _test_basic_i(0);
}

static void dtls_basic_sc_psk()
{
  _test_basic_i(1);
}

static void dtls_basic_cc_cert()
{
  _test_basic_i(2);
}

static void dtls_basic_cc_psk()
{
  _test_basic_i(3);
}


static void dtls_unknown_1()
{
  _test_unknown_i(0);
}

static void dtls_unknown_2()
{
  _test_unknown_i(1);
}


int main(int argc, char **argv)
{
  (void)uloop_init();

  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_dtls", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dtls"); /* optional */
  argc -= 1;
  argv += 1;

  sput_maybe_run_test(dtls_basic_sc_cert, do {} while(0));
  sput_maybe_run_test(dtls_basic_sc_psk, do {} while(0));
  sput_maybe_run_test(dtls_basic_cc_cert, do {} while(0));
  sput_maybe_run_test(dtls_basic_cc_psk, do {} while(0));
  sput_maybe_run_test(dtls_unknown_1, do {} while(0));
  sput_maybe_run_test(dtls_unknown_2, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
