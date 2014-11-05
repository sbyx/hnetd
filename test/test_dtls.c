/*
 * $Id: test_dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:31 2014 mstenber
 * Last modified: Wed Nov  5 18:49:07 2014 mstenber
 * Edit time:     72 min
 *
 */

#include "dtls.c"
#include "sput.h"
#include "smock.h"

#include <net/if.h>
#include <libubox/uloop.h>
#include <arpa/inet.h>

int log_level = LOG_DEBUG;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

void _timeout(struct uloop_timeout *t)
{
  L_INFO("test failed - timeout");
  sput_fail_unless(false, "test timed out");
  uloop_end();
}

int pending_readable;

void _readable_cb(dtls d, void *context)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  struct sockaddr_in6 src;

  r = dtls_recvfrom(d, buf, len, &src);
  L_DEBUG("_readable_cb - %d", r);
  smock_pull_int_is("dtls_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("dtls_recvfrom_buf");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      struct in6_addr *a = smock_pull("dtls_recvfrom_src_in6");
      sput_fail_unless(memcmp(a, &src.sin6_addr, sizeof(*a))==0, "src mismatch");
    }
  if (!--pending_readable)
    uloop_end();
  sput_fail_unless(pending_readable >= 0, "too many reads");
}

int pending_unknown;

void _unknown_cb(dtls d, const char *pem, void *context)
{
  const char *s = smock_pull("dtls_unknown_pem");

  L_DEBUG("_unknown_cb: %s", pem);
  sput_fail_unless(strcmp(pem, s) == 0, "string mismatch");
  if (!--pending_unknown)
    uloop_end();
  sput_fail_unless(pending_unknown >= 0, "too many unknown");
}

static void dtls_basic_2()
{
  int i;

  for (i = 0 ; i < 2 ; i++)
    {
      int pbase = 49000 + i * 2;
      dtls d1 = dtls_create(pbase);
      dtls_set_readable_callback(d1, _readable_cb, NULL);
      dtls d2 = dtls_create(pbase+1);
      dtls_set_readable_callback(d2, _readable_cb, NULL);
      int rv;
      char *msg = "foo";
      struct uloop_timeout t = { .cb = _timeout };
      bool rb;
      struct sockaddr_in6 src = {.sin6_family = AF_INET6 };
      struct sockaddr_in6 dst = {.sin6_family = AF_INET6 };
      if (i == 0)
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
      rv = dtls_sendto(d1, msg, strlen(msg), &dst);
      L_DEBUG("sendto => %d", rv);
      sput_fail_unless(rv == 3, "sendto failed?");
      pending_readable = 1;

      uloop_timeout_set(&t, 5000);
      uloop_run();
      sput_fail_unless(!pending_readable, "readable left");

      L_DEBUG("killing dtls instances");

      dtls_destroy(d1);
      dtls_destroy(d2);
      uloop_timeout_cancel(&t);

    }
}

static void dtls_unknown()
{
  int i;

  for (i = 0 ; i < 2 ; i++)
    {
      int pbase = 49100 + i * 2;
      dtls d1 = dtls_create(pbase);
      dtls_set_unknown_cert_callback(d1, _unknown_cb, NULL);
      dtls d2 = dtls_create(pbase+1);
      dtls_set_unknown_cert_callback(d2, _unknown_cb, NULL);
      int rv;
      char *msg = "foo";
      struct uloop_timeout t = { .cb = _timeout };
      bool rb;
      struct sockaddr_in6 src = {.sin6_family = AF_INET6 };
      struct sockaddr_in6 dst = {.sin6_family = AF_INET6 };
      rb = dtls_set_local_cert(d1, "test/cert1.pem", "test/key1.pem");
      sput_fail_unless(rb, "dtls_set_local_cert 1");

      if (i == 1)
        {
          rb = dtls_set_verify_locations(d1, "test/cert2.pem", NULL);
          sput_fail_unless(rb, "dtls_set_verify_locations 1");
        }

      rb = dtls_set_local_cert(d2, "test/cert2.pem", "test/key2.pem");
      sput_fail_unless(rb, "dtls_set_local_cert 2");

      if (i == 0)
        {
          rb = dtls_set_verify_locations(d2, "test/cert1.pem", NULL);
          sput_fail_unless(rb, "dtls_set_verify_locations 2");
        }

      /* Start the instances once they have been configured */
      dtls_start(d1);
      dtls_start(d2);

      /* Send a packet to ourselves */
      (void)inet_pton(AF_INET6, "::1", &src.sin6_addr);
      (void)inet_pton(AF_INET6, "::1", &dst.sin6_addr);
      src.sin6_port = htons(pbase);
      dst.sin6_port = htons(pbase+1);

      rv = dtls_sendto(d1, msg, strlen(msg), &dst);
      pending_unknown = 1;

      uloop_timeout_set(&t, 5000);
      uloop_run();

      dtls_destroy(d1);
      dtls_destroy(d2);
      uloop_timeout_cancel(&t);

      sput_fail_unless(!pending_unknown, "no unknown left");
    }
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

  sput_maybe_run_test(dtls_basic_2, do {} while(0));
  sput_maybe_run_test(dtls_unknown, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
