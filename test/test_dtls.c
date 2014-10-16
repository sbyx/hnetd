/*
 * $Id: test_dtls.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 10:57:31 2014 mstenber
 * Last modified: Thu Oct 16 14:34:30 2014 mstenber
 * Edit time:     12 min
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

int pending_readable = 0;

#ifdef __APPLE__
#define LOOPBACK_NAME "lo0"
#else
#define LOOPBACK_NAME "lo"
#endif /* __APPLE__ */


void test_timeout(struct uloop_timeout *t)
{
  L_INFO("test failed - timeout");
  sput_fail_unless(false, "test timed out");
  uloop_end();
}


void dtls_readable(dtls d, void *context)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  char ifname[IFNAMSIZ];
  struct in6_addr src, dst;
  uint16_t src_port;
  r = dtls_recvfrom(d, buf, len, ifname, &src, &src_port, &dst);
  smock_pull_int_is("dtls_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("dtls_recvfrom_buf");
      char *ifn = smock_pull("dtls_recvfrom_ifname");
      struct in6_addr *s = smock_pull("dtls_recvfrom_src");
      struct in6_addr *d = smock_pull("dtls_recvfrom_dst");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      sput_fail_unless(strcmp(ifn, ifname) == 0, "ifname mismatch");
      sput_fail_unless(memcmp(s, &src, sizeof(src))==0, "src mismatch");
      smock_pull_int_is("dtls_recvfrom_src_port", src_port);
      sput_fail_unless(memcmp(d, &dst, sizeof(dst))==0, "dst mismatch");
    }
  if (!--pending_readable)
    uloop_end();
}

static void dtls_basic_2()
{
  (void)uloop_init();
  dtls d1 = dtls_create(49000, dtls_readable, NULL);
  dtls d2 = dtls_create(49001, dtls_readable, NULL);
  int rv;
  struct in6_addr a;
  char *msg = "foo";
  char *ifname = LOOPBACK_NAME;
  struct uloop_timeout t = { .cb = test_timeout };

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &a);
  smock_push_int("dtls_recvfrom", 3);
  smock_push_int("dtls_recvfrom_src", &a);
  smock_push_int("dtls_recvfrom_dst", &a);
  smock_push_int("dtls_recvfrom_buf", msg);
  smock_push_int("dtls_recvfrom_ifname", ifname);
  smock_push_int("dtls_recvfrom_src_port", 49000);
  rv = dtls_sendto(d1, msg, strlen(msg), ifname, &a, 49001);
  L_DEBUG("got %d", rv);
  sput_fail_unless(rv == 3, "sendto failed?");
  pending_readable++;

  uloop_timeout_set(&t, 5000);
  uloop_run();

  dtls_destroy(d1);
  dtls_destroy(d2);
}

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_dtls", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dtls"); /* optional */
  argc -= 1;
  argv += 1;

  sput_maybe_run_test(dtls_basic_2, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
  return 0;
}
