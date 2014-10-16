/*
 * $Id: test_hncp_io.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 09:56:00 2014 mstenber
 * Last modified: Thu Oct 16 10:37:15 2014 mstenber
 * Edit time:     21 min
 *
 */

/* This module tests that the hncp_io module's (small) external
 * interface seems to work correctly, _and_ that we can use it to send
 * packets back and forth. */

#include "hncp_io.c"
#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#ifdef __APPLE__
#define LOOPBACK_NAME "lo0"
#else
#define LOOPBACK_NAME "lo"
#endif /* __APPLE__ */



void hncp_run(hncp o)
{
  smock_pull("hncp_run");
}

int pending_poll = 0;

void hncp_poll(hncp o)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  char ifname[IFNAMSIZ];
  struct in6_addr src, dst;
  uint16_t src_port;

  r = hncp_io_recvfrom(o, buf, len, ifname, &src, &src_port, &dst);
  smock_pull_int_is("hncp_poll_io_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("hncp_poll_io_recvfrom_buf");
      char *ifn = smock_pull("hncp_poll_io_recvfrom_ifname");
      struct in6_addr *s = smock_pull("hncp_poll_io_recvfrom_src");
      struct in6_addr *d = smock_pull("hncp_poll_io_recvfrom_dst");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      sput_fail_unless(strcmp(ifn, ifname) == 0, "ifname mismatch");
      sput_fail_unless(memcmp(s, &src, sizeof(src))==0, "src mismatch");
      smock_pull_int_is("hncp_poll_io_recvfrom_src_port", src_port);
      sput_fail_unless(memcmp(d, &dst, sizeof(dst))==0, "dst mismatch");
    }
  if (!--pending_poll)
    uloop_end();
}

static void hncp_io_basic_2()
{
  hncp_s h1, h2;
  bool r;
  int rv;
  struct in6_addr a;
  char *msg = "foo";
  char *ifname = LOOPBACK_NAME;

  (void)uloop_init();
  memset(&h1, 0, sizeof(h1));
  memset(&h2, 0, sizeof(h2));
  h1.udp_port = 62000;
  h2.udp_port = 62001;
  r = hncp_io_init(&h1);
  sput_fail_unless(r, "hncp_io_init h1");
  r = hncp_io_init(&h2);
  sput_fail_unless(r, "hncp_io_init h2");

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &a);
  smock_push_int("hncp_poll_io_recvfrom", 3);
  smock_push_int("hncp_poll_io_recvfrom_src", &a);
  smock_push_int("hncp_poll_io_recvfrom_dst", &a);
  smock_push_int("hncp_poll_io_recvfrom_buf", msg);
  smock_push_int("hncp_poll_io_recvfrom_ifname", ifname);
  smock_push_int("hncp_poll_io_recvfrom_src_port", h1.udp_port);
  rv = hncp_io_sendto(&h1, msg, strlen(msg), ifname, &a, h2.udp_port);
  L_DEBUG("got %d", rv);
  sput_fail_unless(rv == 3, "sendto failed?");
  pending_poll++;

  uloop_run();

  hncp_io_uninit(&h1);
  hncp_io_uninit(&h2);
}

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp_io", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hncp_io"); /* optional */
  argc -= 1;
  argv += 1;

  sput_maybe_run_test(hncp_io_basic_2, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
