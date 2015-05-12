/*
 * $Id: test_hncp_io.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 09:56:00 2014 mstenber
 * Last modified: Tue Dec 23 18:42:32 2014 mstenber
 * Edit time:     32 min
 *
 */

/* This module tests that the hncp_io module's (small) external
 * interface seems to work correctly, _and_ that we can use it to send
 * packets back and forth. */

#include "dncp_i.h"
#define dncp_find_link_by_name(o,n,c) NULL
#include "hncp_io.c"
#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;
void (*hnetd_log)(int priority, const char *format, ...) = syslog;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

#ifdef __APPLE__
#define LOOPBACK_NAME "lo0"
#else
#define LOOPBACK_NAME "lo"
#endif /* __APPLE__ */



void dncp_run(dncp o)
{
  smock_pull("dncp_run");
}

int pending_poll = 0;

void dncp_poll(dncp o)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  char ifname[IFNAMSIZ];
  struct sockaddr_in6 srcsa;
  struct in6_addr dst;

  r = dncp_io_recvfrom(o, buf, len, ifname, &srcsa, &dst);
  smock_pull_int_is("dncp_poll_io_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("dncp_poll_io_recvfrom_buf");
      char *ifn = smock_pull("dncp_poll_io_recvfrom_ifname");
      struct sockaddr_in6 *sa = smock_pull("dncp_poll_io_recvfrom_src");
      struct in6_addr *d = smock_pull("dncp_poll_io_recvfrom_dst");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      sput_fail_unless(strcmp(ifn, ifname) == 0, "ifname mismatch");
      sput_fail_unless(memcmp(sa, &srcsa, sizeof(srcsa))==0, "src mismatch");
      sput_fail_unless(memcmp(d, &dst, sizeof(dst))==0, "dst mismatch");
    }
  if (!--pending_poll)
    uloop_end();
}

static void dncp_io_basic_2()
{
  dncp_s h1, h2;
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
  r = dncp_io_init(&h1);
  sput_fail_unless(r, "dncp_io_init h1");
  r = dncp_io_init(&h2);
  sput_fail_unless(r, "dncp_io_init h2");

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &a);
  struct sockaddr_in6 src;
  memset(&src, 0, sizeof(src));
  src.sin6_family = AF_INET6;
  src.sin6_port = htons(h1.udp_port);
  src.sin6_addr = a;
#ifdef __APPLE__
  src.sin6_len = sizeof(src);
#endif /* __APPLE__ */
  struct sockaddr_in6 dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons(h2.udp_port);
  dst.sin6_addr = a;
#ifdef __APPLE__
  dst.sin6_len = sizeof(dst);
#endif /* __APPLE__ */
  smock_push_int("dncp_poll_io_recvfrom", 3);
  smock_push_int("dncp_poll_io_recvfrom_src", &src);
  smock_push_int("dncp_poll_io_recvfrom_dst", &a);
  smock_push_int("dncp_poll_io_recvfrom_buf", msg);
  smock_push_int("dncp_poll_io_recvfrom_ifname", ifname);
  rv = dncp_io_sendto(&h1, msg, strlen(msg), &dst);
  L_DEBUG("got %d", rv);
  sput_fail_unless(rv == 3, "sendto failed?");
  pending_poll++;

  uloop_run();

  dncp_io_uninit(&h1);
  dncp_io_uninit(&h2);
}

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_dncp_io", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("dncp_io"); /* optional */
  argc -= 1;
  argv += 1;

  sput_maybe_run_test(dncp_io_basic_2, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
