/*
 * $Id: test_hncp_io.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Oct 16 09:56:00 2014 mstenber
 * Last modified: Tue Jun  2 12:03:10 2015 mstenber
 * Edit time:     64 min
 *
 */

/* This module tests that the hncp_io module's (small) external
 * interface seems to work correctly, _and_ that we can use it to send
 * packets back and forth. */

#include "dncp_i.h"

#ifdef __APPLE__
#define LOOPBACK_NAME "lo0"
#else
#define LOOPBACK_NAME "lo"
#endif /* __APPLE__ */


dncp_ep_s static_ep = { .ifname = LOOPBACK_NAME,
                        .accept_insecure_nonlocal_traffic = true };

#define dncp_ep_find_by_name(o, n) &static_ep
#include "hncp_io.c"
#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;
void (*hnetd_log)(int priority, const char *format, ...) = syslog;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

void dncp_ext_ep_ready(dncp_ep ep, bool ready)
{
  smock_pull_string_is("dncp_ready", ep->ifname);
  smock_pull_bool_is("dncp_ready_value", ready);
}

void dncp_ext_timeout(dncp o)
{
  smock_pull("dncp_run");
}

int pending_packets = 0;

void dncp_ext_readable(dncp o)
{
  char buf[1024];
  size_t len = sizeof(buf);
  int r;
  struct sockaddr_in6 *src, *dst;
  dncp_ep ep;

  r = o->ext->cb.recv(o->ext, &ep, &src, &dst, buf, len);
  smock_pull_int_is("dncp_poll_io_recvfrom", r);
  if (r >= 0)
    {
      void *b = smock_pull("dncp_poll_io_recvfrom_buf");
      char *ifn = smock_pull("dncp_poll_io_recvfrom_ifname");
      struct sockaddr_in6 *esrc = smock_pull("dncp_poll_io_recvfrom_src");
      struct sockaddr_in6 *edst = smock_pull("dncp_poll_io_recvfrom_dst");

      sput_fail_unless(memcmp(b, buf, r)==0, "buf mismatch");
      sput_fail_unless(strcmp(ifn, ep->ifname) == 0, "ifname mismatch");
      sput_fail_unless(memcmp(src, esrc, sizeof(*src))==0, "src mismatch");
      sput_fail_unless(memcmp(&dst->sin6_addr,
                              &edst->sin6_addr, sizeof(dst->sin6_addr))==0,
                       "dst mismatch");
      if (!--pending_packets)
        uloop_end();
    }
}

static void dncp_io_basic_2()
{
  hncp_s h1, h2;
  dncp_s d1, d2;
  bool r;
  struct in6_addr a;
  char *msg = "foo";
  char *ifname = LOOPBACK_NAME;

  (void)uloop_init();
  memset(&h1, 0, sizeof(h1));
  memset(&h2, 0, sizeof(h2));
  memset(&d1, 0, sizeof(d1));
  memset(&d2, 0, sizeof(d2));
  h1.udp_port = 62000;
  h2.udp_port = 62001;
  h1.dncp = &d1;
  h2.dncp = &d2;
  d1.ext = &h1.ext;
  d2.ext = &h2.ext;
  r = hncp_io_init(&h1);
  sput_fail_unless(r, "dncp_io_init h1");
  r = hncp_io_init(&h2);
  sput_fail_unless(r, "dncp_io_init h2");

  /* Send a packet to ourselves */
  (void)inet_pton(AF_INET6, "::1", &a);
  struct sockaddr_in6 src = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(h1.udp_port),
    .sin6_addr = a
#ifdef __APPLE__
    , .sin6_len = sizeof(struct sockaddr_in6)
#endif /* __APPLE__ */
  };
  struct sockaddr_in6 dst = {
    .sin6_family = AF_INET6,
    .sin6_port = htons(h2.udp_port),
    .sin6_addr = a
#ifdef __APPLE__
    , .sin6_len = sizeof(struct sockaddr_in6)
#endif /* __APPLE__ */
  };
  smock_push_int("dncp_poll_io_recvfrom", 3);
  smock_push_int("dncp_poll_io_recvfrom_src", &src);
  smock_push_int("dncp_poll_io_recvfrom_dst", &dst);
  smock_push_int("dncp_poll_io_recvfrom_buf", msg);
  smock_push_int("dncp_poll_io_recvfrom_ifname", ifname);
  h1.ext.cb.send(&h1.ext, dncp_ep_find_by_name(h1.dncp, "lo"),
                 NULL, &dst, msg, strlen(msg));
  pending_packets++;

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

  sput_maybe_run_test(dncp_io_basic_2, do {} while(0));
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
