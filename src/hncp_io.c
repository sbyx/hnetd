/*
 * $Id: dncp_io.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Mon Nov 25 14:00:10 2013 mstenber
 * Last modified: Wed Apr 29 16:38:31 2015 mstenber
 * Edit time:     297 min
 *
 */

/* This module implements I/O needs of hncp. Notably, it has both
 * functionality that deals with sockets, and bit more abstract ones
 * that just deal with buffers for input and output (thereby
 * facilitating unit testing without using real sockets). */

#include "hncp_i.h"
#undef __unused
/* In linux, fcntl.h includes something with __unused. Argh. */
#include <fcntl.h>
#define __unused __attribute__((unused))
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libubox/usock.h>
#include <ifaddrs.h>

#ifdef __linux__
#define AF_LINK AF_PACKET
#include <linux/if_packet.h>
#endif /* __linux__ */

#include "dncp_io.h"

int
dncp_io_get_hwaddrs(unsigned char *buf, int buf_left)
{
  struct ifaddrs *ia, *p;
  int r = getifaddrs(&ia);
  void *a1 = buf, *a2 = buf + ETHER_ADDR_LEN;
  int addrs = 0;
  unsigned char zeroed_addr[] = {0, 0, 0, 0, 0, 0};

  if (buf_left < ETHER_ADDR_LEN * 2)
    return 0;
  memset(buf, 0, ETHER_ADDR_LEN * 2);
  if (r)
    return 0;
  for (p = ia ; p ; p = p->ifa_next)
    if (p->ifa_addr && p->ifa_addr->sa_family == AF_LINK)
      {
        void *a;
#ifdef __linux__
        struct sockaddr_ll *sll = (struct sockaddr_ll *) p->ifa_addr;
        a = sll->sll_addr;
#else
        a = &p->ifa_addr->sa_data[0];
#endif /* __linux__ */
        if (memcmp(a, zeroed_addr, sizeof(zeroed_addr)) == 0)
          continue;
        if (!addrs || memcmp(a1, a, ETHER_ADDR_LEN) < 0)
          memcpy(a1, a, ETHER_ADDR_LEN);
        if (!addrs || memcmp(a2, a, ETHER_ADDR_LEN) > 0)
          memcpy(a2, a, ETHER_ADDR_LEN);
        addrs++;
      }
  L_INFO("dncp_io_get_hwaddrs => %s", HEX_REPR(buf, ETHER_ADDR_LEN * 2));
  freeifaddrs(ia);
  if (!addrs)
    {
      L_ERR("dncp_io_get_hwaddrs failed - no AF_LINK addresses");
      return 0;
    }
  return ETHER_ADDR_LEN * 2;
}

static void _timeout(struct uloop_timeout *t)
{
  dncp o = container_of(t, dncp_s, timeout);
  dncp_run(o);
}

static void _fd_callback(struct uloop_fd *u, unsigned int events __unused)
{
  dncp o = container_of(u, dncp_s, ufd[SOCKET_IPV6]);
  dncp_poll(o);
}

static void _fd4_callback(struct uloop_fd *u, unsigned int events __unused)
{
  dncp o = container_of(u, dncp_s, ufd[SOCKET_IPV4]);
  dncp_poll(o);
}

bool dncp_io_init(dncp o)
{
  if (!o->udp_port)
    o->udp_port = HNCP_PORT;

  o->timeout.cb = _timeout;
  return !dncp_io_sockets(o->ufd, o->udp_port, _fd_callback, _fd4_callback);
}

void dncp_io_uninit(dncp o)
{
  dncp_io_close(o->ufd);

  /* clear the timer from uloop. */
  uloop_timeout_cancel(&o->timeout);
}

bool dncp_io_set_ifname_enabled(dncp o,
                                const char *ifname,
                                bool enabled)
{
  struct ipv6_mreq val;

  val.ipv6mr_multiaddr = o->profile_data.multicast_address;
  L_DEBUG("dncp_io_set_ifname_enabled %s %s",
          ifname, enabled ? "enabled" : "disabled");
  uint32_t ifindex = 0;
  dncp_link l = dncp_find_link_by_name(o, ifname, false);
  if (!(l && (ifindex = l->ifindex)))
    if (!(ifindex = if_nametoindex(ifname)))
      {
        L_DEBUG("unable to enable on %s - if_nametoindex: %s",
                ifname, strerror(errno));
        goto fail;
      }
  val.ipv6mr_interface = ifindex;
  if (setsockopt(o->ufd[SOCKET_IPV6].fd,
                 IPPROTO_IPV6,
                 enabled ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP,
                 (char *) &val, sizeof(val)) < 0)
    {
      L_ERR("unable to enable on %s - setsockopt:%s", ifname, strerror(errno));
      goto fail;
    }
  /* Yay. It succeeded(?). */
  return true;

 fail:
  return false;
}

void dncp_io_schedule(dncp o, int msecs)
{
  //1ms timeout was weird in VirtualBox env (causing less than 1ms to).
  uloop_timeout_set(&o->timeout, msecs?(msecs+1):0);
}

ssize_t dncp_io_recvfrom(dncp o, void *buf, size_t len,
                         char *ifname,
                         struct sockaddr_in6 *src,
                         struct in6_addr *dst)
{
  ssize_t l;

  while (1)
    {
#ifdef DTLS
      if (o->profile_data.d)
        {
          l = dtls_recvfrom(o->profile_data.d, buf, len, src);
          if (l > 0)
            {
              if (!IN6_IS_ADDR_LINKLOCAL(&src->sin6_addr))
                continue;
              /* In case of DTLS, we have just to trust that it has sane
               * scope id as we use that for interface determination. */
              if (!src->sin6_scope_id)
                {
                  L_DEBUG("linklocal w/o scope id..?");
                  continue;
                }
              if (!if_indextoname(src->sin6_scope_id, ifname))
                {
                  L_ERR("unable to receive (dtls) - if_indextoname:%s",
                        strerror(errno));
                  continue;
                }
              /* We do not _know_ destination address. However,
               * the code does not really care, so we fake something
               * here that looks like unicast linklocal address. */
              struct in6_addr dummy = { .s6_addr = { 0xfe,0x80 }};
              *dst = dummy;
              break;
            }
        }
#endif /* DTLS */
      l = dncp_io_recvmsg(o->ufd, buf, len, ifname, src, dst);
#ifdef DTLS
      if (o->profile_data.d && !IN6_IS_ADDR_MULTICAST(dst))
        {
          L_ERR("plaintext unicast received when in dtls mode - skip");
          continue;
        }
#endif /* DTLS */
      break;
    }

  return l;
}

ssize_t dncp_io_sendto(dncp o, void *buf, size_t len,
                       const struct sockaddr_in6 *dst,
					   const struct in6_pktinfo *src)
{
  ssize_t r;

#ifdef DTLS
  if (o->profile_data.d && !IN6_IS_ADDR_MULTICAST(&dst->sin6_addr))
    {
      /* Change destination port to DTLS server port too if it is the
       * default port. Otherwise answer on the different port (which
       * is presumably already DTLS protected due to protection in
       * input path).*/
      struct sockaddr_in6 rdst = *dst;
      if (rdst.sin6_port == htons(HNCP_PORT))
        rdst.sin6_port = htons(HNCP_DTLS_SERVER_PORT);
      r = dtls_sendto(o->profile_data.d, buf, len, &rdst, src);
    }
  else
#endif /* DTLS */
  {
    r = dncp_io_sendmsg(o->ufd, buf, len, dst, src);
  }

  return r;
}

hnetd_time_t dncp_io_time(dncp o __unused)
{
  return hnetd_time();
}

#ifdef DTLS

void _dtls_readable_callback(dtls d __unused, void *context)
{
  dncp o = context;

  dncp_poll(o);
}


void hncp_set_dtls(dncp o, dtls d)
{
  o->profile_data.d = d;
  dtls_set_readable_callback(d, _dtls_readable_callback, o);
}

#endif /* DTLS */

pid_t hncp_run(char *argv[])
{
  pid_t pid = fork();

  if (pid == 0)
    {
      execv(argv[0], argv);
      _exit(128);
    }
  L_DEBUG("hncp_run %s", argv[0]);
  for (int i = 1 ; argv[i] ; i++)
    L_DEBUG(" %s", argv[i]);
  return pid;
}
