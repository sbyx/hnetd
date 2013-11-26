/*
 * $Id: hcp_io.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Mon Nov 25 14:00:10 2013 mstenber
 * Last modified: Tue Nov 26 12:07:56 2013 mstenber
 * Edit time:     106 min
 *
 */

/* This module implements I/O needs of hcp. Notably, it has both
 * functionality that deals with sockets, and bit more abstract ones
 * that just deal with buffers for input and output (thereby
 * facilitating unit testing without using real sockets). */

#include <fcntl.h>
#include "hcp_i.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <libubox/usock.h>

/* 'found' from odhcp6c */
int
hcp_io_get_hwaddr(const char *ifname, unsigned char *buf, int buf_left)
{
  struct ifreq ifr;
  int sock;
  int tocopy = buf_left < ETHER_ADDR_LEN ? buf_left : ETHER_ADDR_LEN;

  sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock<0)
    return 0;
  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if (ioctl(sock, SIOCGIFINDEX, &ifr))
    return 0;
  if (ioctl(sock, SIOCGIFHWADDR, &ifr))
    return 0;
  memcpy(buf, ifr.ifr_hwaddr.sa_data, tocopy);
  close(sock);
  return tocopy;
}

static void _timeout(struct uloop_timeout *t)
{
  hcp o = container_of(t, hcp_s, timeout);
  hcp_run(o);
}

bool hcp_io_init(hcp o)
{
  int s;
  int on = 1;
#if 0
  /* Could also use usock here; however, it uses getaddrinfo, which
   * doesn't seem to work when e.g. default routes aren't currently
   * set up. Too bad. */
  char buf[6];

  sprintf(buf, "%d", HCP_PORT);
  s = usock(USOCK_IPV6ONLY|USOCK_UDP|USOCK_SERVER|USOCK_NONBLOCK, NULL, buf);
  if (s < 0)
    return false;
#else
  struct sockaddr_in6 addr;

  s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s<0)
    return false;
  fcntl(s, F_SETFL, O_NONBLOCK);
  memset(&addr, 0, sizeof(addr));
  addr.sin6_family = AF_INET6;
  addr.sin6_port = HCP_PORT;
  if (bind(s, &addr, sizeof(addr))<0)
    return false;
#endif
  if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)) < 0)
    return false;
  o->udp_socket = s;
  o->timeout.cb = _timeout;
  if (!inet_pton(AF_INET6, HCP_MCAST_GROUP, &o->multicast_address))
    return false;
  return true;
}

void hcp_io_uninit(hcp o)
{
  close(o->udp_socket);
  /* clear the timer from uloop. */
  uloop_timeout_cancel(&o->timeout);
}

bool hcp_io_set_ifname_enabled(hcp o,
                               const char *ifname,
                               bool enabled)
{
  struct ipv6_mreq val;

  val.ipv6mr_multiaddr = o->multicast_address;
  if (!(val.ipv6mr_interface = if_nametoindex(ifname)))
    goto fail;
  if (setsockopt(o->udp_socket,
                 IPPROTO_IPV6,
                 enabled ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP,
                 (char *) &val, sizeof(val)) < 0)
    goto fail;
  /* Yay. It succeeded(?). */
  return true;

 fail:
  return false;
}

void hcp_io_schedule(hcp o, int msecs)
{
  uloop_timeout_set(&o->timeout, msecs);
}

ssize_t hcp_io_recvfrom(hcp o, void *buf, size_t len,
                        char *ifname,
                        struct in6_addr *src,
                        struct in6_addr *dst)
{
  struct sockaddr_in6 srcsa;
  struct iovec iov = {buf, len};
  unsigned char cmsg_buf[256];
  struct msghdr msg = {&srcsa, sizeof(srcsa), &iov, 1,
                       cmsg_buf, sizeof(cmsg_buf), 0};
  ssize_t l;
  struct cmsghdr *h;
  struct in6_pktinfo *ipi6;

  l = recvmsg(o->udp_socket, &msg, MSG_DONTWAIT);
  if (l > 0)
    {
      *ifname = 0;
      *src = srcsa.sin6_addr;
      for (h = CMSG_FIRSTHDR(&msg); h ;
           h = CMSG_NXTHDR(&msg, h))
        if (h->cmsg_level == IPPROTO_IPV6
            && h->cmsg_type == IPV6_PKTINFO)
          {
            ipi6 = (struct in6_pktinfo *)CMSG_DATA(h);
            if (!if_indextoname(ipi6->ipi6_ifindex, ifname))
              *ifname = 0;
            *dst = ipi6->ipi6_addr;
          }
    }
  else
    {
      *ifname = 0;
    }
  if (!*ifname)
    return -1;
  return l;
}

ssize_t hcp_io_sendto(hcp o, void *buf, size_t len,
                      const char *ifname,
                      const struct in6_addr *to)
{
  int flags = 0;
  struct sockaddr_in6 dst;

  memset(&dst, 0, sizeof(dst));
  if (!(dst.sin6_scope_id = if_nametoindex(ifname)))
    return -1;
  dst.sin6_addr = *to;
  return sendto(o->udp_socket, buf, len, flags, &dst, sizeof(dst));
}
