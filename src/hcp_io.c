/*
 * $Id: hcp_io.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Mon Nov 25 14:00:10 2013 mstenber
 * Last modified: Mon Nov 25 17:37:00 2013 mstenber
 * Edit time:     18 min
 *
 */

/* This module implements I/O needs of hcp. Notably, it has both
 * functionality that deals with sockets, and bit more abstract ones
 * that just deal with buffers for input and output (thereby
 * facilitating unit testing without using real sockets). */

#include "hcp_i.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <arpa/inet.h>

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


bool hcp_io_init(hcp o)
{
  int s;

  s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s<0)
    return false;
  /* XXX - bind port */
  o->udp_socket = s;
  return true;
}

void hcp_io_uninit(hcp o)
{
  close(o->udp_socket);
}

bool hcp_io_set_ifname_enabled(hcp o,
                               const char *ifname,
                               bool enabled)
{
  struct ipv6_mreq val;

  if (!inet_pton(AF_INET6, HCP_MCAST_GROUP, &val.ipv6mr_multiaddr))
    return false;
  if (!(val.ipv6mr_interface = if_nametoindex(ifname)))
    return false;
  if (setsockopt(o->udp_socket,
                 IPPROTO_IPV6,
                 enabled ? IPV6_ADD_MEMBERSHIP : IPV6_DROP_MEMBERSHIP,
                 (char *) &val, sizeof(val)) < 0)
    return false;
  /* Yay. It succeeded(?). */
  return true;
}
