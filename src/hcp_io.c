/*
 * $Id: hcp_io.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Mon Nov 25 14:00:10 2013 mstenber
 * Last modified: Mon Nov 25 18:49:24 2013 mstenber
 * Edit time:     52 min
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

#define TRICKLE_IMIN 250

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define TRICKLE_IMAX ((TRICKLE_IMIN*4)*64)

/* Redundancy constant. */
#define TRICKLE_K 1

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

static void trickle_set_i(hcp_link l, hnetd_time_t now, int i)
{
  l->i = i;
  l->send_time = now + l->i * (1000 + random() % 1000) / 2000;
  l->interval_end_time = now + l->i;
}

static void trickle_upgrade(hcp_link l, hnetd_time_t now)
{
  int i = l->i * 2;
  i = i < TRICKLE_IMIN ? TRICKLE_IMIN : i > TRICKLE_IMAX ? TRICKLE_IMAX : i;
  trickle_set_i(l, now, i);
}

static void trickle_send(hcp_link l)
{
  if (l->c < TRICKLE_K)
    {
      /* XXX */
    }
  l->send_time = 0;
}

#define TMIN(x,y) ((x) == 0 ? (y) : (y) == 0 ? (x) : (x) < (y) ? (x) : (y))

static void _timeout(struct uloop_timeout *t)
{
  hcp o = container_of(t, hcp_s, timeout);
  hnetd_time_t next = 0;
  hnetd_time_t now = hnetd_time();
  hcp_link l;

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      unsigned char buf[HCP_HASH_LEN];

      memcpy(buf, o->network_hash, HCP_HASH_LEN);
      hcp_calculate_network_hash(o, o->network_hash);
      if (memcmp(buf, o->network_hash, HCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle. */
          vlist_for_each_element(&o->links, l, in_links)
            trickle_set_i(l, now, TRICKLE_IMIN);
        }
      o->network_hash_dirty = false;
    }

  vlist_for_each_element(&o->links, l, in_links)
    {
      if (l->interval_end_time <= now)
        {
          trickle_upgrade(l, now);
          next = TMIN(next, l->send_time);
          continue;
        }

      if (l->send_time)
        {
          if (l->send_time > now)
            {
              next = TMIN(next, l->send_time);
              continue;
            }

          trickle_send(l);
        }
      next = TMIN(next, l->interval_end_time);
    }
  if (next)
    uloop_timeout_set(&o->timeout, next - now);
}

bool hcp_io_init(hcp o)
{
  int s;

  s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (s<0)
    return false;
  /* XXX - bind port */
  o->udp_socket = s;
  o->timeout.cb = _timeout;
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
    goto fail;
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
  o->join_failed_time = hnetd_time();
  uloop_timeout_set(&o->timeout, 0);
  return false;
}

void hcp_io_maybe_reset_trickle(hcp o)
{
  uloop_timeout_set(&o->timeout, 0);
}
