/*
 * $Id: fake_iface.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Thu Feb 26 13:40:08 2015 mstenber
 * Last modified: Thu Feb 26 13:56:27 2015 mstenber
 * Edit time:     3 min
 *
 */

#pragma once

#include "iface.h"
#include "smock.h"

/********************************************************************* iface */

bool mock_iface = false;

struct iface default_iface = {.elected = -1,
                              .internal = true};

struct iface* iface_get(const char *ifname)
{
  if (mock_iface)
    return smock_pull("iface_get");
  static struct {
    struct iface iface;
    char ifname[16];
  } iface;
  strcpy(iface.ifname, ifname);
  iface.iface = default_iface;
  return &iface.iface;
}

struct iface* iface_next(struct iface *prev)
{
  if (mock_iface)
    return smock_pull("iface_next");
  return NULL;
}

void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len,
                             const void *dhcp_data, size_t dhcp_len)
{
}

int iface_get_preferred_address(struct in6_addr *foo, bool v4, const char *ifname)
{
  inet_pton(AF_INET6, (v4) ? "::ffff:192.168.1.2" : "2001:db8::f00:1", foo);
  return 0;
}

struct list_head *current_iface_users = NULL;

void iface_register_user(struct iface_user *user)
{
  sput_fail_unless(current_iface_users, "no current_iface_users");
  if (current_iface_users)
    list_add(&user->head, current_iface_users);
}

void iface_unregister_user(struct iface_user *user)
{
  list_del(&user->head);
}

#define net_sim_node_iface_callback(n, cb_name, ...)    \
do {                                                    \
  struct iface_user *u;                                 \
  list_for_each_entry(u, &n->iface_users, head)         \
  if (u->cb_name)                                       \
    u->cb_name(u, __VA_ARGS__);                         \
} while(0)
