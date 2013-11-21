/*
 * $Id: hcp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Thu Nov 21 14:30:15 2013 mstenber
 * Edit time:     69 min
 *
 */

#include "hcp_i.h"
#include <libubox/md5.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <unistd.h>

#ifndef __unused
#define __unused __attribute__((unused))
#endif /* !__unused */

/* 'found' from odhcp6c */
static int
get_hwaddr(const char *ifname, unsigned char *buf, int buf_left)
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

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  hcp_node n1 = (hcp_node) a, n2 = (hcp_node) b;

  return memcmp(n1->node_identifier_hash, n2->node_identifier_hash,
                HCP_HASH_LEN);
}

static void update_node(__unused struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hcp_node n_old = container_of(node_old, hcp_node_s, in_nodes);
  __unused hcp_node n_new = container_of(node_new, hcp_node_s, in_nodes);
  if (n_old)
    {
      if (n_old->tlv_container)
        free(n_old->tlv_container);
      free(n_old);
    }
}


static int
compare_tlvs(const void *a, const void *b, void *ptr __attribute__((unused)))
{
  hcp_tlv t1 = (hcp_tlv) a, t2 = (hcp_tlv) b;
  int s1 = tlv_pad_len(&t1->tlv);
  int s2 = tlv_pad_len(&t2->tlv);
  int s = s1 < s2 ? s1 : s2;
  int r = memcmp(&t1->tlv, &t2->tlv, s);

  if (r == 0 && s1 != s2)
    return s1 < s2 ? -1 : 1;
  return r;
}

static void update_tlv(struct vlist_tree *t,
                       struct vlist_node *node_new,
                       struct vlist_node *node_old)
{
  hcp o = container_of(t, hcp_s, tlvs);
  hcp_tlv t_old = container_of(node_old, hcp_tlv_s, in_tlvs);
  __unused hcp_tlv t_new = container_of(node_new, hcp_tlv_s, in_tlvs);

  if (t_old)
    free(t_old);
  o->should_publish = true;
}

void hcp_hash(const void *buf, int len, unsigned char *dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}


bool hcp_init(hcp o, unsigned char *node_identifier, int len)
{
  hcp_node n;

  vlist_init(&o->nodes, compare_nodes, update_node);
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  hcp_hash(node_identifier, len, n->node_identifier_hash);
  n->hcp = o;
  vlist_add(&o->nodes, &n->in_nodes, n);
  o->own_node = n;
  return true;
}

hcp hcp_create(void)
{
  hcp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  o = calloc(1, sizeof(*o));
  if (!o) return NULL;

  /* XXX - this is very arbitrary and Linux-only. However, hopefully
   * it is enough (should probably have ifname(s) as argument). */
  c += get_hwaddr("eth0", c, sizeof(buf) + buf - c);
  c += get_hwaddr("eth1", c, sizeof(buf) + buf - c);
  if (c == buf)
    {
      /* No hwaddr = no go. */
      free(o);
      return NULL;
    }
  if (!hcp_init(o, buf, c-buf))
    {
      free(o);
      return NULL;
    }
  return o;
}

void hcp_destroy(hcp o)
{
  if (!o) return;
  vlist_flush_all(&o->nodes);
  vlist_flush_all(&o->tlvs);
  free(o);
}

hcp_node hcp_get_first_node(hcp o)
{
  hcp_node n;

  return avl_is_empty(&o->nodes.avl) ? NULL :
    avl_first_element(&o->nodes.avl, n, in_nodes.avl);
}

bool hcp_add_tlv(hcp o, struct tlv_attr *tlv)
{
  hcp_tlv t;
  int s = tlv_pad_len(tlv);

  t = calloc(1, sizeof(*t) + s - sizeof(*tlv));
  if (!t) return false;
  memcpy(&t->tlv, tlv, s);
  vlist_add(&o->tlvs, &t->in_tlvs, t);
  return true;
}

bool hcp_remove_tlv(hcp o, struct tlv_attr *tlv)
{
  /* kids, don't do this at home, the pointer itself is invalid,
     but it _should_ work as comparison operator only operates on
     n->tlv. */
  hcp_tlv t = container_of(tlv, hcp_tlv_s, tlv);
  hcp_tlv old = vlist_find(&o->tlvs, t, t, in_tlvs);

  if (!old)
    return false;
  vlist_delete(&o->tlvs, &old->in_tlvs);
  return true;
}

bool hcp_node_is_self(hcp_node n)
{
  return n->hcp->own_node == n;
}

hcp_node hcp_node_get_next(hcp_node n)
{
  hcp o = n->hcp;
  hcp_node last = avl_last_element(&o->nodes.avl, n, in_nodes.avl);
  if (!n || n == last)
    return NULL;
  return avl_next_element(n, in_nodes.avl);
}

static void _flush(hcp_node n)
{
  hcp o = n->hcp;
  hcp_tlv t;
  struct tlv_buf tb;

  if (!o->should_publish)
    return;
  /* Dump the contents of hcp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    if (!tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv)))
      return;
  /* Ok, all puts _did_ succeed. */
  if (n->tlv_container)
    free(n->tlv_container);
  n->tlv_container = tb.head;
  o->should_publish = false;
}

void hcp_node_get_tlvs(hcp_node n, struct tlv_attr **r)
{
  if (hcp_node_is_self(n))
    _flush(n);
  *r = n->tlv_container;
}
