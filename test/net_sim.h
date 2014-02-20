/*
 * $Id: net_sim.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Fri Dec  6 18:48:08 2013 mstenber
 * Last modified: Thu Feb 20 17:12:15 2014 mstenber
 * Edit time:     35 min
 *
 */

#ifndef NET_SIM_H
#define NET_SIM_H

#include "hncp_i.h"
#include "hncp_pa.h"
#include "hncp_sd.h"
#include "pa.h"
#include "sput.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* This is abstraction that can be used to play with multiple HNCP
 * instances; no separate C module provided just due to
 * laziness. Moved from test_hncp_net (as test_hncp_pa needs similar
 * code but it has to be separate test binary due to different
 * interests in stubbed interfaces) */

struct pa {
  struct pa_flood_callbacks cbs;
};

#ifndef MAXIMUM_PROPAGATION_DELAY
#define MAXIMUM_PROPAGATION_DELAY 100
#endif /* !MAXIMUM_PROPAGATION_DELAY */
#if MAXIMUM_PROPAGATION_DELAY > 0
#define MESSAGE_PROPAGATION_DELAY (random() % MAXIMUM_PROPAGATION_DELAY + 1)
#else
#define MESSAGE_PROPAGATION_DELAY 1
#endif

typedef struct {
  struct list_head h;

  hnetd_time_t readable_at;
  hncp_link l;
  struct in6_addr src;
  struct in6_addr dst;
  void *buf;
  size_t len;
} net_msg_s, *net_msg;

typedef struct {
  struct list_head h;

  hncp_link src;
  hncp_link dst;
} net_neigh_s, *net_neigh;

typedef struct {
  struct list_head h;
  struct net_sim_t *s;
  char *name;
  hncp_s n;
  struct pa pa;
#ifndef DISABLE_HNCP_PA
  hncp_glue g;
#endif /* !DISABLE_HNCP_PA */
  hncp_sd sd;
  hnetd_time_t want_timeout_at;
  hnetd_time_t next_message_at;
  int updated_eap;
  int updated_edp;
} net_node_s, *net_node;

typedef struct net_sim_t {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;

  bool assume_bidirectional_reachability;
  bool disable_sd;

  hnetd_time_t now, start;

  int sent_unicast;
  hnetd_time_t last_unicast_sent;
  int sent_multicast;

  int converged_count;
  int not_converged_count;
} net_sim_s, *net_sim;

void net_sim_init(net_sim s)
{
  memset(s, 0, sizeof(*s));
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
  /* 64 bits -> have to enjoy it.. */
  /* s->start = s->now = 12345678901234; */
  s->start = s->now = 10000000000000; /* easier to see deltas in abs. values */
}

bool net_sim_is_converged(net_sim s)
{
  net_node n, n2;
  bool first = true;
  hncp_hash h = NULL;
  hncp_node hn;

  list_for_each_entry(n, &s->nodes, h)
    {
      if (n->n.network_hash_dirty)
        return false;
      if (first)
        {
          h = &n->n.network_hash;
          first = false;
          continue;
        }
      if (memcmp(h, &n->n.network_hash, sizeof(hncp_hash_s)))
        {
          L_DEBUG("not converged, network hash mismatch %llx <> %llx",
                  hncp_hash64(h), hncp_hash64(&n->n.network_hash));
          s->not_converged_count++;
          return false;
        }
    }
  list_for_each_entry(n, &s->nodes, h)
    {
      list_for_each_entry(n2, &s->nodes, h)
        {
          /* Make sure that the information about other node _is_ valid */
          hn = hncp_find_node_by_hash(&n->n,
                                      &n2->n.own_node->node_identifier_hash,
                                      false);
          sput_fail_unless(hn, "hncp_find_node_by_hash failed");
          if (abs(n2->n.own_node->origination_time -
                  hn->origination_time) > 5000)
            {
              L_DEBUG("origination time mismatch %lld <> %lld",
                      (long long) n2->n.own_node->origination_time,
                      (long long) hn->origination_time);
              s->not_converged_count++;
              return false;
            }
        }
    }

  s->converged_count++;
  return true;
}

hncp net_sim_find_hncp(net_sim s, const char *name)
{
  net_node n;
  bool r;

  list_for_each_entry(n, &s->nodes, h)
    {
      if (strcmp(n->name, name) == 0)
        return &n->n;
    }

  n = calloc(1, sizeof(*n));
  n->name = strdup(name);
  sput_fail_unless(n, "calloc net_node");
  sput_fail_unless(n->name, "strdup name");
  n->s = s;
  r = hncp_init(&n->n, name, strlen(name));
  n->n.assume_bidirectional_reachability = s->assume_bidirectional_reachability;
  n->n.io_init_done = true; /* our IO doesn't really need init.. */
  sput_fail_unless(r, "hncp_init");
  if (!r)
    return NULL;
  list_add(&n->h, &s->nodes);
#ifndef DISABLE_HNCP_PA
  /* Glue it to pa */
  if (!(n->g = hncp_pa_glue_create(&n->n, &n->pa)))
    return NULL;
#endif /* !DISABLE_HNCP_PA */
  /* Add SD support */
  if (!s->disable_sd)
    if (!(n->sd = hncp_sd_create(&n->n,
                                 "/bin/yes",
                                 "/tmp/dnsmasq.conf",
                                 "/bin/no",
                                 NULL, NULL)))
      return NULL;
  return &n->n;
}

hncp_link net_sim_hncp_find_link_by_name(hncp o, const char *name)
{
  hncp_link l;

  l = hncp_find_link_by_name(o, name, false);

  if (l)
    return l;

  l = hncp_find_link_by_name(o, name, true);

  sput_fail_unless(l, "hncp_find_link_by_name");
  if (l)
    {
      /* Initialize the address - in rather ugly way. We just hash
       * ifname + xor that with our own hash. The result should be
       * highly unique still. */
      hncp_hash_s h1, h;
      int i;

      hncp_calculate_hash(name, strlen(name), &h1);
      for (i = 0 ; i < HNCP_HASH_LEN ; i++)
        h.buf[i] = h1.buf[i] ^ o->own_node->node_identifier_hash.buf[i];
      h.buf[0] = 0xFE;
      h.buf[1] = 0x80;
      /* Let's pretend it's /64; clear out 2-7 */
      for (i = 2 ; i < 8 ; i++)
        h.buf[i] = 0;
      hncp_link_set_ipv6_address(l, (struct in6_addr *)&h);
    }
  return l;
}

void net_sim_set_connected(hncp_link l1, hncp_link l2, bool enabled)
{
  hncp o = l1->hncp;
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  net_neigh n;


  L_DEBUG("connection %p/%d -> %p/%d %s",
          l1, l1->iid, l2, l2->iid, enabled ? "on" : "off");
  if (enabled)
    {
      /* Add node */
      n = calloc(1, sizeof(*n));

      sput_fail_unless(n, "calloc net_neigh");
      n->src = l1;
      n->dst = l2;
      list_add(&n->h, &s->neighs);
    }
  else
    {
      /* Remove node */
      list_for_each_entry(n, &s->neighs, h)
        {
          if (n->src == l1 && n->dst == l2)
            {
              list_del(&n->h);
              free(n);
              return;
            }
        }
    }
}

void net_sim_remove_node(net_sim s, net_node node)
{
  struct list_head *p, *pn;
  hncp o = &node->n;
  net_neigh n, nn;

  /* Remove from neighbors */
  list_for_each_entry_safe(n, nn, &s->neighs, h)
    {
      if (n->src->hncp == o || n->dst->hncp == o)
        {
          list_del(&n->h);
          free(n);
        }
    }

  /* Remove from messages */
  list_for_each_safe(p, pn, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      if (m->l->hncp == o)
        {
          list_del(&m->h);
          free(m->buf);
          free(m);
        }
    }

  /* Remove from list of nodes */
  list_del(&node->h);
  free(node->name);
  hncp_uninit(&node->n);

  /* Get rid of sd data structure */
  if (!s->disable_sd)
    hncp_sd_destroy(node->sd);

#ifndef DISABLE_HNCP_PA
  /* Kill glue (has to be done _after_ hncp_uninit). */
  hncp_pa_glue_destroy(node->g);
#endif /* !DISABLE_HNCP_PA */

  free(node);
}

void net_sim_remove_node_by_name(net_sim s, const char *name)
{
  hncp o = net_sim_find_hncp(s, name);
  net_node node = container_of(o, net_node_s, n);
  sput_fail_unless(o, "net_sim_find_hncp");
  net_sim_remove_node(s, node);
}

void net_sim_uninit(net_sim s)
{
  struct list_head *p, *pn;
  int c = 0;

  list_for_each_safe(p, pn, &s->nodes)
    {
      net_node node = container_of(p, net_node_s, h);
      net_sim_remove_node(s, node);
      c++;
    }
  L_NOTICE("#nodes:%d elapsed:%.2fs unicasts:%d multicasts:%d",
           c,
           (float)(s->now - s->start) / HNETD_TIME_PER_SECOND,
           s->sent_unicast, s->sent_multicast);
  sput_fail_unless(list_empty(&s->neighs), "no neighs");
  sput_fail_unless(list_empty(&s->messages), "no messages");
}

hnetd_time_t net_sim_next(net_sim s)
{
  hnetd_time_t v = 0;
  net_node n;
  net_msg m;

  list_for_each_entry(n, &s->nodes, h)
    {
      n->next_message_at = 0;
      v = TMIN(v, n->want_timeout_at);
    }
  list_for_each_entry(m, &s->messages, h)
    {
      hncp o = m->l->hncp;

      n = container_of(o, net_node_s, n);
      v = TMIN(v, m->readable_at);
      n->next_message_at = TMIN(n->next_message_at, m->readable_at);
    }
  return v;
}

int net_sim_poll(net_sim s)
{
  net_node n;
  hnetd_time_t nt = net_sim_next(s);
  int i = 0;

  if (nt > s->now)
    return 0;
  list_for_each_entry(n, &s->nodes, h)
    {
      if (n->want_timeout_at && n->want_timeout_at <= s->now)
        {
          n->want_timeout_at = 0;
          hncp_run(&n->n);
          i++;
        }
      if (n->next_message_at && n->next_message_at <= s->now)
        {
          hncp_poll(&n->n);
          i++;
        }
    }
  return i;
}

void net_sim_run(net_sim s)
{
  while (net_sim_poll(s));
}

void net_sim_advance(net_sim s, hnetd_time_t t)
{
  sput_fail_unless(s->now <= t, "time moving forwards");
  s->now = t;
  L_DEBUG("time = %lld", (long long int) (t - s->start));
}

#define SIM_WHILE(s, maxiter, criteria)                 \
  do {                                                  \
    int iter = 0;                                       \
                                                        \
    sput_fail_unless((criteria), "criteria at start");  \
    while(iter < maxiter)                               \
      {                                                 \
        net_sim_run(s);                                 \
        if (!(criteria))                                \
          break;                                        \
        net_sim_advance(s, net_sim_next(s));            \
        iter++;                                         \
      }                                                 \
    sput_fail_unless(!(criteria), "!criteria at end");  \
  } while(0)

/************************************************* Mocked interface - hncp_io */

bool hncp_io_init(hncp o)
{
  return true;
}

void hncp_io_uninit(hncp o)
{
}

bool hncp_io_set_ifname_enabled(hncp o, const char *ifname, bool enabled)
{
  return true;
}

int hncp_io_get_hwaddrs(unsigned char *buf, int buf_left)
{
  return 0;
}

bool hncp_io_get_ipv6(struct in6_addr *addr, char *prefer_ifname)
{
  memset(addr, 0, sizeof(*addr));
  ((uint8_t *)addr)[0] = prefer_ifname ? 1 : 0;
  return true;
}

void hncp_io_schedule(hncp o, int msecs)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  hnetd_time_t wt = s->now + msecs;

  sput_fail_unless(wt >= s->now, "should be present or future");
  if (!node->want_timeout_at || node->want_timeout_at > wt)
    node->want_timeout_at = wt;
}

ssize_t hncp_io_recvfrom(hncp o, void *buf, size_t len,
                         char *ifname,
                         struct in6_addr *src,
                         struct in6_addr *dst)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  net_msg m;

  list_for_each_entry(m, &s->messages, h)
    {
      if (m->l->hncp == o && m->readable_at <= s->now)
        {
          int s = m->len > len ? len : m->len;
          /* Aimed at us. Yay. */
          strcpy(ifname, m->l->ifname);
          *src = m->src;
          *dst = m->dst;
          memcpy(buf, m->buf, s);
          list_del(&m->h);
          free(m->buf);
          free(m);
          return s;
        }
    }
  return -1;
}

void
sanity_check_buf(void *buf, size_t len)
{
  struct tlv_attr *a, *last = NULL;
  int a_len;
  int last_len;
  bool ok = true;
  tlv_for_each_in_buf(a, buf, len)
    {
      a_len = tlv_pad_len(a);
      if (last)
        {
          if (memcmp(last, a, last_len < a_len ? last_len : a_len) >= 0)
            {
              ok = false;
              L_ERR("ordering error - %s >= %s",
                    TLV_REPR(last), TLV_REPR(a));
            }
        }
      last = a;
      last_len = a_len;
      /* XXX - some better way to determine recursion? */
      switch (tlv_id(a))
        {
        case HNCP_T_NODE_DATA:
          sanity_check_buf(tlv_data(a), tlv_len(a));
          break;
        }
    }
  sput_fail_unless(ok, "tlv ordering valid");

}

void _sendto(net_sim s, void *buf, size_t len, hncp_link sl, hncp_link dl,
             const struct in6_addr *dst)
{
#if L_LEVEL >= 7
  hncp o = dl->hncp;
  net_node node1 = container_of(sl->hncp, net_node_s, n);
  net_node node2 = container_of(dl->hncp, net_node_s, n);
  bool is_multicast = memcmp(dst, &o->multicast_address, sizeof(*dst)) == 0;
#endif /* L_LEVEL >= 7 */
  net_msg m = calloc(1, sizeof(*m));
  hnetd_time_t wt = s->now + MESSAGE_PROPAGATION_DELAY;

  sput_fail_unless(m, "calloc neigh");
  m->l = dl;
  m->buf = malloc(len);
  sput_fail_unless(m->buf, "malloc buf");
  memcpy(m->buf, buf, len);
  m->len = len;
  sput_fail_unless(sl->has_ipv6_address, "no ipv6 address?!?");
  m->src = sl->ipv6_address;
  m->dst = *dst;
  m->readable_at = wt;
  list_add(&m->h, &s->messages);
  L_DEBUG("sendto: %s/%s -> %s/%s (%d bytes %s)",
          node1->name, sl->ifname, node2->name, dl->ifname, (int)len,
          is_multicast ? "multicast" : "unicast");
}

ssize_t hncp_io_sendto(hncp o, void *buf, size_t len,
                       const char *ifname,
                       const struct in6_addr *dst)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  hncp_link l = hncp_find_link_by_name(o, ifname, false);
  bool is_multicast = memcmp(dst, &o->multicast_address, sizeof(*dst)) == 0;
  net_neigh n;

  if (!l)
    return -1;

  sanity_check_buf(buf, len);
  if (is_multicast)
    s->sent_multicast++;
  else
    {
      s->sent_unicast++;
      s->last_unicast_sent = s->now;
    }
  list_for_each_entry(n, &s->neighs, h)
    {
      if (n->src == l
          && (is_multicast
              || (n->dst->has_ipv6_address
                  && memcmp(&n->dst->ipv6_address, dst, sizeof(*dst)) == 0)))
        _sendto(s, buf, len, n->src, n->dst, dst);
    }
  /* Loop at self too, just for fun. */
  if (is_multicast)
    _sendto(s, buf, len, l, l, dst);
  return -1;
}

hnetd_time_t hncp_io_time(hncp o)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;

  return s->now;
}

/**************************************** (Partially mocked) interface - pa  */

void pa_flood_subscribe(pa_t pa, const struct pa_flood_callbacks *cbs)
{
  pa->cbs = *cbs;
  sput_fail_unless(pa->cbs.priv, "priv set");
}

void pa_set_rid(pa_t pa, const struct pa_rid *rid)
{
  net_node node = container_of(pa, net_node_s, pa);
  hncp o = &node->n;

  /* We're not checking new updates. */
  sput_fail_unless(!o->own_node
                   || memcmp(rid,
                             &o->own_node->node_identifier_hash,
                             HNCP_HASH_LEN) == 0,
                   "rid same");

}

/********************************************************************* iface */

struct iface* iface_get(const char *ifname)
{
  return NULL;
}

void iface_set_dhcpv6_send(const char *ifname,
                           const void *dhcpv6_data, size_t dhcpv6_len,
                           const void *dhcp_data, size_t dhcp_len)
{
}

#endif /* NET_SIM_H */
