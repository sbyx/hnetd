/*
 * $Id: test_hcp_net.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 10:41:56 2013 mstenber
 * Last modified: Wed Nov 27 12:51:53 2013 mstenber
 * Edit time:     63 min
 *
 */

/*
 * This is a variant of hcp test suite, which replaces the hcp_io code
 * with a fake network. The fake network can be dynamically
 * configured, and basically contains UNIDIRECTIONAL "propagate from X
 * to Y" configuration entries that can change dynamically over the
 * time of the testcase.
 */

#include "hnetd.h"
#include "hcp.c"
#include "hcp_recv.c"
#include "hcp_timeout.c"
#include "sput.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/*********************************************** Fake network infrastructure */

hnetd_time_t now_time;

#define MESSAGE_PROPAGATION_DELAY (random() % 100 + 1)

typedef struct {
  struct list_head h;

  hnetd_time_t readable_at;
  hcp_link l;
  struct in6_addr src;
  struct in6_addr dst;
  void *buf;
  size_t len;
} net_msg_s, *net_msg;

typedef struct {
  struct list_head h;

  hcp_link src;
  hcp_link dst;
} net_neigh_s, *net_neigh;

typedef struct {
  struct list_head h;
  struct net_sim_t *s;
  hcp_s n;
  hnetd_time_t want_timeout_at;
} net_node_s, *net_node;

typedef struct net_sim_t {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;

  hnetd_time_t now;
} net_sim_s, *net_sim;

void net_sim_init(net_sim s)
{
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
}

hcp net_sim_add_hcp(net_sim s, const char *name)
{
  net_node n = calloc(1, sizeof(*n));
  bool r;

  sput_fail_unless(n, "calloc net_node");
  n->s = s;
  r = hcp_init(&n->n, name, strlen(name));
  sput_fail_unless(r, "hcp_init");
  if (!r)
    return NULL;
  list_add(&n->h, &s->nodes);
  return &n->n;
}

hcp_link net_sim_hcp_find_link(hcp o, const char *name)
{
  hcp_link l = hcp_find_link(o, name, true);

  if (l)
    {
      /* Initialize the address - in rather ugly way. We just hash
       * ifname + xor that with our own hash. The result should be
       * highly unique still. */
      unsigned char h1[HCP_HASH_LEN];
      unsigned char h[HCP_HASH_LEN];
      int i;

      hcp_hash(name, strlen(name), h1);
      for (i = 0 ; i < HCP_HASH_LEN ; i++)
        h[i] = h1[i] ^ o->own_node->node_identifier_hash[i];
      memcpy(&l->address, h, sizeof(l->address));
    }
  return l;
}

void net_sim_set_connected(hcp_link l1, hcp_link l2, bool enabled)
{
}

void net_sim_uninit(net_sim s)
{
  struct list_head *p, *pn;

  list_for_each_safe(p, pn, &s->nodes)
    {
      net_node n = container_of(p, net_node_s, h);
      hcp_uninit(&n->n);
      free(n);
    }
  list_for_each_safe(p, pn, &s->neighs)
    {
      net_neigh n = container_of(p, net_neigh_s, h);
      free(n);
    }
  list_for_each_safe(p, pn, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      free(m->buf);
      free(m);
    }
}

/********************************************************* Mocked interfaces */

bool hcp_io_init(hcp o)
{
  return true;
}

void hcp_io_uninit(hcp o)
{
}

bool hcp_io_set_ifname_enabled(hcp o, const char *ifname, bool enabled)
{
  return true;
}

int hcp_io_get_hwaddr(const char *ifname, unsigned char *buf, int buf_left)
{
  return 0;
}

void hcp_io_schedule(hcp o, int msecs)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  hnetd_time_t wt = msecs + s->now;

  if (!node->want_timeout_at || node->want_timeout_at > wt)
    node->want_timeout_at = wt;
}

ssize_t hcp_io_recvfrom(hcp o, void *buf, size_t len,
                        char *ifname,
                        struct in6_addr *src,
                        struct in6_addr *dst)
{
  struct list_head *p;
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;

  list_for_each(p, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      if (m->l->hcp == o && m->readable_at <= s->now)
        {
          int s = m->len > len ? len : m->len;
          /* Aimed at us. Yay. */
          strcpy(ifname, m->l->ifname);
          *src = m->src;
          *dst = m->dst;
          memcpy(buf, m->buf, s);
          list_del(p);
          free(m->buf);
          free(m);
          return s;
        }
    }
  return -1;
}

ssize_t hcp_io_sendto(hcp o, void *buf, size_t len,
                      const char *ifname,
                      const struct in6_addr *dst)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  hcp_link l = hcp_find_link(o, ifname, false);
  bool is_multicast = memcmp(dst, &o->multicast_address, sizeof(*dst)) == 0;
  struct list_head *p;

  if (!l)
    return -1;

  list_for_each(p, &s->neighs)
    {
      net_neigh n = container_of(p, net_neigh_s, h);

      if (n->src == l
          && (is_multicast
              || memcmp(&n->dst->address, dst, sizeof(*dst)) == 0))
        {
          net_msg m = calloc(1, sizeof(*m));
          hnetd_time_t wt = s->now + MESSAGE_PROPAGATION_DELAY;

          sput_fail_unless(m, "calloc neigh");
          m->l = n->dst;
          m->buf = malloc(len);
          sput_fail_unless(m->buf, "malloc buf");
          memcpy(m->buf, buf, len);
          m->len = len;
          m->dst = *dst;
          m->readable_at = wt;
          list_add(&m->h, &s->messages);
        }
    }
  return -1;
}

hnetd_time_t hcp_io_time(hcp o)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;

  return s->now;
}

/**************************************************************** Test cases */

void hcp_two(void)
{
  net_sim_s s;
  hcp n1;
  hcp n2;

  net_sim_init(&s);
  n1 = net_sim_add_hcp(&s, "n1");
  n2 = net_sim_add_hcp(&s, "n2");
  
  net_sim_uninit(&s);
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hcp_net"); /* optional */
  sput_run_test(hcp_two);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
