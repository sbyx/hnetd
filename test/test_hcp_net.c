/*
 * $Id: test_hcp_net.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 10:41:56 2013 mstenber
 * Last modified: Mon Dec  2 13:01:16 2013 mstenber
 * Edit time:     176 min
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
#include "hcp_proto.c"
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
  char *name;
  hcp_s n;
  hnetd_time_t want_timeout_at;
  hnetd_time_t next_message_at;
} net_node_s, *net_node;

typedef struct net_sim_t {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;

  hnetd_time_t now, start;

  int sent_unicast;
  int sent_multicast;
} net_sim_s, *net_sim;

void net_sim_init(net_sim s)
{
  memset(s, 0, sizeof(*s));
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
  /* 64 bits -> have to enjoy it.. */
  s->start = s->now = 12345678901234;
}

bool net_sim_is_converged(net_sim s)
{
  net_node n;
  struct list_head *p;
  bool first = true;
  hcp_hash h = NULL;

  list_for_each(p, &s->nodes)
    {
      n = container_of(p, net_node_s, h);
      if (n->n.network_hash_dirty)
        return false;
      if (first)
        {
          h = &n->n.network_hash;
          first = false;
          continue;
        }
      if (memcmp(h, &n->n.network_hash, sizeof(hcp_hash_s)))
        return false;
    }
  return true;
}

hcp net_sim_find_hcp(net_sim s, const char *name)
{
  net_node n;
  struct list_head *p;
  bool r;

  list_for_each(p, &s->nodes)
    {
      n = container_of(p, net_node_s, h);
      if (strcmp(n->name, name) == 0)
        return &n->n;
    }

  n = calloc(1, sizeof(*n));
  n->name = strdup(name);
  sput_fail_unless(n, "calloc net_node");
  sput_fail_unless(n->name, "strdup name");
  n->s = s;
  r = hcp_init(&n->n, name, strlen(name));
  n->n.io_init_done = true; /* our IO doesn't really need init.. */
  sput_fail_unless(r, "hcp_init");
  if (!r)
    return NULL;
  list_add(&n->h, &s->nodes);
  return &n->n;
}

hcp_link net_sim_hcp_find_link(hcp o, const char *name)
{
  hcp_link l;

  l = hcp_find_link(o, name, false);

  if (l)
    return l;

  l = hcp_find_link(o, name, true);

  sput_fail_unless(l, "hcp_find_link");
  if (l)
    {
      /* Initialize the address - in rather ugly way. We just hash
       * ifname + xor that with our own hash. The result should be
       * highly unique still. */
      hcp_hash_s h1, h;
      int i;

      hcp_calculate_hash(name, strlen(name), &h1);
      for (i = 0 ; i < HCP_HASH_LEN ; i++)
        h.buf[i] = h1.buf[i] ^ o->own_node->node_identifier_hash.buf[i];
      h.buf[0] = 0xFE;
      h.buf[1] = 0x80;
      /* Let's pretend it's /64; clear out 2-7 */
      for (i = 2 ; i < 8 ; i++)
        h.buf[i] = 0;
      memcpy(&l->address, &h, sizeof(l->address));
      sput_fail_unless(sizeof(l->address) == HCP_HASH_LEN,
                       "weird address size");
    }
  return l;
}

void net_sim_set_connected(hcp_link l1, hcp_link l2, bool enabled)
{
  hcp o = l1->hcp;
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;

  /* printf("connection %x -> %x %s\n", l1, l2, enabled ? "on" : "off"); */
  if (enabled)
    {
      /* Add node */
      net_neigh n = calloc(1, sizeof(*n));

      sput_fail_unless(n, "calloc net_neigh");
      n->src = l1;
      n->dst = l2;
      list_add(&n->h, &s->neighs);
    }
  else
    {
      struct list_head *p;

      /* Remove node */
      list_for_each(p, &s->neighs)
        {
          net_neigh n = container_of(p, net_neigh_s, h);

          if (n->src == l1 && n->dst == l2)
            {
              list_del(&n->h);
              free(n);
              return;
            }
        }
    }
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

hnetd_time_t net_sim_next(net_sim s)
{
  struct list_head *p;
  hnetd_time_t v = 0;
  net_node n;

  list_for_each(p, &s->nodes)
    {
      n = container_of(p, net_node_s, h);
      n->next_message_at = 0;
      v = TMIN(v, n->want_timeout_at);
    }
  list_for_each(p, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      hcp o = m->l->hcp;

      n = container_of(o, net_node_s, n);
      v = TMIN(v, m->readable_at);
      n->next_message_at = TMIN(n->next_message_at, m->readable_at);
    }
  return v;
}

int net_sim_poll(net_sim s)
{
  struct list_head *p;
  hnetd_time_t n = net_sim_next(s);
  int i = 0;

  if (n <= s->now)
    {
      list_for_each(p, &s->nodes)
        {
          net_node n = container_of(p, net_node_s, h);

          if (n->want_timeout_at && n->want_timeout_at <= s->now)
            {
              n->want_timeout_at = 0;
              hcp_run(&n->n);
              i++;
            }
          if (n->next_message_at && n->next_message_at <= s->now)
            {
              hcp_poll(&n->n);
              i++;
            }
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
  printf("time = %lld\n", (long long int) (t - s->start));
}

#define SIM_WHILE(s, maxiter, criteria)                 \
do {                                                    \
  int iter = 0;                                         \
                                                        \
  while((criteria) && iter < maxiter)                   \
    {                                                   \
      net_sim_run(s);                                   \
      net_sim_advance(s, net_sim_next(s));              \
      iter++;                                           \
    }                                                   \
  sput_fail_unless(!(criteria), "!criteria at end");    \
 } while(0)

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

int hcp_io_get_hwaddrs(unsigned char *buf, int buf_left)
{
  return 0;
}

void hcp_io_schedule(hcp o, int msecs)
{
  net_node node = container_of(o, net_node_s, n);
  net_sim s = node->s;
  hnetd_time_t wt = s->now + msecs;

  sput_fail_unless(wt >= s->now, "should be present or future");
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

  if (is_multicast)
    s->sent_multicast++;
  else
    s->sent_unicast++;
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
          m->src = l->address;
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
  hcp_link l1;
  hcp_link l2;

  net_sim_init(&s);
  n1 = net_sim_find_hcp(&s, "n1");
  n2 = net_sim_find_hcp(&s, "n2");
  l1 = net_sim_hcp_find_link(n1, "eth0");
  l2 = net_sim_hcp_find_link(n2, "eth1");
  sput_fail_unless(avl_is_empty(&l1->neighbors.avl), "no l1 neighbors");
  sput_fail_unless(avl_is_empty(&l2->neighbors.avl), "no l2 neighbors");

  /* connect l1+l2 -> should converge at some point */
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);
  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));

  sput_fail_unless(n1->nodes.avl.count == 2, "n1 nodes == 2");
  sput_fail_unless(n2->nodes.avl.count == 2, "n2 nodes == 2");

  /* disconnect on one side (=> unidirectional traffic) => should at
   * some point disappear. */
  net_sim_set_connected(l1, l2, false);
  SIM_WHILE(&s, 1000,
            !avl_is_empty(&l2->neighbors.avl));

  /* n1 will keep getting stuff from n2, so it's sometimes alive,
   * sometimes not.. However, network hashes should be again
   * different. */
  sput_fail_unless(memcmp(&n1->network_hash, &n2->network_hash, HCP_HASH_LEN),
                   "hashes different");

  /* Should also have done the necessary purging of nodes due to lack
   * of reachability.. */
  sput_fail_unless(n2->nodes.avl.count == 1, "n2 nodes == 1");

  net_sim_uninit(&s);
}

/* 11 nodes represented, wired according to how they are wired in the
 * test topology. */
char *nodenames[] = {"cpe", "b1", "b2", "b3", "b4", "b5", "b6",
                     "b7", "b8", "b9", "b10", NULL};
typedef struct {
  int src;
  char *srclink;
  int dst;
  char *dstlink;
} nodeconnection_s;

nodeconnection_s nodeconnections[] = {
  {0, "eth1", 1, "eth0"},
  {0, "eth1", 2, "eth0"},
  {1, "eth1", 5, "eth0"},
  {1, "eth2", 2, "eth1"},
  {1, "eth3", 9, "eth0"},
  {2, "eth2", 3, "eth0"},
  {3, "eth1", 4, "eth0"},
  {4, "eth1", 8, "eth0"},
  {4, "eth1", 9, "eth1"},
  {5, "eth1", 6, "eth0"},
  {6, "eth1", 9, "eth2"},
  {6, "eth2", 7, "eth0"},
  {7, "eth1", 10, "eth0"},
  {8, "eth1", 10, "eth1"},
  {9, "eth3", 10, "eth2"},
};

void hcp_bird14(void)
{
  net_sim_s s;
  int i;
  int num_connections = sizeof(nodeconnections) / sizeof(nodeconnections[0]);

  net_sim_init(&s);
  for (i = 0 ; i < num_connections ; i++)
    {
      nodeconnection_s *c = &nodeconnections[i];
      hcp n1 = net_sim_find_hcp(&s, nodenames[c->src]);
      hcp_link l1 = net_sim_hcp_find_link(n1, c->srclink);
      hcp n2 = net_sim_find_hcp(&s, nodenames[c->dst]);
      hcp_link l2 = net_sim_hcp_find_link(n2, c->dstlink);

      net_sim_set_connected(l1, l2, true);
      net_sim_set_connected(l2, l1, true);
    }

  SIM_WHILE(&s, 10000, !net_sim_is_converged(&s));

  sput_fail_unless(net_sim_find_hcp(&s, "b10")->nodes.avl.count == 11,
                   "b10 enough nodes");

  sput_fail_unless(s.now - s.start < 6000, "should converge in minute");

  sput_fail_unless(s.sent_multicast < 500, "with 'few' multicast");

  sput_fail_unless(s.sent_unicast < 2000, "with 'few' unicast");

  net_sim_uninit(&s);
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hcp_net"); /* optional */
  sput_run_test(hcp_two);
  sput_run_test(hcp_bird14);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
