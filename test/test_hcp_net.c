/*
 * $Id: test_hcp_net.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 10:41:56 2013 mstenber
 * Last modified: Tue Dec  3 13:27:49 2013 mstenber
 * Edit time:     265 min
 *
 */

/*
 * This is a variant of hcp test suite, which replaces the hcp_io code
 * with a fake network. The fake network can be dynamically
 * configured, and basically contains UNIDIRECTIONAL "propagate from X
 * to Y" configuration entries that can change dynamically over the
 * time of the testcase.
 */

#ifdef L_LEVEL
#undef L_LEVEL
#endif /* L_LEVEL */

#define L_LEVEL 5

#include "hcp.c"
#include "hcp_proto.c"
#include "hcp_timeout.c"
#include "sput.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/*********************************************** Fake network infrastructure */

hnetd_time_t now_time;

#define MAXIMUM_PROPAGATION_DELAY 100
#define MESSAGE_PROPAGATION_DELAY (random() % MAXIMUM_PROPAGATION_DELAY + 1)

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

  bool assume_bidirectional_reachability;

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
  s->start = s->now = 12345678901234;
}

bool net_sim_is_converged(net_sim s)
{
  net_node n, n2;
  struct list_head *p, *p2;
  bool first = true;
  hcp_hash h = NULL;
  hcp_node hn;

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
        {
          L_DEBUG("not converged, network hash mismatch %llx <> %llx",
                  hcp_hash64(h), hcp_hash64(&n->n.network_hash));
          s->not_converged_count++;
          return false;
        }
    }
  list_for_each(p, &s->nodes)
    {
      n = container_of(p, net_node_s, h);
      list_for_each(p2, &s->nodes)
        {
          n2 = container_of(p2, net_node_s, h);
          /* Make sure that the information about other node _is_ valid */
          hn = hcp_find_node_by_hash(&n->n,
                                     &n2->n.own_node->node_identifier_hash,
                                     false);
          sput_fail_unless(hn, "hcp_find_node_by_hash failed");
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
  n->n.assume_bidirectional_reachability = s->assume_bidirectional_reachability;
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

  L_DEBUG("connection %p -> %p %s", l1, l2, enabled ? "on" : "off");
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

void net_sim_remove_node(net_sim s, net_node node)
{
  struct list_head *p, *pn;
  hcp o = &node->n;

  /* Remove from neighbors */
  list_for_each_safe(p, pn, &s->neighs)
    {
      net_neigh n = container_of(p, net_neigh_s, h);
      if (n->src->hcp == o || n->dst->hcp == o)
        {
          list_del(&n->h);
          free(n);
        }
    }

  /* Remove from messages */
  list_for_each_safe(p, pn, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      if (m->l->hcp == o)
        {
          list_del(&m->h);
          free(m->buf);
          free(m);
        }
    }

  /* Remove from list of nodes */
  list_del(&node->h);
  free(node->name);
  hcp_uninit(&node->n);
  free(node);
}

void net_sim_remove_node_by_name(net_sim s, const char *name)
{
  hcp o = net_sim_find_hcp(s, name);
  net_node node = container_of(o, net_node_s, n);
  sput_fail_unless(o, "net_sim_find_hcp");
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
  L_DEBUG("time = %lld", (long long int) (t - s->start));
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
        case HCP_T_NODE_DATA:
          sanity_check_buf(tlv_data(a), tlv_len(a));
          break;
        }
    }
  sput_fail_unless(ok, "ordering error");

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

  sanity_check_buf(buf, len);
  if (is_multicast)
    s->sent_multicast++;
  else
    {
      s->sent_unicast++;
      s->last_unicast_sent = s->now;
    }
  list_for_each(p, &s->neighs)
    {
      net_neigh n = container_of(p, net_neigh_s, h);

      if (n->src == l
          && (is_multicast
              || memcmp(&n->dst->address, dst, sizeof(*dst)) == 0))
        {
#if L_LEVEL >= 7
          net_node node2 = container_of(n->dst->hcp, net_node_s, n);
#endif /* L_LEVEL >= 7 */
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
          L_DEBUG("sendto: %s/%s -> %s/%s (%d bytes %s)",
                  node->name, l->ifname, node2->name, n->dst->ifname, (int)len,
                  is_multicast ? "multicast" : "unicast");
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

static void handle_connections(net_sim s,
                               nodeconnection_s *c,
                               int n_conns)
{
  int i;

  for (i = 0 ; i < n_conns ; i++)
    {
      hcp n1 = net_sim_find_hcp(s, nodenames[c->src]);
      hcp_link l1 = net_sim_hcp_find_link(n1, c->srclink);
      hcp n2 = net_sim_find_hcp(s, nodenames[c->dst]);
      hcp_link l2 = net_sim_hcp_find_link(n2, c->dstlink);

      net_sim_set_connected(l1, l2, true);
      net_sim_set_connected(l2, l1, true);
      c++;
    }
}

static void raw_bird14(net_sim s)
{
  int num_connections = sizeof(nodeconnections) / sizeof(nodeconnections[0]);

  handle_connections(s, &nodeconnections[0], num_connections);

  SIM_WHILE(s, 1000, !net_sim_is_converged(s));

  sput_fail_unless(net_sim_find_hcp(s, "b10")->nodes.avl.count == 11,
                   "b10 enough nodes");

  sput_fail_unless(s->now - s->start < 10 * HNETD_TIME_PER_SECOND,
                   "should converge in 10 seconds");

  sput_fail_unless(s->sent_multicast < 500, "with 'few' multicast");

  sput_fail_unless(s->sent_unicast < 1000, "with 'few' unicast");

  net_sim_remove_node_by_name(s, nodenames[0]);

  /* Re-add the node */
  (void)net_sim_find_hcp(s, nodenames[0]);

  handle_connections(s, &nodeconnections[0], 2); /* Two first ones are needed */

  SIM_WHILE(s, 1000, !net_sim_is_converged(s));

  /* Then, simulate network for a while, keeping eye on how often it's
   * NOT converged. */
  int converged_count = s->converged_count;
  int not_converged_count = s->not_converged_count;
  int sent_unicast = s->sent_unicast;
  hnetd_time_t convergence_time = s->now;

  SIM_WHILE(s, 1000, !net_sim_is_converged(s) || iter < 900);
  L_NOTICE("unicasts sent:%d after convergence, last %lld ms after convergence",
           s->sent_unicast - sent_unicast, s->last_unicast_sent - convergence_time);
#if 0
  /* As we do reachability checking, this isn't valid.. unfortunately. */
  sput_fail_unless((s->sent_unicast - sent_unicast) < 50,
                   "did not send (many) unicasts");
#endif /* 0 */
  sput_fail_unless(s->not_converged_count == not_converged_count,
                   "should stay converged");
  sput_fail_unless(s->converged_count >= 900 + converged_count,
                   "converged count rising");
}

void hcp_bird14()
{
  net_sim_s s;

  net_sim_init(&s);
  raw_bird14(&s);
  net_sim_uninit(&s);
}

void hcp_bird14_bidir()
{
  net_sim_s s;

  net_sim_init(&s);
  s.assume_bidirectional_reachability = true;
  raw_bird14(&s);
  net_sim_uninit(&s);
}

static void raw_hcp_tube(unsigned int num_nodes)
{
  /* A LOT of routers connected in a tube (R1 R2 R3 .. RN). */
  unsigned int i;
  net_sim_s s;

  net_sim_init(&s);
  for (i = 0 ; i < num_nodes-1 ; i++)
    {
      char buf[128];

      sprintf(buf, "node%d", i);
      hcp n1 = net_sim_find_hcp(&s, buf);

      sprintf(buf, "node%d", i+1);
      hcp n2 = net_sim_find_hcp(&s, buf);

      hcp_link l1 = net_sim_hcp_find_link(n1, "down");
      hcp_link l2 = net_sim_hcp_find_link(n2, "up");
      net_sim_set_connected(l1, l2, true);
      net_sim_set_connected(l2, l1, true);
    }
  SIM_WHILE(&s, 10000, !net_sim_is_converged(&s));

  sput_fail_unless(net_sim_find_hcp(&s, "node0")->nodes.avl.count == num_nodes,
                   "enough nodes");

  net_sim_uninit(&s);
}

void hcp_tube_small(void)
{
  raw_hcp_tube(5);
}

void hcp_tube_beyond_multicast(void)
{
  raw_hcp_tube(1400 / (HCP_HASH_LEN * 2 + TLV_SIZE));
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hcp_net", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hcp_net"); /* optional */
  sput_run_test(hcp_two);
  sput_run_test(hcp_bird14);
  sput_run_test(hcp_bird14_bidir);
  sput_run_test(hcp_tube_small);
  sput_run_test(hcp_tube_beyond_multicast);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
