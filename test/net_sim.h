/*
 * $Id: net_sim.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Fri Dec  6 18:48:08 2013 mstenber
 * Last modified: Mon Jun 15 13:26:32 2015 mstenber
 * Edit time:     413 min
 *
 */

#ifndef NET_SIM_H
#define NET_SIM_H

#include "dncp_i.h"
#include "hncp_i.h"
#include "hncp_pa.h"
#include "hncp_sd.h"
#include "hncp_link.h"
#include "hncp_multicast.h"
#include "sput.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* Use the faked interfaces */
#include "fake_iface.h"

/* We leverage the fake timers and other stuff in fake_uloop. */
#include "fake_uloop.h"

/* iface_* functions from smock queue */
#include "smock.h"

/* hncp_run and friends */
#include "fake_fork_exec.h"

/* Logging stuff for tests */
#include "fake_log.h"

#ifdef L_PREFIX
#undef L_PREFIX
#endif /* L_PREFIX */
#define L_PREFIX ""

/* This is abstraction that can be used to play with multiple HNCP
 * instances; no separate C module provided just due to
 * laziness. Moved from test_hncp_net (as test_hncp_pa needs similar
 * code but it has to be separate test binary due to different
 * interests in stubbed interfaces) */

#ifndef MAXIMUM_PROPAGATION_DELAY
#define MAXIMUM_PROPAGATION_DELAY 100
#endif /* !MAXIMUM_PROPAGATION_DELAY */
#if MAXIMUM_PROPAGATION_DELAY > 0
#define MESSAGE_PROPAGATION_DELAY (random() % MAXIMUM_PROPAGATION_DELAY + 1)
#else
#define MESSAGE_PROPAGATION_DELAY 1
#endif

#ifndef MESSAGE_LOSS_CHANCE
/* Percentage chance of losing a message in transit. */
#define MESSAGE_LOSS_CHANCE 0

/* Note: some of the test topologies (notably, the 'huge' tube) start
 * breaking if any message loss happens. That is not really
 * unexpected, as given 1% chance of message drop, one in 1e4
 * keepalives is dropped twice, and neighbor is lost. That leads to
 * funny churn in the tube testcases. TBD: Should the message loss
 * chance be made net_sim parameter instead so individual test cases
 * could test this? */

#if MESSAGE_LOSS_CHANCE > 0
#define MESSAGE_WAS_LOST (random() % 100 <= MESSAGE_LOSS_CHANCE)
#else
#define MESSAGE_WAS_LOST false
#endif /* MESSAGE_LOSS_CHANCE > 0 */
#endif /* !MESSAGE_LOSS_CHANCE */

typedef struct {
  struct list_head lh;

  dncp_ep ep;
  struct sockaddr_in6 src, dst;
  void *buf;
  size_t len;

  /* When is it delivered? */
  struct uloop_timeout deliver_to;
} net_msg_s, *net_msg;

typedef struct {
  struct list_head lh;

  dncp_ep src;
  dncp_ep dst;
} net_neigh_s, *net_neigh;

typedef struct {
  struct list_head lh;
  struct net_sim_t *s;
  char *name;
  hncp_s h;
  dncp d;
  struct hncp_link *link;
#ifndef DISABLE_HNCP_PA
  hncp_pa pa;
#endif /* !DISABLE_HNCP_PA */
#ifndef DISABLE_HNCP_MULTICAST
  hncp_multicast multicast;
#endif /* !DISABLE_HNCP_MULTICAST */
  hncp_sd sd;

  /* Received messages (timeout has moved them from global list to
   * ours readable list) */
  struct list_head messages;

  /* When is it scheduled to run? */
  struct uloop_timeout run_to;

  /* Debug subscriber we use just to make sure there are no changes
   * when the topology should be stable. */
  dncp_subscriber_s debug_subscriber;

  struct list_head iface_users;
} net_node_s, *net_node;

typedef struct net_sim_t {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;

  bool disable_link_auto_address;
  bool disable_sd;
  bool disable_pa;
  bool disable_multicast;

  int node_count;
  bool add_neighbor_is_error;
  bool del_neighbor_is_error;
  hnetd_time_t start;

  int sent_unicast;
  hnetd_time_t last_unicast_sent;
  int sent_multicast;

  int converged_count;
  int not_converged_count;

  bool use_global_ep_ids;
  int next_free_ep_id;

  bool accept_time_errors;

  bool fake_unicast;
  bool fake_unicast_is_reliable_stream;

} net_sim_s, *net_sim;

static struct list_head net_sim_interfaces = LIST_HEAD_INIT(net_sim_interfaces);

void net_sim_init(net_sim s)
{
  memset(s, 0, sizeof(*s));
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
  uloop_init();
  s->start = hnetd_time();
  s->next_free_ep_id = 100;
}

int net_sim_dncp_tlv_type_count(dncp o, int type)
{
  int c = 0;
  dncp_node n;
  struct tlv_attr *a;

  dncp_for_each_node(o, n)
    dncp_node_for_each_tlv_with_type(n, a, type)
    c++;
  L_DEBUG("net_sim_dncp_tlv_type_count %d -> %d", type, c);
  return c;
}

bool net_sim_is_converged(net_sim s)
{
  net_node n, n2, fn = NULL;
  bool first = true;
  dncp_node hn;
  int acceptable_offset = MAXIMUM_PROPAGATION_DELAY * (s->node_count - 1);
#if L_LEVEL >= 7
  /* Dump # of nodes in each node */
  char *buf = alloca(4 * s->node_count), *c = buf;
  list_for_each_entry(n, &s->nodes, lh)
    {
      int count = 0;

      dncp_for_each_node(n->d, hn)
        count++;
      c += sprintf(c, "%d ", count);
    }
  L_DEBUG("net_sim_is_converged: %s", buf);
#endif /* L_LEVEL >= 7 */

  list_for_each_entry(n, &s->nodes, lh)
    {
      if (n->d->network_hash_dirty)
        return false;
      if (first)
        {
          fn = n;
          first = false;
          continue;
        }
      if (memcmp(&fn->d->network_hash, &n->d->network_hash, HNCP_HASH_LEN))
        {
          L_DEBUG("network hash mismatch %s<>%s [%llx <> %llx]",
                  fn->name, n->name,
                  dncp_hash64(&fn->d->network_hash),
                  dncp_hash64(&n->d->network_hash));
          s->not_converged_count++;
          return false;
        }
    }
  list_for_each_entry(n, &s->nodes, lh)
    {
      list_for_each_entry(n2, &s->nodes, lh)
        {
          /* Make sure that the information about other node _is_ valid */
          hn = dncp_find_node_by_node_id(n->d, &n2->d->own_node->node_id, false);
          if (!hn)
            {
              L_DEBUG("unable to find other node hash - %s -> %s",
                      n->name, n2->name);
              return false;
            }
          if (memcmp(&n2->d->own_node->node_data_hash,
                     &hn->node_data_hash, HNCP_HASH_LEN))
            {
              L_DEBUG("node data hash mismatch w/ network hash in sync %s @%s",
                      n2->name, n->name);
              return false;
            }
          if (!s->accept_time_errors
              && llabs(n2->d->own_node->origination_time
                       - hn->origination_time) > acceptable_offset)
            {
              L_DEBUG("origination time mismatch at "
                      "%s: %lld !=~ %lld for %s [update number %d]",
                      n->name,
                      (long long) hn->origination_time,
                      (long long) n2->d->own_node->origination_time,
                      n2->name,
                      hn->update_number);
              s->not_converged_count++;
              return false;
            }
        }
    }

  s->converged_count++;
  return true;
}

bool net_sim_is_busy(net_sim s)
{
  net_node n;

  if (!list_empty(&s->messages))
    {
      L_DEBUG("net_sim_is_busy: messages pending");
      return true;
    }
  list_for_each_entry(n, &s->nodes, lh)
    {
      if (n->d->immediate_scheduled)
        {
          L_DEBUG("net_sim_is_busy: immediate scheduled");
          return true;
        }
#ifndef DISABLE_HNCP_SD
      if (!s->disable_sd && hncp_sd_busy(n->sd))
        {
          L_DEBUG("net_sim_is_busy: pending sd");
          return true;
        }
#endif /* !DISABLE_HNCP_SD */
#ifndef DISABLE_HNCP_MULTICAST
      if (!s->disable_multicast && hncp_multicast_busy(n->multicast))
        {
          L_DEBUG("net_sim_is_busy: pending multicast");
          return true;
        }
#endif /* !DISABLE_HNCP_MULTICAST */
    }
  return false;
}



void net_sim_local_tlv_cb(dncp_subscriber sub,
                                struct tlv_attr *tlv, bool add)
{
#if MESSAGE_LOSS_CHANCE < 1
  net_node n = container_of(sub, net_node_s, debug_subscriber);
  net_sim s = n->s;

  if (tlv_id(tlv) == DNCP_T_NEIGHBOR)
    {
      sput_fail_unless(!add || !s->add_neighbor_is_error, "undesired add");
      sput_fail_unless(add || !s->del_neighbor_is_error, "undesired del");
    }
#endif /* MESSAGE_LOSS_CHANCE < 1 */
}

hncp net_sim_find_hncp(net_sim s, const char *name)
{
  net_node n;
  bool r;

  list_for_each_entry(n, &s->nodes, lh)
    {
      if (strcmp(n->name, name) == 0)
        return &n->h;
    }

  n = calloc(1, sizeof(*n));
  current_iface_users = &n->iface_users;
  n->name = strdup(name);
  sput_fail_unless(n, "calloc net_node");
  sput_fail_unless(n->name, "strdup name");
  n->s = s;
  r = hncp_init(&n->h);
  if (s->fake_unicast)
    n->h.ext.conf.per_ep.unicast_only = true;
  if (s->fake_unicast_is_reliable_stream)
    n->h.ext.conf.per_ep.unicast_is_reliable_stream = true;
  n->d = hncp_get_dncp(&n->h);
  sput_fail_unless(r, "hncp_init");

  if (!r)
    {
    fail:
      current_iface_users = NULL;
      return NULL;
    }
  list_add_tail(&n->lh, &s->nodes);
  INIT_LIST_HEAD(&n->messages);
  INIT_LIST_HEAD(&n->iface_users);
  if (!(n->link = hncp_link_create(n->d, NULL)))
    goto fail;
#ifndef DISABLE_HNCP_PA
  /* Glue it to pa */
  if (!s->disable_pa && !(n->pa = hncp_pa_create(&n->h, n->link)))
    goto fail;
#endif /* !DISABLE_HNCP_PA */
#ifndef DISABLE_HNCP_SD
  static hncp_sd_params_s sd_params = {
    .dnsmasq_script = "s-dnsmasq",
    .dnsmasq_bonus_file = "/tmp/dnsmasq.conf",
    .ohp_script = "s-ohp",
    .pcp_script = "s-pcp",
  };

  /* Add SD support */
  if (!s->disable_sd)
    if (!(n->sd = hncp_sd_create(&n->h, &sd_params, NULL)))
      goto fail;

#endif /* !DISABLE_HNCP_SD */
#ifndef DISABLE_HNCP_MULTICAST
  static hncp_multicast_params_s multicast_params = {
    .multicast_script = "s-mc"
  };
  if (!s->disable_multicast)
    if (!(n->multicast = hncp_multicast_create(&n->h, &multicast_params)))
      return NULL;
#endif /* !DISABLE_HNCP_MULTICAST */
  n->debug_subscriber.local_tlv_change_cb = net_sim_local_tlv_cb;
  s->node_count++;
  dncp_subscribe(n->d, &n->debug_subscriber);
  L_DEBUG("[%s] %s net_sim_find_hncp added",
          DNCP_NODE_REPR(n->d->own_node), n->name);
  current_iface_users = NULL;
  return &n->h;
}

dncp net_sim_find_dncp(net_sim s, const char *name)
{
  return hncp_get_dncp(net_sim_find_hncp(s, name));
}

dncp_ep net_sim_dncp_find_ep_by_name(dncp o, const char *name)
{
  hncp h = container_of(o->ext, hncp_s, ext);
  net_node n = container_of(h, net_node_s, h);
  dncp_ep ep = dncp_find_ep_by_name(o, name);

  if (!ep)
    return NULL;

  if (dncp_ep_is_enabled(ep))
    return ep;

  /* Initialize the address - in rather ugly way. We just hash
   * ifname + xor that with our own hash. The result should be
   * highly unique still. */
  dncp_hash_s h1, h2;
  unsigned char buf[16];
  int i;
  hncp_ep hep = dncp_ep_get_ext_data(ep);

  o->ext->cb.hash(name, strlen(name), &h1);
  o->ext->cb.hash(n->name, strlen(n->name), &h2);

  int bytes = HNCP_HASH_LEN;
  if (bytes > 8)
    bytes = 8;
  memset(buf, 0, sizeof(buf));
  for (i = 0; i < bytes; i++)
    buf[i+8] = h1.buf[i] ^ h2.buf[i];
  buf[0] = 0xFE;
  buf[1] = 0x80;
  /* 2 .. 7 left 0 always */
  hncp_set_ipv6_address(h, name, (struct in6_addr *)buf);
  hep->has_ipv6_address = !n->s->disable_link_auto_address;
  /* Internally we use the ipv6 address even if it is not
   * officially set(!). Beautiful.. */
  /* Override the ep_id to be unique. */
  if (n->s->use_global_ep_ids)
    {
      dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
      l->ep_id = n->s->next_free_ep_id++;
    }

  /* Note that the interface is ready. */
  dncp_ext_ep_ready(ep, true);

  /* Give callback about it to iface users. */
  net_sim_node_iface_cb(n, cb_intiface, name, true);
  return ep;
}

void net_sim_set_connected(dncp_ep ep1, dncp_ep ep2, bool enabled)
{
  dncp_ep_i l1 = container_of(ep1, dncp_ep_i_s, conf);
  dncp o = l1->dncp;
  hncp h = container_of(o->ext, hncp_s, ext);
  net_node node = container_of(h, net_node_s, h);
  net_sim s = node->s;
  net_neigh n;
  hncp_ep h1 = dncp_ep_get_ext_data(ep1);
  hncp_ep h2 = dncp_ep_get_ext_data(ep2);


  if (enabled)
    {
      /* Make sure it's not there already */
      list_for_each_entry(n, &s->neighs, lh)
        if (n->src == ep1 && n->dst == ep2)
          return;

      /* Add node */
      n = calloc(1, sizeof(*n));

      sput_fail_unless(n, "calloc net_neigh");
      n->src = ep1;
      n->dst = ep2;
      list_add(&n->lh, &s->neighs);
    }
  else
    {
      /* Remove node */
      list_for_each_entry(n, &s->neighs, lh)
        {
          if (n->src == ep1 && n->dst == ep2)
            {
              list_del(&n->lh);
              free(n);
              break;
            }
        }
    }
  if (s->fake_unicast || s->fake_unicast_is_reliable_stream)
    {
      struct sockaddr_in6 a1, a2;

      sockaddr_in6_set(&a1, &h1->ipv6_address, HNCP_PORT);
      sockaddr_in6_set(&a2, &h2->ipv6_address, HNCP_PORT);
      dncp_ext_ep_peer_state(&l1->conf, &a1, &a2, enabled);
      dncp_ext_ep_peer_state(&l1->conf, &a2, &a1, enabled);
    }
}

void net_sim_remove_node(net_sim s, net_node node)
{
  struct list_head *p, *pn;
  dncp o = node->d;
  net_neigh n, nn;

  /* Remove from neighbors */
  list_for_each_entry_safe(n, nn, &s->neighs, lh)
    {
      if (dncp_ep_get_dncp(n->src) == o || dncp_ep_get_dncp(n->dst) == o)
        {
          list_del(&n->lh);
          free(n);
        }
    }

  /* Remove from messages */
  list_for_each_safe(p, pn, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, lh);
      if (dncp_ep_get_dncp(m->ep) == o)
        {
          uloop_timeout_cancel(&m->deliver_to);
          list_del(&m->lh);
          free(m->buf);
          free(m);
        }
    }

#ifndef DISABLE_HNCP_SD
  /* Get rid of sd data structure */
  if (!s->disable_sd)
    hncp_sd_destroy(node->sd);
#endif /* !DISABLE_HNCP_SD */

#ifndef DISABLE_HNCP_PA
  /* Kill glue (has to be done _after_ hncp_uninit). */
  if (!s->disable_pa)
    hncp_pa_destroy(node->pa);
#endif /* !DISABLE_HNCP_PA */
#ifndef DISABLE_HNCP_MULTICAST
  if (!s->disable_multicast)
    hncp_multicast_destroy(node->multicast);
#endif /* !DISABLE_HNCP_MULTICAST */

  hncp_link_destroy(node->link);

  /* Remove from list of nodes */
  list_del(&node->lh);
  free(node->name);

  hncp_uninit(&node->h);

  uloop_timeout_cancel(&node->run_to);

  free(node);
}

void net_sim_remove_node_by_name(net_sim s, const char *name)
{
  hncp h = net_sim_find_hncp(s, name);
  sput_fail_unless(h, "net_sim_find_hncp");
  net_node node = container_of(h, net_node_s, h);
  net_sim_remove_node(s, node);
}

void net_sim_uninit(net_sim s)
{
  struct list_head *p, *pn;
  int c = 0;

  s->del_neighbor_is_error = false;
  list_for_each_safe(p, pn, &s->nodes)
    {
      net_node node = container_of(p, net_node_s, lh);
      net_sim_remove_node(s, node);
      c++;
    }
  L_NOTICE("#nodes:%d elapsed:%.2fs unicasts:%d multicasts:%d",
           c,
           (float)(hnetd_time() - s->start) / HNETD_TIME_PER_SECOND,
           s->sent_unicast, s->sent_multicast);
  sput_fail_unless(list_empty(&s->neighs), "no neighs");
  sput_fail_unless(list_empty(&s->messages), "no messages");
}

void net_sim_advance(net_sim s, hnetd_time_t t)
{
  set_hnetd_time(t);
  L_DEBUG("time = %lld", (long long int) (t - s->start));
}

#define SIM_WHILE(s, maxiter, criteria)                 \
  do {                                                  \
    int iter = 0;                                       \
                                                        \
    sput_fail_unless((criteria), "criteria at start");  \
    while (iter < maxiter && fu_loop(1) == 0)           \
      {                                                 \
        while (fu_poll());                              \
        if (!(criteria))                                \
          break;                                        \
        iter++;                                         \
      }                                                 \
    sput_fail_unless(!(criteria), "!criteria at end");  \
  } while(0)

void net_sim_populate_iface_next(net_node n)
{
  static char dummybuf[12345];
  struct iface *i = (struct iface *)dummybuf;
  dncp_ep ep;

  dncp_for_each_ep(n->d, ep)
    {
      *i = default_iface;
      strcpy(i->ifname, ep->ifname);
      smock_push("iface_next", i);
      i = (void *)i + sizeof(struct iface) + strlen(ep->ifname) + 1;
    }
  smock_push("iface_next", NULL);
}

net_node net_sim_node_from_dncp(dncp d)
{
  hncp h = container_of(d->ext, hncp_s, ext);
  return container_of(h, net_node_s, h);
}

/************************************************* Mocked interface - hncp_io */

static void _timeout(struct uloop_timeout *t)
{
  net_node node = container_of(t, net_node_s, run_to);
  L_DEBUG("%s: dncp_run", node->name);
  dncp_ext_timeout(node->d);
}

static void _schedule_timeout(dncp_ext ext, int msecs)
{
  hncp h = container_of(ext, hncp_s, ext);
  net_node node = container_of(h, net_node_s, h);

  sput_fail_unless(msecs >= 0, "should be present or future");
  node->run_to.cb = _timeout;
  uloop_timeout_set(&node->run_to, msecs);
}

static ssize_t
_recv(dncp_ext ext,
      dncp_ep *ep,
      struct sockaddr_in6 **src,
      struct sockaddr_in6 **dst,
      int *flags,
      void *buf, size_t len)
{
  hncp h = container_of(ext, hncp_s, ext);
  dncp o = h->dncp;
  net_node node = container_of(h, net_node_s, h);
  net_msg m;

  list_for_each_entry(m, &node->messages, lh)
    {
      int s = m->len > len ? len : m->len;
      *ep = dncp_find_ep_by_name(o, m->ep->ifname);
      static struct sockaddr_in6 ret_src, ret_dst;
      ret_src = m->src;
      ret_dst = m->dst;
      *src = &ret_src;
      int f = 0;
      if (IN6_IS_ADDR_MULTICAST(&ret_dst.sin6_addr))
        *dst = NULL;
      else
        {
          *dst = &ret_dst;
          if (IN6_IS_ADDR_LINKLOCAL(&ret_dst.sin6_addr))
            f |= DNCP_RECV_FLAG_DST_LINKLOCAL;
        }
      if (IN6_IS_ADDR_LINKLOCAL(&ret_src.sin6_addr))
        f |= DNCP_RECV_FLAG_SRC_LINKLOCAL;
      *flags = f;
      memcpy(buf, m->buf, s);
      L_DEBUG("%s/%s: _io_recv %d bytes", node->name, m->ep->ifname, s);
      list_del(&m->lh);
      free(m->buf);
      free(m);
      return s;
    }
  return - 1;
}

static void
sanity_check_buf(dncp o, void *buf, size_t len, int depth)
{
  struct tlv_attr *a, *last = NULL;
  int a_len;
  int last_len;
  bool ok = true;
  size_t nhs = sizeof(dncp_t_node_state_s) + DNCP_NI_LEN(o) + DNCP_HASH_LEN(o);

  tlv_for_each_in_buf(a, buf, len)
    {
      a_len = tlv_pad_len(a);
      if (last)
        {
          if (depth
              && memcmp(last, a, last_len < a_len ? last_len : a_len) >= 0)
            {
              ok = false;
              L_ERR("ordering error @depth %d - %s >= %s",
                    depth, TLV_REPR(last), TLV_REPR(a));
            }
        }
      last = a;
      last_len = a_len;
      /* XXX - some better way to determine recursion? */
      switch (tlv_id(a))
        {
        case DNCP_T_NODE_STATE:
          sanity_check_buf(o, tlv_data(a)+nhs, tlv_len(a)-nhs, depth + 1);
          break;
        case HNCP_T_EXTERNAL_CONNECTION:
          sanity_check_buf(o, tlv_data(a), tlv_len(a), depth + 1);
          break;
        }
    }
  sput_fail_unless(ok, "tlv ordering valid");

}


static void _message_deliver_cb(struct uloop_timeout *t)
{
  net_msg m = container_of(t, net_msg_s, deliver_to);
  dncp o = dncp_ep_get_dncp(m->ep);
  hncp h = container_of(o->ext, hncp_s, ext);
  net_node node = container_of(h, net_node_s, h);

  list_del(&m->lh);
  list_add(&m->lh, &node->messages);
  dncp_ext_readable(node->d);
}

static void
_send_one(net_sim s, void *buf, size_t len, dncp_ep sl, dncp_ep dl,
          const struct sockaddr_in6 *dst)
{
  if (MESSAGE_WAS_LOST)
    return;
  net_msg m = calloc(1, sizeof(*m));
  hncp_ep shl = dncp_ep_get_ext_data(sl);

  sput_fail_unless(m, "calloc neigh");
  m->ep = dl;
  m->buf = malloc(len);
  sput_fail_unless(m->buf, "malloc buf");
  memcpy(m->buf, buf, len);
  m->len = len;
  memset(&m->src, 0, sizeof(m->src));
  m->src.sin6_family = AF_INET6;
  m->src.sin6_addr = shl->ipv6_address;
  m->src.sin6_scope_id = dncp_ep_get_id(dl);
  m->dst = *dst;
  list_add(&m->lh, &s->messages);
  m->deliver_to.cb = _message_deliver_cb;
  uloop_timeout_set(&m->deliver_to, MESSAGE_PROPAGATION_DELAY);

#if L_LEVEL >= 7
  hncp h1 = container_of(dncp_ep_get_dncp(sl)->ext, hncp_s, ext);
  net_node node1 = container_of(h1, net_node_s, h);
  hncp h2 = container_of(dncp_ep_get_dncp(dl)->ext, hncp_s, ext);
  net_node node2 = container_of(h2, net_node_s, h);
  bool is_multicast = memcmp(&dst->sin6_addr, &h1->multicast_address,
                             sizeof(h1->multicast_address)) == 0;
  L_DEBUG("_send_one: %s/%s -> %s/%s (%d bytes %s)",
          node1->name, sl->ifname, node2->name, dl->ifname, (int)len,
          is_multicast ? "multicast" : "unicast");
#endif /* L_LEVEL >= 7 */
}

static void
_send(dncp_ext ext, dncp_ep ep,
      struct sockaddr_in6 *src,
      struct sockaddr_in6 *dst,
      void *buf, size_t len)
{
  hncp h = container_of(ext, hncp_s, ext);
  dncp o = h->dncp;
  net_node node = container_of(h, net_node_s, h);
  net_sim s = node->s;
  struct sockaddr_in6 rdst;

  if (!dst)
    {
      if (s->fake_unicast)
        return;
      sockaddr_in6_set(&rdst, &h->multicast_address, HNCP_PORT);
    }
  else
    rdst = *dst;
  dst = &rdst;

  /* Cheat and just get ep_id from the struct; we are unlikely to have
   * real matching system interfaces after all. */
  dncp_ep_i lo = container_of(ep, dncp_ep_i_s, conf);
  dst->sin6_scope_id = lo->ep_id;

  dncp_ep ep2 = dncp_find_ep_by_id(o, dst->sin6_scope_id);
  sput_fail_unless(ep2, "sin6_scope_id lookup ok");
  sput_fail_unless(ep == ep2, "same returned ep");

  bool is_multicast = memcmp(&dst->sin6_addr, &h->multicast_address,
                             sizeof(h->multicast_address)) == 0;
  net_neigh n;

  L_DEBUG("_io_send: %s -> " SA6_F,
          is_multicast ? "multicast" : "unicast", SA6_D(dst));
  sanity_check_buf(o, buf, len, 0);
  if (is_multicast)
    {
      s->sent_multicast++;
      sput_fail_unless(len <= HNCP_MAXIMUM_MULTICAST_SIZE,
                       "not too long multicast");
    }
  else
    {
      s->sent_unicast++;
      s->last_unicast_sent = hnetd_time();
    }
  int sent = 0;
  list_for_each_entry(n, &s->neighs, lh)
    {
      hncp_ep dhl = dncp_ep_get_ext_data(n->dst);
      if (n->src == ep
          && (is_multicast
              || (memcmp(&dhl->ipv6_address, &dst->sin6_addr,
                         sizeof(dst->sin6_addr)) == 0)))
        {
          _send_one(s, buf, len, n->src, n->dst, dst);
          sent++;
        }
    }
  /* Loop at self too, just for fun. */
  if (is_multicast)
    _send_one(s, buf, len, ep, ep, dst);
  else
    sput_fail_unless(sent <= 1, "unicast must hit only one target");
}

static hnetd_time_t
_get_time(dncp_ext ext)
{
  return hnetd_time();
}

static int
_get_hwaddrs(dncp_ext ext, unsigned char *buf, int buf_left)
{
  hncp h = container_of(ext, hncp_s, ext);
  net_node node = container_of(h, net_node_s, h);
  const char *name = node->name;
  int tocopy = buf_left < (int)strlen(name) ? buf_left : (int)strlen(name);

  memcpy(buf, name, tocopy);
  return tocopy;
}

bool hncp_io_init(hncp h)
{
  h->ext.cb.recv = _recv;
  h->ext.cb.send = _send;
  h->ext.cb.get_hwaddrs = _get_hwaddrs;
  h->ext.cb.get_time = _get_time;
  h->ext.cb.schedule_timeout = _schedule_timeout;
  return true;
}

void hncp_io_uninit(hncp o)
{
  /* nop */
}

bool hncp_io_set_ifname_enabled(hncp h, const char *ifname, bool enabled)
{
  /* Yeah, sure.. */
  return true;
}


#endif /* NET_SIM_H */
