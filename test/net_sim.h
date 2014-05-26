/*
 * $Id: net_sim.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Fri Dec  6 18:48:08 2013 mstenber
 * Last modified: Thu May 22 12:56:40 2014 mstenber
 * Edit time:     127 min
 *
 */

#ifndef NET_SIM_H
#define NET_SIM_H

#include "hncp_i.h"
#include "hncp_pa.h"
#include "hncp_sd.h"
#include "sput.h"

/* We leverage the fake timers and other stuff in fake_uloop. */
#include "fake_uloop.h"

#include "pa_data.c"
#ifdef L_PREFIX
#undef L_PREFIX
#endif /* L_PREFIX */
#define L_PREFIX ""

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

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

typedef struct {
  struct list_head h;

  hncp_link l;
  struct in6_addr src;
  struct in6_addr dst;
  void *buf;
  size_t len;

  /* When is it delivered? */
  struct uloop_timeout deliver_to;
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
  struct pa_data pa_data;
  struct pa_data_user pa_data_user;
#ifndef DISABLE_HNCP_PA
  hncp_glue g;
#endif /* !DISABLE_HNCP_PA */
  hncp_sd sd;
  int updated_eap;
  int updated_edp;

  /* Received messages (timeout has moved them from global list to
   * ours readable list) */
  struct list_head messages;

  /* When is it scheduled to run? */
  struct uloop_timeout run_to;

  /* Debug subscriber we use just to make sure there are no changes
   * when the topology should be stable. */
  hncp_subscriber_s debug_subscriber;

} net_node_s, *net_node;

typedef struct net_sim_t {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;

  bool disable_sd;

  bool should_be_stable_topology;
  hnetd_time_t start;

  int sent_unicast;
  hnetd_time_t last_unicast_sent;
  int sent_multicast;

  int converged_count;
  int not_converged_count;

  bool use_global_iids;
  int next_free_iid;
} net_sim_s, *net_sim;

int pa_update_eap(net_node node, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  const char *ifname, bool to_delete);

int pa_update_eaa(net_node node, const struct in6_addr *addr,
					const struct pa_rid *rid,
					const char *ifname, bool to_delete);

int pa_update_edp(net_node node, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  hnetd_time_t valid_until, hnetd_time_t preferred_until,
                  const void *dhcpv6_data, size_t dhcpv6_len);

void net_sim_pa_dps(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	bool todelete = !!(flags & PADF_DP_TODELETE);
	if (!dp->local && flags) {
		struct pa_edp *edp = container_of(dp, struct pa_edp, dp);
		pa_update_edp(container_of(user, net_node_s, pa_data_user), &dp->prefix,
				&edp->rid, todelete?0:dp->valid_until, todelete?0:dp->preferred_until,
						dp->dhcp_data, dp->dhcp_len);
	}
}

void net_sim_pa_aps(struct pa_data_user *user, struct pa_ap *ap, uint32_t flags)
{
	bool todelete = !!(flags & PADF_DP_TODELETE);
	if(flags) {
		pa_update_eap(container_of(user, net_node_s, pa_data_user),
				&ap->prefix, &ap->rid, ap->iface?ap->iface->ifname:NULL, todelete);
	}
}

void net_sim_pa_aas(struct pa_data_user *user, struct pa_aa *aa, uint32_t flags)
{
	bool todelete = !!(flags & PADF_DP_TODELETE);
	if(flags && !aa->local) {
		struct pa_eaa *eaa = container_of(aa, struct pa_eaa, aa);
		pa_update_eaa(container_of(user, net_node_s, pa_data_user), &aa->address,
				&eaa->rid, eaa->iface?eaa->iface->ifname:NULL, todelete);
	}
}

void net_sim_init(net_sim s)
{
  memset(s, 0, sizeof(*s));
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
  uloop_init();
  s->start = hnetd_time();
  s->next_free_iid = 100;
}

bool net_sim_is_converged(net_sim s)
{
  net_node n, n2;
  bool first = true;
  hncp_hash h = NULL;
  hncp_node hn;

#if L_LEVEL >= 7
  /* Dump # of nodes in each node */
  int n_nodes = 0;
  list_for_each_entry(n, &s->nodes, h)
    n_nodes++;

  char *buf = alloca(4 * n_nodes), *c = buf;
  list_for_each_entry(n, &s->nodes, h)
    {
      int count = 0;

      hncp_for_each_node(&n->n, hn)
        count++;
      c += sprintf(c, "%d ", count);
    }
  L_DEBUG("net_sim_is_converged: %s", buf);
#endif /* L_LEVEL >= 7 */

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
          L_DEBUG("network hash mismatch first<>%s [%llx <> %llx]",
                  n->name,
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
          if (!hn)
            {
              L_DEBUG("unable to find other node hash - %s -> %s",
                      n->name, n2->name);
              return false;
            }
          if (memcmp(&n2->n.own_node->node_data_hash,
                     &hn->node_data_hash, HNCP_HASH_LEN))
            {
              L_DEBUG("node data hash mismatch w/ network hash in sync %s @%s",
                      n2->name, n->name);
              return false;
            }
          if (abs(n2->n.own_node->origination_time -
                  hn->origination_time) > 5000)
            {
              L_DEBUG("origination time mismatch "
                      "%lld !=~ %lld for %s @ %s [update number %d]",
                      (long long) hn->origination_time,
                      (long long) n2->n.own_node->origination_time,
                      n2->name, n->name,
                      hn->update_number);
              s->not_converged_count++;
              return false;
            }
        }
    }

  s->converged_count++;
  return true;
}

void net_sim_local_tlv_callback(hncp_subscriber sub,
                                struct tlv_attr *tlv, bool add)
{
  net_node n = container_of(sub, net_node_s, debug_subscriber);
  net_sim s = n->s;

  if (s->should_be_stable_topology)
    if (tlv_id(tlv) == HNCP_T_NODE_DATA_NEIGHBOR)
      {
        sput_fail_unless(false, "got change when topology stable");
      }
}

hncp net_sim_find_hncp(net_sim s, const char *name)
{
  net_node n;
  bool r;
  static hncp_sd_params_s sd_params = {
    .dnsmasq_script = "/bin/yes",
    .dnsmasq_bonus_file = "/tmp/dnsmasq.conf",
    .ohp_script = "/bin/no"
  };


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
  n->n.io_init_done = true; /* our IO doesn't really need init.. */
  sput_fail_unless(r, "hncp_init");
  if (!r)
    return NULL;
  list_add(&n->h, &s->nodes);
  INIT_LIST_HEAD(&n->messages);
#ifndef DISABLE_HNCP_PA
  memset(&n->pa_data_user, 0, sizeof(struct pa_data_user));
  n->pa_data_user.dps = net_sim_pa_dps;
  n->pa_data_user.aps = net_sim_pa_aps;
  n->pa_data_user.aas = net_sim_pa_aas;
  pa_data_init(&n->pa_data, NULL);
  pa_data_subscribe(&n->pa_data, &n->pa_data_user);
  /* Glue it to pa */
  if (!(n->g = hncp_pa_glue_create(&n->n, &n->pa_data)))
    return NULL;
#endif /* !DISABLE_HNCP_PA */
#ifndef DISABLE_HNCP_SD
  /* Add SD support */
  if (!s->disable_sd)
    if (!(n->sd = hncp_sd_create(&n->n, &sd_params)))
      return NULL;
#endif /* !DISABLE_HNCP_SD */
  n->debug_subscriber.local_tlv_change_callback = net_sim_local_tlv_callback;
  hncp_subscribe(&n->n, &n->debug_subscriber);
  L_DEBUG("[%s] %s net_sim_find_hncp added",
          HNCP_NODE_REPR(n->n.own_node), n->name);
  return &n->n;
}

hncp_link net_sim_hncp_find_link_by_name(hncp o, const char *name)
{
  net_node n = container_of(o, net_node_s, n);
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
      for (i = 0; i < HNCP_HASH_LEN; i++)
        h.buf[i] = h1.buf[i] ^ o->own_node->node_identifier_hash.buf[i];
      h.buf[0] = 0xFE;
      h.buf[1] = 0x80;
      /* Let's pretend it's /64; clear out 2-7 */
      for (i = 2; i < 8; i++)
        h.buf[i] = 0;
      hncp_link_set_ipv6_address(l, (struct in6_addr *)&h);

      /* Override the iid to be unique. */
      if (n->s->use_global_iids)
        l->iid = n->s->next_free_iid++;
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
          uloop_timeout_cancel(&m->deliver_to);
          list_del(&m->h);
          free(m->buf);
          free(m);
        }
    }

  uloop_timeout_cancel(&node->run_to);

  /* Remove from list of nodes */
  list_del(&node->h);
  free(node->name);
  hncp_uninit(&node->n);

#ifndef DISABLE_HNCP_SD
  /* Get rid of sd data structure */
  if (!s->disable_sd)
    hncp_sd_destroy(node->sd);
#endif /* !DISABLE_HNCP_SD */

#ifndef DISABLE_HNCP_PA
  /* Kill glue (has to be done _after_ hncp_uninit). */
  hncp_pa_glue_destroy(node->g);
  pa_data_term(&node->pa_data);
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

static void _node_run_cb(struct uloop_timeout *t)
{
  net_node node = container_of(t, net_node_s, run_to);
  L_DEBUG("%s: hncp_run", node->name);
  hncp_run(&node->n);
}

void hncp_io_schedule(hncp o, int msecs)
{
  net_node node = container_of(o, net_node_s, n);
  sput_fail_unless(msecs >= 0, "should be present or future");
  node->run_to.cb = _node_run_cb;
  uloop_timeout_set(&node->run_to, msecs);
}

ssize_t hncp_io_recvfrom(hncp o, void *buf, size_t len,
                         char *ifname,
                         struct in6_addr *src,
                         struct in6_addr *dst)
{
  net_node node = container_of(o, net_node_s, n);
  net_msg m;

  list_for_each_entry(m, &node->messages, h)
    {
      int s = m->len > len ? len : m->len;
      strcpy(ifname, m->l->ifname);
      *src = m->src;
      *dst = m->dst;
      memcpy(buf, m->buf, s);
      list_del(&m->h);
      free(m->buf);
      free(m);
      L_DEBUG("%s: hncp_io_recvfrom %d bytes", node->name, s);
      return s;
    }
  return - 1;
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


void _message_deliver_cb(struct uloop_timeout *t)
{
  net_msg m = container_of(t, net_msg_s, deliver_to);
  hncp o = m->l->hncp;
  net_node node = container_of(o, net_node_s, n);

  list_del(&m->h);
  list_add(&m->h, &node->messages);
  hncp_poll(&node->n);
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

  sput_fail_unless(m, "calloc neigh");
  m->l = dl;
  m->buf = malloc(len);
  sput_fail_unless(m->buf, "malloc buf");
  memcpy(m->buf, buf, len);
  m->len = len;
  sput_fail_unless(sl->has_ipv6_address, "no ipv6 address?!?");
  m->src = sl->ipv6_address;
  m->dst = *dst;
  list_add(&m->h, &s->messages);
  m->deliver_to.cb = _message_deliver_cb;
  uloop_timeout_set(&m->deliver_to, MESSAGE_PROPAGATION_DELAY);

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
    return - 1;

  sanity_check_buf(buf, len);
  if (is_multicast)
    {
      s->sent_multicast++;
      sput_fail_unless(len <= HNCP_MAXIMUM_MULTICAST_SIZE, "not too long multicast");
    }
  else
    {
      s->sent_unicast++;
      s->last_unicast_sent = hnetd_time();
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
  return hnetd_time();
}

/**************************************** (Partially mocked) interface - pa  */

void pa_update_lap(struct pa_data *data, const struct prefix *prefix, const char *ifname,
		int to_delete)
{
	/* In case of no ifname, we create a CPD */
	if(ifname) {
		struct pa_cpl *cpl = _pa_cpl(pa_cp_get(data, prefix, PA_CPT_L, !to_delete));
		if(!cpl)
			return;
		if(!to_delete) {
			struct pa_iface *iface = pa_iface_get(data, ifname, true);
			pa_cpl_set_iface(cpl, iface);
			pa_cp_set_advertised(&cpl->cp, true);
		} else {
			pa_cp_todelete(&cpl->cp);
		}
		pa_cp_notify(&cpl->cp);
	} else {
		struct pa_cpd *cpd = _pa_cpd(pa_cp_get(data, prefix, PA_CPT_D, !to_delete));
		if(!cpd)
			return;
		if(!to_delete) {
			pa_cp_set_advertised(&cpd->cp, true);
		} else {
			pa_cp_todelete(&cpd->cp);
		}
		pa_cp_notify(&cpd->cp);
	}
}

/* An laa can only be set for a valid chosen prefix */
void pa_update_laa(struct pa_data *data, const struct prefix *cp_prefix,
		const struct in6_addr *addr, const char *ifname,
		int to_delete)
{
	struct pa_cpl *cpl = _pa_cpl(pa_cp_get(data, cp_prefix, PA_CPT_L, !to_delete));
	struct pa_iface *iface = NULL;
	struct pa_laa *laa = NULL;
	if(!cpl)
		return;


	if(to_delete) {
		if(cpl->laa)
			pa_aa_todelete(&cpl->laa->aa);
	} else {
		iface = ifname?pa_iface_get(data, ifname, true):NULL;
		pa_cpl_set_iface(cpl, iface);
		laa = pa_laa_create(addr, cpl);
	}

	pa_cp_notify(&cpl->cp);
	if(laa)
		pa_aa_notify(data, &cpl->laa->aa);
	if(iface)
		pa_iface_notify(data, iface);
}


void pa_update_ldp(struct pa_data *data, const struct prefix *prefix,
		const char *ifname,
		hnetd_time_t valid_until, hnetd_time_t preferred_until,
		const void *dhcp_data, size_t dhcp_len)
{
	struct pa_ldp *ldp;
	struct pa_iface *iface = NULL;

	if(!(ldp = pa_ldp_get(data, prefix, !!valid_until)))
		return;

	if(valid_until) {

		pa_dp_set_lifetime(&ldp->dp, preferred_until, valid_until);
		pa_dp_set_dhcp(&ldp->dp, dhcp_data, dhcp_len);

		if(ifname)
			iface = pa_iface_get(data, ifname, true);
		pa_ldp_set_iface(ldp, iface);

		if(iface)
			pa_iface_notify(data, iface);
	} else {
		pa_dp_todelete(&ldp->dp);
	}

	pa_dp_notify(data, &ldp->dp);
}

/********************************************************************* iface */

struct iface* iface_get(const char *ifname)
{
  return NULL;
}

void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len,
                             const void *dhcp_data, size_t dhcp_len)
{
}

#endif /* NET_SIM_H */
