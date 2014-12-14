/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Sun Dec 14 18:59:08 2014 mstenber
 * Edit time:     810 min
 *
 */

#include "hncp_i.h"
#include <libubox/md5.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

int hncp_node_cmp(hncp_node n1, hncp_node n2)
{
  return memcmp(&n1->node_identifier, &n2->node_identifier, DNCP_NI_LEN);
}

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  hncp_node n1 = (hncp_node) a, n2 = (hncp_node) b;

  return hncp_node_cmp(n1, n2);
}

void hncp_schedule(hncp o)
{
  if (o->io_init_done)
    {
      if (o->immediate_scheduled)
        return;
      hncp_io_schedule(o, 0);
      o->immediate_scheduled = true;
    }
  else
    o->should_schedule = true;
}

void hncp_node_set(hncp_node n, uint32_t update_number,
                   hnetd_time_t t, struct tlv_attr *a)
{
  struct tlv_attr *a_valid = a;
  bool node_hash_changed = true;
  bool should_schedule = false;

  L_DEBUG("hncp_node_set %s update #%d %p (@%lld (-%lld))",
          HNCP_NODE_REPR(n), (int) update_number, a,
          (long long)t, (long long)(hnetd_time()-t));

  /* If new data is set, consider if similar, and if not,
   * handle version check  */
  if (a)
    {
      if (n->tlv_container && tlv_attr_equal(n->tlv_container, a))
        {
          if (n->tlv_container != a)
            {
              free(a);
              a = n->tlv_container;
            }
          a_valid = n->tlv_container_valid;
          node_hash_changed = false; /* provisionally, depend on update#  */
        }
      else
        {
          uint8_t version = 0;
#if L_LEVEL >= LOG_ERR
          const char *agent = NULL;
          int agent_len = 0;
#endif /* L_LEVEL >= LOG_ERR */
          struct tlv_attr *va;
          hncp_node on = n->hncp->own_node;

          tlv_for_each_attr(va, a)
            {
              if (tlv_id(va) == HNCP_T_VERSION &&
                  tlv_len(va) >= sizeof(hncp_t_version_s))
                {
                  hncp_t_version v = tlv_data(va);
                  version = v->version;
#if L_LEVEL >= LOG_ERR
                  agent = v->user_agent;
                  agent_len = tlv_len(va) - sizeof(hncp_t_version_s);
#endif /* L_LEVEL >= LOG_ERR */
                  break;
                }
            }
          if (on && on != n && on->version && version != on->version)
            a_valid = NULL;
          if (a && n->version != version)
            {
              if (!a_valid)
                L_ERR("Incompatible node: %s version %u (%.*s) != %u",
                      HNCP_NODE_REPR(n), version, agent_len, agent, on->version);
              else if (!n->version)
                L_INFO("%s runs %.*s",
                       HNCP_NODE_REPR(n), agent_len, agent);
              n->version = version;
            }
        }
      n->hncp->graph_dirty = true;
      should_schedule = true;
    }

  /* Replace update number if any */
  if (n->update_number != update_number)
    {
      node_hash_changed = true;
      n->update_number = update_number;
    }

  /* Replace origination time if any */
  if (t)
    n->origination_time = t;

  /* Replace data (if it is a different pointer) */
  if (n->tlv_container != a)
    {
      if (n->last_reachable_prune == n->hncp->last_prune)
        hncp_notify_subscribers_tlvs_changed(n, n->tlv_container_valid,
                                             a_valid);
      if (n->tlv_container)
        free(n->tlv_container);
      n->tlv_container = a;
      n->tlv_container_valid = a_valid;
      n->tlv_index_dirty = true;
    }

  /* If something that affects network hash has changed,
   * set various flags + schedule hncp_run. */
  if (node_hash_changed)
    {
      n->node_data_hash_dirty = true;
      n->hncp->network_hash_dirty = true;
      should_schedule = true;
    }

  if (should_schedule)
    hncp_schedule(n->hncp);
}


static void update_node(__unused struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hncp o = container_of(t, hncp_s, nodes);
  hncp_node n_old = container_of(node_old, hncp_node_s, in_nodes);
  __unused hncp_node n_new = container_of(node_new, hncp_node_s, in_nodes);

  if (n_old == n_new)
    return;
  if (n_old)
    {
      hncp_node_set(n_old, 0, 0, NULL);
      if (n_old->tlv_index)
        free(n_old->tlv_index);
      free(n_old);
    }
  if (n_new)
    {
      n_new->node_data_hash_dirty = true;
      n_new->tlv_index_dirty = true;
      /* By default unreachable */
      n_new->last_reachable_prune = o->last_prune - 1;
    }
  o->network_hash_dirty = true;
  o->graph_dirty = true;
  hncp_schedule(o);
}


static int
compare_tlvs(const void *a, const void *b, void *ptr __unused)
{
  hncp_tlv t1 = (hncp_tlv) a, t2 = (hncp_tlv) b;

  return tlv_attr_cmp(&t1->tlv, &t2->tlv);
}

static void update_tlv(struct vlist_tree *t,
                       struct vlist_node *node_new,
                       struct vlist_node *node_old)
{
  hncp o = container_of(t, hncp_s, tlvs);
  hncp_tlv t_old = container_of(node_old, hncp_tlv_s, in_tlvs);
  __unused hncp_tlv t_new = container_of(node_new, hncp_tlv_s, in_tlvs);

  if (t_old)
    {
      hncp_notify_subscribers_local_tlv_changed(o, &t_old->tlv, false);
      free(t_old);
    }
  if (t_new)
    hncp_notify_subscribers_local_tlv_changed(o, &t_new->tlv, true);

  o->tlvs_dirty = true;
  hncp_schedule(o);
}

static int
compare_links(const void *a, const void *b, void *ptr __unused)
{
  hncp_link t1 = (hncp_link) a, t2 = (hncp_link) b;

  return strcmp(t1->ifname, t2->ifname);
}

static void update_link(struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hncp o = container_of(t, hncp_s, links);
  hncp_link t_old = container_of(node_old, hncp_link_s, in_links);
  hncp_link t_new = container_of(node_new, hncp_link_s, in_links);

  if (t_old)
    {
      if (!t_new && o->io_init_done)
        hncp_io_set_ifname_enabled(o, t_old->ifname, false);
      hncp_tlv t, t2;
      hncp_for_each_local_tlv_safe(o, t, t2)
        if (tlv_id(&t->tlv) == HNCP_T_NODE_DATA_NEIGHBOR)
          {
            hncp_t_node_data_neighbor ne = tlv_data(&t->tlv);
            if (ne->link_id == t_old->iid)
              hncp_remove_tlv(o, t);
          }
      free(t_old);
    }
  else
    {
      t_new->join_failed_time = 1;
    }
  hncp_schedule(o);
}

void hncp_calculate_hash(const void *buf, int len, hncp_hash dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  hncp_md5_end(dest, &ctx);
}


hncp_node
hncp_find_node_by_node_identifier(hncp o, hncp_node_identifier ni, bool create)
{
  hncp_node ch = container_of(ni, hncp_node_s, node_identifier);
  hncp_node n = vlist_find(&o->nodes, ch, ch, in_nodes);

  if (n)
    return n;
  if (!create)
    return NULL;
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  n->node_identifier = *ni;
  n->hncp = o;
  n->tlv_index_dirty = true;
  vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}

bool hncp_init(hncp o, const void *node_identifier, int len)
{
  hncp_hash_s h;

  memset(o, 0, sizeof(*o));
  INIT_LIST_HEAD(&o->subscribers);
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->links, compare_links, update_link);
  INIT_LIST_HEAD(&o->link_confs);
  hncp_calculate_hash(node_identifier, len, &h);
  if (inet_pton(AF_INET6, HNCP_MCAST_GROUP, &o->multicast_address) < 1) {
    L_ERR("unable to inet_pton multicast group address");
    return false;
  }
  o->first_free_iid = 1;
  o->last_prune = 1;
  /* this way new nodes with last_prune=0 won't be reachable */
  return hncp_set_own_node_identifier(o, (hncp_node_identifier)&h);
}

bool hncp_set_own_node_identifier(hncp o, hncp_node_identifier ni)
{
  if (o->own_node)
    {
      vlist_delete(&o->nodes, &o->own_node->in_nodes);
      o->own_node = NULL;
    }
  hncp_node n = hncp_find_node_by_node_identifier(o, ni, true);
  if (!n)
    {
      L_ERR("unable to create own node");
      return false;
    }
  o->own_node = n;
  o->tlvs_dirty = true; /* by default, they are, even if no neighbors yet. */
  n->last_reachable_prune = o->last_prune; /* we're always reachable */
  hncp_schedule(o);
  return true;
}

hncp hncp_create(void)
{
  hncp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  /* hncp_init does memset 0 -> we can just malloc here. */
  o = malloc(sizeof(*o));
  if (!o)
    return NULL;
  c += hncp_io_get_hwaddrs(buf, sizeof(buf));
  if (c == buf) {
    L_ERR("no hardware address available, fatal error");
    goto err;
  }
  if (!hncp_init(o, buf, c-buf))
    goto err;
  if (!hncp_io_init(o))
    goto err2;
  o->io_init_done = true;
  if (o->should_schedule)
    hncp_schedule(o);

  struct __packed {
    hncp_t_version_s h;
    char agent[32];
  } data;
  memset(&data, 0, sizeof(data));
  data.h.version = HNCP_VERSION;
  int alen = snprintf(data.agent, sizeof(data.agent),
                      "hnetd-%s", STR(HNETD_VERSION));
  if (alen == sizeof(data.agent))
    alen = sizeof(data.agent) - 1;
  data.agent[alen] = 0;
  hncp_add_tlv(o, HNCP_T_VERSION, &data, sizeof(data.h) + alen + 1, 0);

  return o;
 err2:
  vlist_flush_all(&o->nodes);
 err:
  free(o);
  return NULL;
}

void hncp_uninit(hncp o)
{
  o->io_init_done = false; /* cannot schedule anything anymore after this. */

  /* TLVs should be freed first; they're local phenomenom, but may be
   * reflected on links/nodes. */
  vlist_flush_all(&o->tlvs);

  /* Link destruction will refer to node -> have to be taken out
   * before nodes. */
  vlist_flush_all(&o->links);

  /* All except own node should be taken out first. */
  vlist_update(&o->nodes);
  o->own_node->in_nodes.version = -1;
  vlist_flush(&o->nodes);

  /* Finally, we can kill own node too. */
  vlist_flush_all(&o->nodes);

  /* Get rid of TLV index. */
  if (o->num_tlv_indexes)
    free(o->tlv_type_to_index);
}

void hncp_destroy(hncp o)
{
  if (!o) return;
  hncp_io_uninit(o);
  hncp_uninit(o);
  free(o);
}

hncp_node hncp_get_first_node(hncp o)
{
  hncp_node n;

  if (avl_is_empty(&o->nodes.avl))
    return NULL;
  n = avl_first_element(&o->nodes.avl, n, in_nodes.avl);
  if (n->last_reachable_prune == o->last_prune)
    return n;
  return hncp_node_get_next(n);
}

hncp_tlv
hncp_add_tlv(hncp o, uint16_t type, void *data, uint16_t len, int extra_bytes)
{
  int plen = TLV_SIZE +
    (len + TLV_ATTR_ALIGN - 1) & ~(TLV_ATTR_ALIGN - 1);
  hncp_tlv t = calloc(1, sizeof(*t) + plen + extra_bytes);

  if (!t)
    return NULL;
  tlv_init(&t->tlv, type, len + TLV_SIZE);
  memcpy(tlv_data(&t->tlv), data, len);
  tlv_fill_pad(&t->tlv);
  vlist_add(&o->tlvs, &t->in_tlvs, t);
  return t;
}

void hncp_remove_tlv(hncp o, hncp_tlv tlv)
{
  if (!tlv)
    return;
  vlist_delete(&o->tlvs, &tlv->in_tlvs);
}

int hncp_remove_tlvs_by_type(hncp o, int type)
{
  hncp_tlv t, t2;
  int c = 0;

  avl_for_each_element_safe(&o->tlvs.avl, t, in_tlvs.avl, t2)
    {
      if ((int)tlv_id(&t->tlv) == type)
        {
          hncp_remove_tlv(o, t);
          c++;
        }
    }
  return c;
}

static void hncp_link_conf_set_default(hncp_link_conf conf, const char *ifname)
{
  conf->trickle_imin = HNCP_TRICKLE_IMIN;
  conf->trickle_imax = HNCP_TRICKLE_IMAX;
  conf->trickle_k = HNCP_TRICKLE_K;
  conf->keepalive_interval = DNCP_KEEPALIVE_INTERVAL;
  strncpy(conf->dnsname, ifname, sizeof(conf->ifname));
  strncpy(conf->ifname, ifname, sizeof(conf->ifname));
}

hncp_link_conf hncp_if_find_conf_by_name(hncp o, const char *ifname)
{
  hncp_link_conf conf;
  list_for_each_entry(conf, &o->link_confs, in_link_confs) {
    if(!strcmp(ifname, conf->ifname))
      return conf;
  }

  if(!(conf = malloc(sizeof(hncp_link_conf_s))))
    return NULL;

  hncp_link_conf_set_default(conf, ifname);
  list_add(&conf->in_link_confs, &o->link_confs);
  return conf;
}

hncp_link hncp_find_link_by_name(hncp o, const char *ifname, bool create)
{
  hncp_link cl = container_of(ifname, hncp_link_s, ifname[0]);
  hncp_link l;

  if (!ifname || !*ifname)
    return NULL;

  l = vlist_find(&o->links, cl, cl, in_links);

  if (create && !l)
    {
      l = (hncp_link) calloc(1, sizeof(*l));
      if (!l)
        return NULL;
      l->conf = hncp_if_find_conf_by_name(o, ifname);
      if(!l->conf) {
        free(l);
        return NULL;
      }
      l->hncp = o;
      l->iid = o->first_free_iid++;
      strcpy(l->ifname, ifname);
      vlist_add(&o->links, &l->in_links, l);
    }
  return l;
}

hncp_link hncp_find_link_by_id(hncp o, uint32_t link_id)
{
  hncp_link l;
  /* XXX - this could be also made more efficient. Oh well. */
  vlist_for_each_element(&o->links, l, in_links)
    if (l->iid == link_id)
      return l;
  return NULL;
}

bool hncp_if_set_enabled(hncp o, const char *ifname, bool enabled)
{
  hncp_link l = hncp_find_link_by_name(o, ifname, false);

  L_DEBUG("hncp_if_set_enabled %s %s",
          ifname, enabled ? "enabled" : "disabled");
  if (!enabled)
    {
      if (!l)
        return false;
      hncp_notify_subscribers_link_changed(l);
      vlist_delete(&o->links, &l->in_links);
      return true;
    }
  if (l)
    return false;
  l = hncp_find_link_by_name(o, ifname, true);
  if (l)
    hncp_notify_subscribers_link_changed(l);
  return l != NULL;
}


bool hncp_node_is_self(hncp_node n)
{
  return n->hncp->own_node == n;
}

hncp_node hncp_node_get_next(hncp_node n)
{
  hncp o = n->hncp;
  hncp_node last = avl_last_element(&o->nodes.avl, n, in_nodes.avl);

  if (!n || n == last)
    return NULL;
  while (1)
    {
      n = avl_next_element(n, in_nodes.avl);
      if (n->last_reachable_prune == o->last_prune)
        return n;
      if (n == last)
        return NULL;
    }
}

static struct tlv_attr *_produce_new_tlvs(hncp_node n)
{
  struct tlv_buf tb;
  hncp o = n->hncp;
  hncp_tlv t;

  if (!o->tlvs_dirty)
    return NULL;

  /* Dump the contents of hncp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    {
      struct tlv_attr *a = tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv));
      if (!a)
        {
          L_ERR("hncp_self_flush: tlv_put_raw failed?!?");
          tlv_buf_free(&tb);
          return NULL;
        }
      tlv_fill_pad(a);
    }
  tlv_fill_pad(tb.head);

  /* Ok, all puts _did_ succeed. */
  o->tlvs_dirty = false;

  if (n->tlv_container && tlv_attr_equal(tb.head, n->tlv_container))
    {
      tlv_buf_free(&tb);
      return NULL;
    }
  return tb.head;
}

void hncp_self_flush(hncp_node n)
{
  hncp o = n->hncp;
  struct tlv_attr *a, *a2;

  if (!(a = _produce_new_tlvs(n)) && !o->republish_tlvs)
    {
      L_DEBUG("hncp_self_flush: state did not change -> nothing to flush");
      return;
    }

  L_DEBUG("hncp_self_flush: notify about to republish tlvs");
  hncp_notify_subscribers_about_to_republish_tlvs(n);

  o->republish_tlvs = false;
  a2 = _produce_new_tlvs(n);
  if (a2)
    {
      if (a)
        free(a);
      a = a2;
    }
  hncp_node_set(n, ++n->update_number, hncp_time(o),
                a ? a : n->tlv_container);
}

struct tlv_attr *hncp_node_get_tlvs(hncp_node n)
{
  return n->tlv_container_valid;
}


void hncp_calculate_node_data_hash(hncp_node n)
{
  md5_ctx_t ctx;
  int l;
  unsigned char buf[TLV_SIZE + sizeof(hncp_t_node_data_header_s)];
  struct tlv_attr *h = (struct tlv_attr *)buf;
  hncp_t_node_data_header ndh = tlv_data(h);

  if (!n->node_data_hash_dirty)
    return;

  l = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  tlv_init(h, HNCP_T_NODE_DATA, sizeof(buf) + l);
  ndh->node_identifier = n->node_identifier;
  ndh->update_number = cpu_to_be32(n->update_number);
  md5_begin(&ctx);
  md5_hash(buf, sizeof(buf), &ctx);
  if (l)
    md5_hash(tlv_data(n->tlv_container), l, &ctx);
  hncp_md5_end(&n->node_data_hash, &ctx);
  n->node_data_hash_dirty = false;
  L_DEBUG("hncp_calculate_node_data_hash @%p %s=%llx%s",
          n->hncp, HNCP_NODE_REPR(n),
          hncp_hash64(&n->node_data_hash),
          n == n->hncp->own_node ? " [self]" : "");
}

void hncp_calculate_network_hash(hncp o)
{
  hncp_node n;
  md5_ctx_t ctx;

  if (!o->network_hash_dirty)
    return;
  md5_begin(&ctx);
  hncp_for_each_node(o, n)
    {
      hncp_calculate_node_data_hash(n);
      md5_hash(&n->node_data_hash, HNCP_HASH_LEN, &ctx);
    }
  hncp_md5_end(&o->network_hash, &ctx);
  L_DEBUG("hncp_calculate_network_hash @%p =%llx",
          o, hncp_hash64(&o->network_hash));
  o->network_hash_dirty = false;
}

bool
hncp_get_ipv6_address(hncp o, char *prefer_ifname, struct in6_addr *addr)
{
  hncp_link l = NULL;

  if (prefer_ifname)
    l = hncp_find_link_by_name(o, prefer_ifname, false);
  if (!l || !l->has_ipv6_address)
    {
      /* Iterate through the links in order, stopping at one with IPv6
       * address. */
      vlist_for_each_element(&o->links, l, in_links)
        if (l->has_ipv6_address)
          break;
    }
  if (l && l->has_ipv6_address)
    {
      *addr = l->ipv6_address;
      return true;
    }
  return false;
}

bool hncp_add_tlv_index(hncp o, uint16_t type)
{
  if (type < o->tlv_type_to_index_length)
    {
      if (o->tlv_type_to_index[type])
        {
          L_DEBUG("hncp_add_tlv_index called for existing index (type %d)",
                  (int)type);
          return true;
        }
    }
  else
    {
      int old_len = o->tlv_type_to_index_length;
      int old_size = old_len * sizeof(o->tlv_type_to_index[0]);
      int new_len = type + 1;
      int new_size = new_len * sizeof(o->tlv_type_to_index[0]);
      int *ni = realloc(o->tlv_type_to_index, new_size);
      if (!ni)
        return false;
      memset((void *)ni + old_size, 0, new_size - old_size);
      o->tlv_type_to_index = ni;
      o->tlv_type_to_index_length = new_len;
      L_DEBUG("hncp_add_tlv_index grew tlv_type_to_index to %d", new_len);
    }

  L_DEBUG("hncp_add_tlv_index: type #%d = index #%d", type, o->num_tlv_indexes);
  o->tlv_type_to_index[type] = ++o->num_tlv_indexes;

  /* Free existing indexes */
  hncp_node n;
  hncp_for_each_node_including_unreachable(o, n)
    {
      if (n->tlv_index)
        {
          free(n->tlv_index);
          n->tlv_index = NULL;
          n->tlv_index_dirty = true;
        }
      assert(n->tlv_index_dirty);
    }
  return true;
}


void
hncp_link_set_ipv6_address(hncp_link l, const struct in6_addr *addr)
{
  bool has_addr = addr != NULL;

  if (l->has_ipv6_address == has_addr &&
      (!has_addr || memcmp(&l->ipv6_address, addr, sizeof(*addr)) == 0))
    {
      return;
    }
  l->has_ipv6_address = has_addr;
  if (has_addr)
    {
      l->ipv6_address = *addr;
      L_DEBUG("hncp_link_set_ipv6_address: address on %s: %s",
              l->ifname, ADDR_REPR(addr));
    }
  else
    {
      L_DEBUG("hncp_link_set_ipv6_address: no %s any more", l->ifname);
    }
  hncp_notify_subscribers_link_changed(l);
}

bool hncp_if_has_highest_id(hncp o, const char *ifname)
{
  hncp_link l = hncp_find_link_by_name(o, ifname, false);

  /* Who knows if link is not enabled.. e.g. guest mode require us to
   * return true here, though. */
  if (!l)
    return true;

  uint32_t iid = l->iid;
  struct tlv_attr *a;
  hncp_t_node_data_neighbor nh;

  hncp_node_for_each_tlv_with_type(o->own_node, a, HNCP_T_NODE_DATA_NEIGHBOR)
    if ((nh = hncp_tlv_neighbor(a)))
      {
        if (nh->link_id != iid)
          continue;
        if (memcmp(&o->own_node->node_identifier,
                   &nh->neighbor_node_identifier, DNCP_NI_LEN) < 0)
          return false;
      }
  return true;
}


void
hncp_if_set_ipv6_address(hncp o, const char *ifname, const struct in6_addr *a)
{
  hncp_link l = hncp_find_link_by_name(o, ifname, false);
  if (l)
    hncp_link_set_ipv6_address(l, a);
}

void hncp_node_recalculate_index(hncp_node n)
{
  int size = n->hncp->num_tlv_indexes * 2 * sizeof(n->tlv_index[0]);

  assert(n->tlv_index_dirty);
  if (!n->tlv_index)
    {
      n->tlv_index = calloc(1, size);
      if (!n->tlv_index)
        return;
    }
  else
    {
      memset(n->tlv_index, 0, size);
    }

  hncp o = n->hncp;
  struct tlv_attr *a;
  int type = -1;
  int idx = 0;

  /* Note: This algorithm isn't particularly clever - while linear in
   * speed (O(# of indexes + # of entries in tlv_container), it has bit
   * too significant constant factor for comfort. */
  hncp_node_for_each_tlv(n, a)
    {
      if ((int)tlv_id(a) != type)
        {
          type = tlv_id(a);
          /* No more indexes here -> stop iteration */
          if (type >= o->tlv_type_to_index_length)
            break;
          if (!(idx = o->tlv_type_to_index[type]))
            continue;
          n->tlv_index[2 * idx - 2] = a;
          assert(idx <= n->hncp->num_tlv_indexes);
        }
      if (idx)
        n->tlv_index[2 * idx - 1] = tlv_next(a);
    }
  n->tlv_index_dirty = false;
}

hncp_tlv hncp_find_tlv(hncp o, uint16_t type, void *data, uint16_t len)
{
  hncp_tlv t;
  /* XXX - this is inefficient, as options are bad (either alloc+copy,
   * or iterate through a list). */
  hncp_for_each_local_tlv(o, t)
    if (tlv_id(&t->tlv) == type
        && tlv_len(&t->tlv) == len
        && memcmp(tlv_data(&t->tlv), data, len) == 0)
      return t;
  return NULL;
}

void *hncp_tlv_get_extra(hncp_tlv t)
{
  unsigned int ofs = tlv_pad_len(&t->tlv);
  return ((unsigned char *)t + sizeof(*t) + ofs);
}
