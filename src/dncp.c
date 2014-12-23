/*
 * $Id: dncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Tue Dec 23 18:57:41 2014 mstenber
 * Edit time:     827 min
 *
 */

#include "dncp_i.h"
#include <libubox/md5.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

int dncp_node_cmp(dncp_node n1, dncp_node n2)
{
  return memcmp(&n1->node_identifier, &n2->node_identifier, DNCP_NI_LEN);
}

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  dncp_node n1 = (dncp_node) a, n2 = (dncp_node) b;

  return dncp_node_cmp(n1, n2);
}

void dncp_schedule(dncp o)
{
  if (o->io_init_done)
    {
      if (o->immediate_scheduled)
        return;
      dncp_io_schedule(o, 0);
      o->immediate_scheduled = true;
    }
  else
    o->should_schedule = true;
}

void dncp_node_set(dncp_node n, uint32_t update_number,
                   hnetd_time_t t, struct tlv_attr *a)
{
  struct tlv_attr *a_valid = a;
  bool node_hash_changed = true;
  bool should_schedule = false;

  L_DEBUG("dncp_node_set %s update #%d %p (@%lld (-%lld))",
          DNCP_NODE_REPR(n), (int) update_number, a,
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
          a_valid = dncp_profile_node_validate_data(n, a);
        }
      n->dncp->graph_dirty = true;
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
      if (n->last_reachable_prune == n->dncp->last_prune)
        dncp_notify_subscribers_tlvs_changed(n, n->tlv_container_valid,
                                             a_valid);
      if (n->tlv_container)
        free(n->tlv_container);
      n->tlv_container = a;
      n->tlv_container_valid = a_valid;
      n->tlv_index_dirty = true;
    }

  /* If something that affects network hash has changed,
   * set various flags + schedule dncp_run. */
  if (node_hash_changed)
    {
      n->node_data_hash_dirty = true;
      n->dncp->network_hash_dirty = true;
      should_schedule = true;
    }

  if (should_schedule)
    dncp_schedule(n->dncp);
}


static void update_node(__unused struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  dncp o = container_of(t, dncp_s, nodes);
  dncp_node n_old = container_of(node_old, dncp_node_s, in_nodes);
  __unused dncp_node n_new = container_of(node_new, dncp_node_s, in_nodes);

  if (n_old == n_new)
    return;
  if (n_old)
    {
      dncp_node_set(n_old, 0, 0, NULL);
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
  dncp_schedule(o);
}


static int
compare_tlvs(const void *a, const void *b, void *ptr __unused)
{
  dncp_tlv t1 = (dncp_tlv) a, t2 = (dncp_tlv) b;

  return tlv_attr_cmp(&t1->tlv, &t2->tlv);
}

static void update_tlv(struct vlist_tree *t,
                       struct vlist_node *node_new,
                       struct vlist_node *node_old)
{
  dncp o = container_of(t, dncp_s, tlvs);
  dncp_tlv t_old = container_of(node_old, dncp_tlv_s, in_tlvs);
  __unused dncp_tlv t_new = container_of(node_new, dncp_tlv_s, in_tlvs);

  if (t_old)
    {
      dncp_notify_subscribers_local_tlv_changed(o, &t_old->tlv, false);
      free(t_old);
    }
  if (t_new)
    dncp_notify_subscribers_local_tlv_changed(o, &t_new->tlv, true);

  o->tlvs_dirty = true;
  dncp_schedule(o);
}

static int
compare_links(const void *a, const void *b, void *ptr __unused)
{
  dncp_link t1 = (dncp_link) a, t2 = (dncp_link) b;

  return strcmp(t1->ifname, t2->ifname);
}

static void update_link(struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  dncp o = container_of(t, dncp_s, links);
  dncp_link t_old = container_of(node_old, dncp_link_s, in_links);
  dncp_link t_new = container_of(node_new, dncp_link_s, in_links);

  if (t_old)
    {
      if (!t_new && o->io_init_done)
        dncp_io_set_ifname_enabled(o, t_old->ifname, false);
      dncp_tlv t, t2;
      dncp_for_each_local_tlv_safe(o, t, t2)
        if (tlv_id(&t->tlv) == DNCP_T_NODE_DATA_NEIGHBOR)
          {
            dncp_t_node_data_neighbor ne = tlv_data(&t->tlv);
            if (ne->link_id == t_old->iid)
              dncp_remove_tlv(o, t);
          }
      free(t_old);
    }
  else
    {
      t_new->join_failed_time = 1;
    }
  dncp_schedule(o);
}

void dncp_calculate_hash(const void *buf, int len, dncp_hash dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  dncp_md5_end(dest, &ctx);
}


dncp_node
dncp_find_node_by_node_identifier(dncp o, dncp_node_identifier ni, bool create)
{
  dncp_node ch = container_of(ni, dncp_node_s, node_identifier);
  dncp_node n = vlist_find(&o->nodes, ch, ch, in_nodes);

  if (n)
    return n;
  if (!create)
    return NULL;
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  n->node_identifier = *ni;
  n->dncp = o;
  n->tlv_index_dirty = true;
  vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}

bool dncp_init(dncp o, const void *node_identifier, int len)
{
  dncp_hash_s h;

  memset(o, 0, sizeof(*o));
  INIT_LIST_HEAD(&o->subscribers);
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->links, compare_links, update_link);
  INIT_LIST_HEAD(&o->link_confs);
  dncp_calculate_hash(node_identifier, len, &h);
  o->first_free_iid = 1;
  o->last_prune = 1;
  /* this way new nodes with last_prune=0 won't be reachable */
  return dncp_set_own_node_identifier(o, (dncp_node_identifier)&h);
}

bool dncp_set_own_node_identifier(dncp o, dncp_node_identifier ni)
{
  if (o->own_node)
    {
      vlist_delete(&o->nodes, &o->own_node->in_nodes);
      o->own_node = NULL;
    }
  dncp_node n = dncp_find_node_by_node_identifier(o, ni, true);
  if (!n)
    {
      L_ERR("unable to create own node");
      return false;
    }
  o->own_node = n;
  o->tlvs_dirty = true; /* by default, they are, even if no neighbors yet. */
  n->last_reachable_prune = o->last_prune; /* we're always reachable */
  dncp_schedule(o);
  return true;
}

dncp dncp_create(void)
{
  dncp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  /* dncp_init does memset 0 -> we can just malloc here. */
  o = malloc(sizeof(*o));
  if (!o)
    return NULL;
  c += dncp_io_get_hwaddrs(buf, sizeof(buf));
  if (c == buf) {
    L_ERR("no hardware address available, fatal error");
    goto err;
  }
  if (!dncp_init(o, buf, c-buf))
    goto err;
  if (!dncp_io_init(o))
    goto err2;
  o->io_init_done = true;
  if (o->should_schedule)
    dncp_schedule(o);

  return o;
 err2:
  vlist_flush_all(&o->nodes);
 err:
  free(o);
  return NULL;
}

void dncp_uninit(dncp o)
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

void dncp_destroy(dncp o)
{
  if (!o) return;
  dncp_io_uninit(o);
  dncp_uninit(o);
  free(o);
}

dncp_node dncp_get_first_node(dncp o)
{
  dncp_node n;

  if (avl_is_empty(&o->nodes.avl))
    return NULL;
  n = avl_first_element(&o->nodes.avl, n, in_nodes.avl);
  if (n->last_reachable_prune == o->last_prune)
    return n;
  return dncp_node_get_next(n);
}

dncp_tlv
dncp_add_tlv(dncp o, uint16_t type, void *data, uint16_t len, int extra_bytes)
{
  int plen = TLV_SIZE +
    (len + TLV_ATTR_ALIGN - 1) & ~(TLV_ATTR_ALIGN - 1);
  dncp_tlv t = calloc(1, sizeof(*t) + plen + extra_bytes);

  if (!t)
    return NULL;
  tlv_init(&t->tlv, type, len + TLV_SIZE);
  memcpy(tlv_data(&t->tlv), data, len);
  tlv_fill_pad(&t->tlv);
  vlist_add(&o->tlvs, &t->in_tlvs, t);
  return t;
}

void dncp_remove_tlv(dncp o, dncp_tlv tlv)
{
  if (!tlv)
    return;
  vlist_delete(&o->tlvs, &tlv->in_tlvs);
}

int dncp_remove_tlvs_by_type(dncp o, int type)
{
  dncp_tlv t, t2;
  int c = 0;

  avl_for_each_element_safe(&o->tlvs.avl, t, in_tlvs.avl, t2)
    {
      if ((int)tlv_id(&t->tlv) == type)
        {
          dncp_remove_tlv(o, t);
          c++;
        }
    }
  return c;
}

static void dncp_link_conf_set_default(dncp_link_conf conf, const char *ifname)
{
  conf->trickle_imin = DNCP_TRICKLE_IMIN;
  conf->trickle_imax = DNCP_TRICKLE_IMAX;
  conf->trickle_k = DNCP_TRICKLE_K;
  conf->keepalive_interval = DNCP_KEEPALIVE_INTERVAL;
  strncpy(conf->dnsname, ifname, sizeof(conf->ifname));
  strncpy(conf->ifname, ifname, sizeof(conf->ifname));
}

dncp_link_conf dncp_if_find_conf_by_name(dncp o, const char *ifname)
{
  dncp_link_conf conf;
  list_for_each_entry(conf, &o->link_confs, in_link_confs) {
    if(!strcmp(ifname, conf->ifname))
      return conf;
  }

  if(!(conf = malloc(sizeof(dncp_link_conf_s))))
    return NULL;

  dncp_link_conf_set_default(conf, ifname);
  list_add(&conf->in_link_confs, &o->link_confs);
  return conf;
}

dncp_link dncp_find_link_by_name(dncp o, const char *ifname, bool create)
{
  dncp_link cl = container_of(ifname, dncp_link_s, ifname[0]);
  dncp_link l;

  if (!ifname || !*ifname)
    return NULL;

  l = vlist_find(&o->links, cl, cl, in_links);

  if (create && !l)
    {
      l = (dncp_link) calloc(1, sizeof(*l));
      if (!l)
        return NULL;
      l->conf = dncp_if_find_conf_by_name(o, ifname);
      if(!l->conf) {
        free(l);
        return NULL;
      }
      l->dncp = o;
      l->iid = o->first_free_iid++;
      strcpy(l->ifname, ifname);
      vlist_add(&o->links, &l->in_links, l);
    }
  return l;
}

dncp_link dncp_find_link_by_id(dncp o, uint32_t link_id)
{
  dncp_link l;
  /* XXX - this could be also made more efficient. Oh well. */
  vlist_for_each_element(&o->links, l, in_links)
    if (l->iid == link_id)
      return l;
  return NULL;
}

bool dncp_if_set_enabled(dncp o, const char *ifname, bool enabled)
{
  dncp_link l = dncp_find_link_by_name(o, ifname, false);

  L_DEBUG("dncp_if_set_enabled %s %s",
          ifname, enabled ? "enabled" : "disabled");
  if (!enabled)
    {
      if (!l)
        return false;
      dncp_notify_subscribers_link_changed(l);
      vlist_delete(&o->links, &l->in_links);
      return true;
    }
  if (l)
    return false;
  l = dncp_find_link_by_name(o, ifname, true);
  if (l)
    dncp_notify_subscribers_link_changed(l);
  return l != NULL;
}


bool dncp_node_is_self(dncp_node n)
{
  return n->dncp->own_node == n;
}

dncp_node dncp_node_get_next(dncp_node n)
{
  dncp o = n->dncp;
  dncp_node last = avl_last_element(&o->nodes.avl, n, in_nodes.avl);

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

static struct tlv_attr *_produce_new_tlvs(dncp_node n)
{
  struct tlv_buf tb;
  dncp o = n->dncp;
  dncp_tlv t;

  if (!o->tlvs_dirty)
    return NULL;

  /* Dump the contents of dncp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    {
      struct tlv_attr *a = tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv));
      if (!a)
        {
          L_ERR("dncp_self_flush: tlv_put_raw failed?!?");
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

void dncp_self_flush(dncp_node n)
{
  dncp o = n->dncp;
  struct tlv_attr *a, *a2;

  if (!(a = _produce_new_tlvs(n)) && !o->republish_tlvs)
    {
      L_DEBUG("dncp_self_flush: state did not change -> nothing to flush");
      return;
    }

  L_DEBUG("dncp_self_flush: notify about to republish tlvs");
  dncp_notify_subscribers_about_to_republish_tlvs(n);

  o->republish_tlvs = false;
  a2 = _produce_new_tlvs(n);
  if (a2)
    {
      if (a)
        free(a);
      a = a2;
    }
  dncp_node_set(n, ++n->update_number, dncp_time(o),
                a ? a : n->tlv_container);
}

struct tlv_attr *dncp_node_get_tlvs(dncp_node n)
{
  return n->tlv_container_valid;
}


void dncp_calculate_node_data_hash(dncp_node n)
{
  md5_ctx_t ctx;
  int l;
  unsigned char buf[TLV_SIZE + sizeof(dncp_t_node_data_header_s)];
  struct tlv_attr *h = (struct tlv_attr *)buf;
  dncp_t_node_data_header ndh = tlv_data(h);

  if (!n->node_data_hash_dirty)
    return;

  l = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  tlv_init(h, DNCP_T_NODE_DATA, sizeof(buf) + l);
  ndh->node_identifier = n->node_identifier;
  ndh->update_number = cpu_to_be32(n->update_number);
  md5_begin(&ctx);
  md5_hash(buf, sizeof(buf), &ctx);
  if (l)
    md5_hash(tlv_data(n->tlv_container), l, &ctx);
  dncp_md5_end(&n->node_data_hash, &ctx);
  n->node_data_hash_dirty = false;
  L_DEBUG("dncp_calculate_node_data_hash @%p %s=%llx%s",
          n->dncp, DNCP_NODE_REPR(n),
          dncp_hash64(&n->node_data_hash),
          n == n->dncp->own_node ? " [self]" : "");
}

void dncp_calculate_network_hash(dncp o)
{
  dncp_node n;
  md5_ctx_t ctx;

  if (!o->network_hash_dirty)
    return;
  md5_begin(&ctx);
  dncp_for_each_node(o, n)
    {
      dncp_calculate_node_data_hash(n);
      md5_hash(&n->node_data_hash, DNCP_HASH_LEN, &ctx);
    }
  dncp_md5_end(&o->network_hash, &ctx);
  L_DEBUG("dncp_calculate_network_hash @%p =%llx",
          o, dncp_hash64(&o->network_hash));
  o->network_hash_dirty = false;
}

bool
dncp_get_ipv6_address(dncp o, char *prefer_ifname, struct in6_addr *addr)
{
  dncp_link l = NULL;

  if (prefer_ifname)
    l = dncp_find_link_by_name(o, prefer_ifname, false);
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

bool dncp_add_tlv_index(dncp o, uint16_t type)
{
  if (type < o->tlv_type_to_index_length)
    {
      if (o->tlv_type_to_index[type])
        {
          L_DEBUG("dncp_add_tlv_index called for existing index (type %d)",
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
      L_DEBUG("dncp_add_tlv_index grew tlv_type_to_index to %d", new_len);
    }

  L_DEBUG("dncp_add_tlv_index: type #%d = index #%d", type, o->num_tlv_indexes);
  o->tlv_type_to_index[type] = ++o->num_tlv_indexes;

  /* Free existing indexes */
  dncp_node n;
  dncp_for_each_node_including_unreachable(o, n)
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
dncp_link_set_ipv6_address(dncp_link l, const struct in6_addr *addr)
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
      L_DEBUG("dncp_link_set_ipv6_address: address on %s: %s",
              l->ifname, ADDR_REPR(addr));
    }
  else
    {
      L_DEBUG("dncp_link_set_ipv6_address: no %s any more", l->ifname);
    }
  dncp_notify_subscribers_link_changed(l);
}

bool dncp_if_has_highest_id(dncp o, const char *ifname)
{
  dncp_link l = dncp_find_link_by_name(o, ifname, false);

  /* Who knows if link is not enabled.. e.g. guest mode require us to
   * return true here, though. */
  if (!l)
    return true;

  uint32_t iid = l->iid;
  struct tlv_attr *a;
  dncp_t_node_data_neighbor nh;

  dncp_node_for_each_tlv_with_type(o->own_node, a, DNCP_T_NODE_DATA_NEIGHBOR)
    if ((nh = dncp_tlv_neighbor(a)))
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
dncp_if_set_ipv6_address(dncp o, const char *ifname, const struct in6_addr *a)
{
  dncp_link l = dncp_find_link_by_name(o, ifname, false);
  if (l)
    dncp_link_set_ipv6_address(l, a);
}

void dncp_node_recalculate_index(dncp_node n)
{
  int size = n->dncp->num_tlv_indexes * 2 * sizeof(n->tlv_index[0]);

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

  dncp o = n->dncp;
  struct tlv_attr *a;
  int type = -1;
  int idx = 0;

  /* Note: This algorithm isn't particularly clever - while linear in
   * speed (O(# of indexes + # of entries in tlv_container), it has bit
   * too significant constant factor for comfort. */
  dncp_node_for_each_tlv(n, a)
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
          assert(idx <= n->dncp->num_tlv_indexes);
        }
      if (idx)
        n->tlv_index[2 * idx - 1] = tlv_next(a);
    }
  n->tlv_index_dirty = false;
}

dncp_tlv dncp_find_tlv(dncp o, uint16_t type, void *data, uint16_t len)
{
  /* This is actually slower than list iteration if publishing only
   * 'some' data. Oh well. I suppose the better performance for 'large
   * N' cases is more useful. */
  dncp_tlv dt = alloca(sizeof(dncp_tlv_s) + len);
  if (!dt)
    return NULL;
  tlv_init(&dt->tlv, type, len + TLV_SIZE);
  memcpy(tlv_data(&dt->tlv), data, len);
  tlv_fill_pad(&dt->tlv);
  return vlist_find(&o->tlvs, dt, dt, in_tlvs);
}

void *dncp_tlv_get_extra(dncp_tlv t)
{
  unsigned int ofs = tlv_pad_len(&t->tlv);
  return ((unsigned char *)t + sizeof(*t) + ofs);
}
