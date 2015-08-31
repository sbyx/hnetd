/*
 * $Id: dncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Thu Jul  2 11:43:05 2015 mstenber
 * Edit time:     1000 min
 *
 */

#include "dncp_i.h"
#include <net/ethernet.h>
#include <arpa/inet.h>

int dncp_node_cmp(dncp_node n1, dncp_node n2)
{
  return memcmp(&n1->node_id, &n2->node_id, DNCP_NI_LEN(n1->dncp));
}

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  dncp_node n1 = (dncp_node) a, n2 = (dncp_node) b;

  return dncp_node_cmp(n1, n2);
}

void dncp_schedule(dncp o)
{
  if (o->immediate_scheduled)
    return;
  o->ext->cb.schedule_timeout(o->ext, 0);
  o->immediate_scheduled = true;
}

void dncp_node_set(dncp_node n, uint32_t update_number,
                   hnetd_time_t t, struct tlv_attr *a)
{
  struct tlv_attr *a_valid = a;

  L_DEBUG("dncp_node_set %s update #%d %p (@%lld (-%lld))",
          DNCP_NODE_REPR(n), (int) update_number, a,
          (long long)t, (long long)(hnetd_time()-t));

  /* If the data is same, and update number is same, skip. */
  if (update_number == n->update_number
      && (!a || tlv_attr_equal(a, n->tlv_container)))
    {
      L_DEBUG(" .. spurious (no change, we ignore time delta)");
      if (a && a != n->tlv_container)
        free(a);
      return;
    }

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
        }
      else
        {
          a_valid = n->dncp->ext->cb.validate_node_data(n, a);
        }
    }

  /* Replace update number if any */
  n->update_number = update_number;

  /* Replace origination time if any */
  if (t)
    {
      n->origination_time = t;
      n->expiration_time = t + ((1LL << 32) - (1LL << 15));
    }

  /* If the pointer changed, handle it */
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
      n->node_data_hash_dirty = true;
      n->dncp->graph_dirty = true;
    }

  /* _anything_ we do here dirties network hash. */
  n->dncp->network_hash_dirty = true;

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
compare_eps(const void *a, const void *b, void *ptr __unused)
{
  dncp_ep_i t1 = (dncp_ep_i) a, t2 = (dncp_ep_i) b;

  return strcmp(t1->conf.ifname, t2->conf.ifname);
}

static void update_ep(struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  dncp o = container_of(t, dncp_s, eps);
  dncp_ep_i t_old = container_of(node_old, dncp_ep_i_s, in_eps);
  dncp_ep_i t_new = container_of(node_new, dncp_ep_i_s, in_eps);

  if (t_old)
    {
      free(t_old);
    }
  else
    {
      t_new->published_keepalive_interval = DNCP_KEEPALIVE_INTERVAL(o);
    }
  dncp_schedule(o);
}


dncp_node
dncp_find_node_by_node_id(dncp o, void *ni, bool create)
{
  /* Unfortunately as DNCP_NI_LEN refers to node -> dncp, we cannot
   * simply use the dncp_node_id pointer as is anymore.. */
  dncp_node_s fake_node = { .dncp = o };
  memcpy(&fake_node.node_id, ni, DNCP_NI_LEN(o));

  dncp_node n = vlist_find(&o->nodes, &fake_node, &fake_node, in_nodes);

  if (n)
    return n;
  if (!create)
    return NULL;
  n = calloc(1, sizeof(*n) + o->ext->conf.ext_node_data_size);
  if (!n)
    return false;
  memcpy(&n->node_id, ni, DNCP_NI_LEN(o));
  n->dncp = o;
  n->tlv_index_dirty = true;
  vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}

bool dncp_init(dncp o, dncp_ext ext, const void *node_id, int len)
{
  union __packed {
    dncp_hash_s h;
    dncp_node_id_s ni;
  } nih;
  int i;

  memset(o, 0, sizeof(*o));
  o->ext = ext;
  for (i = 0 ; i < NUM_DNCP_CALLBACKS; i++)
    INIT_LIST_HEAD(&o->subscribers[i]);
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->eps, compare_eps, update_ep);
  memset(&nih, 0, sizeof(nih));
  ext->cb.hash(node_id, len, &nih.h);
  o->first_free_ep_id = 1;
  o->last_prune = 1;
  /* this way new nodes with last_prune=0 won't be reachable */
  return dncp_set_own_node_id(o, &nih.ni);
}

bool dncp_set_own_node_id(dncp o, void *nibuf)
{
  if (o->own_node)
    {
      vlist_delete(&o->nodes, &o->own_node->in_nodes);
      o->own_node = NULL;
    }
  dncp_node_id_s ni;
  memset(&ni, 0, sizeof(ni));
  memcpy(&ni, nibuf, DNCP_NI_LEN(o));
  dncp_node n = dncp_find_node_by_node_id(o, &ni, true);
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

dncp dncp_create(dncp_ext ext)
{
  dncp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  /* dncp_init does memset 0 -> we can just malloc here. */
  o = malloc(sizeof(*o));
  if (!o)
    return NULL;
  c += ext->cb.get_hwaddrs(ext, buf, sizeof(buf));
  if (c == buf)
    {
      L_ERR("no hardware address available, fatal error");
      goto err;
    }
  if (!dncp_init(o, ext, buf, c-buf))
    {
      /* Error produced elsewhere .. */
      goto err;
    }
  return o;
 err:
  free(o);
  return NULL;
}

void dncp_uninit(dncp o)
{
  /* TLVs should be freed first; they're local phenomenom, but may be
   * reflected on eps/nodes. */
  vlist_flush_all(&o->tlvs);

  /* Link destruction will refer to node -> have to be taken out
   * before nodes. */
  vlist_flush_all(&o->eps);

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

dncp_tlv dncp_get_first_tlv(dncp o)
{
  dncp_tlv t;

  if (avl_is_empty(&o->tlvs.avl))
    return NULL;
  t = avl_first_element(&o->tlvs.avl, t, in_tlvs.avl);
  return t;
}

dncp_ep dncp_get_first_ep(dncp o)
{
  if (avl_is_empty(&o->eps.avl))
    return NULL;
  dncp_ep_i l = avl_first_element(&o->eps.avl, l, in_eps.avl);
  return &l->conf;
}


dncp_tlv
dncp_add_tlv(dncp o, uint16_t type, void *data, uint16_t len, int extra_bytes)
{
  int plen =
    (TLV_SIZE + len + TLV_ATTR_ALIGN - 1) & ~(TLV_ATTR_ALIGN - 1);
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

dncp_ep dncp_find_ep_by_name(dncp o, const char *ifname)
{
  dncp_ep_i cl = container_of(ifname, dncp_ep_i_s, conf.ifname[0]);
  dncp_ep_i l;

  if (!ifname || !*ifname)
    return NULL;

  l = vlist_find(&o->eps, cl, cl, in_eps);

  if (l)
    return &l->conf;
  l = (dncp_ep_i) calloc(1, sizeof(*l) + o->ext->conf.ext_ep_data_size);
  if (!l)
    return NULL;
  l->dncp = o;
  l->ep_id = o->first_free_ep_id++;
  l->conf = o->ext->conf.per_ep;
  strncpy(l->conf.dnsname, ifname, sizeof(l->conf.ifname));
  strncpy(l->conf.ifname, ifname, sizeof(l->conf.ifname));
  vlist_add(&o->eps, &l->in_eps, l);
  return &l->conf;
}

dncp_ep dncp_find_ep_by_id(dncp o, uint32_t ep_id)
{
  dncp_ep_i l;
  /* XXX - this could be also made more efficient. Oh well. */
  vlist_for_each_element(&o->eps, l, in_eps)
    if (l->ep_id == ep_id)
      return &l->conf;
  return NULL;
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

dncp_ep dncp_ep_get_next(dncp_ep ep)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
  dncp o = l->dncp;
  dncp_ep_i last = avl_last_element(&o->eps.avl, l, in_eps.avl);

  if (!ep || l == last)
    return NULL;
  l = avl_next_element(l, in_eps.avl);
  return &l->conf;
}

dncp_tlv dncp_get_next_tlv(dncp o, dncp_tlv n)
{
  dncp_tlv last = avl_last_element(&o->tlvs.avl, n, in_tlvs.avl);

  if (!n || n == last)
    return NULL;
  n = avl_next_element(n, in_tlvs.avl);
  return n;
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
  dncp_node_set(n, n->update_number + 1, dncp_time(o),
                a ? a : n->tlv_container);
}

struct tlv_attr *dncp_node_get_tlvs(dncp_node n)
{
  return n->tlv_container_valid;
}


void dncp_calculate_node_data_hash(dncp_node n)
{
  int l;

  if (!n->node_data_hash_dirty)
    return;
  n->node_data_hash_dirty = false;
  l = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  n->dncp->ext->cb.hash(tlv_data(n->tlv_container), l, &n->node_data_hash);
  L_DEBUG("dncp_calculate_node_data_hash %s=%s%s",
          DNCP_NODE_REPR(n),
          DNCP_HASH_REPR(n->dncp, &n->node_data_hash),
          n == n->dncp->own_node ? " [self]" : "");
}

void dncp_calculate_network_hash(dncp o)
{
  dncp_node n;

  if (!o->network_hash_dirty)
    return;

  /* Store original network hash for future study. */
  dncp_hash_s old_hash = o->network_hash;

  int cnt = 0;
  dncp_for_each_node(o, n)
    cnt++;
  int onelen = 4 + DNCP_HASH_LEN(o);
  void *buf = malloc(cnt * onelen);
  if (!buf)
    return;
  void *dst = buf;
  dncp_for_each_node(o, n)
    {
      dncp_calculate_node_data_hash(n);
      *((uint32_t *)dst) = cpu_to_be32(n->update_number);
      memcpy(dst + 4, &n->node_data_hash, DNCP_HASH_LEN(o));
      L_DEBUG(".. %s/%d=%s",
              DNCP_NODE_REPR(n), n->update_number,
              DNCP_HASH_REPR(n->dncp, &n->node_data_hash));
      dst += onelen;
    }
  o->ext->cb.hash(buf, cnt * onelen, &o->network_hash);
  free(buf);
  L_DEBUG("dncp_calculate_network_hash =%s",
          DNCP_HASH_REPR(o, &o->network_hash));

  if (memcmp(&old_hash, &o->network_hash, DNCP_HASH_LEN(o)))
    dncp_trickle_reset(o);

  o->network_hash_dirty = false;
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


bool dncp_ep_has_highest_id(dncp_ep ep)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
  dncp o = l->dncp;
  uint32_t ep_id = l->ep_id;
  struct tlv_attr *a;
  dncp_t_peer nh;

  dncp_node_for_each_tlv_with_t_v(o->own_node, a, DNCP_T_PEER, false)
    if ((nh = dncp_tlv_peer(o, a)))
      {
        if (nh->ep_id != ep_id)
          continue;

        if (memcmp(dncp_tlv_get_node_id(o, nh),
                   &o->own_node->node_id, DNCP_NI_LEN(o)) > 0)
          return false;
      }
  return true;
}


void dncp_node_recalculate_index(dncp_node n)
{
  int size = n->dncp->num_tlv_indexes * 4 * sizeof(n->tlv_index[0]);

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
  tlv_for_each_attr(a, n->tlv_container)
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

  /* TBD: What if n->tlv_container_valid && n->tlv_container_valid !=
   * n->tlv_container (currently we do not support rewriting, but at
   * some point we might); iterate again? */
  if (size
      && n->tlv_container_valid && n->tlv_container_valid == n->tlv_container)
    memcpy((void *)n->tlv_index + size / 2, n->tlv_index, size / 2);
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

void *dncp_ep_get_ext_data(dncp_ep n)
{
  dncp_ep_i l = container_of(n, dncp_ep_i_s, conf);
  return (void*)l+sizeof(*l);
}

void *dncp_node_get_ext_data(dncp_node n)
{
  return (void*)n+sizeof(*n);
}

dncp_node dncp_node_from_ext_data(void *ext_data)
{
  return ext_data - sizeof(dncp_node_s);
}

dncp_ep dncp_ep_from_ext_data(void *ext_data)
{
  dncp_ep_i l = ext_data - sizeof(dncp_ep_i_s);
  return &l->conf;
}

struct tlv_attr *
dncp_node_get_tlv_with_type(dncp_node n, uint16_t type, bool first, bool valid)
{
  if (type >= n->dncp->tlv_type_to_index_length
      || !n->dncp->tlv_type_to_index[type])
    if (!dncp_add_tlv_index(n->dncp, type))
      return NULL;
  if (n->tlv_index_dirty)
    {
      dncp_node_recalculate_index(n);
      if (!n->tlv_index)
        return NULL;
    }
  int index = n->dncp->tlv_type_to_index[type] - 1 +
    (valid ? n->dncp->num_tlv_indexes : 0);
  int i = index * 2 + (first ? 0 : 1);
  return n->tlv_index[i];
}

dncp_node dncp_get_own_node(dncp o)
{
  return o->own_node;
}

void *dncp_node_get_id(dncp_node n)
{
  return &n->node_id;
}

dncp dncp_node_get_dncp(dncp_node n)
{
  return n->dncp;
}

const char *dncp_node_repr(dncp_node n, char *to_buf)
{
  return hex_repr(to_buf, &n->node_id, DNCP_NI_LEN(n->dncp));
}

dncp dncp_ep_get_dncp(dncp_ep ep)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
  return l->dncp;
}

ep_id_t dncp_ep_get_id(dncp_ep ep)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);

  return ep ? l->ep_id : 0;
}

bool dncp_ep_is_enabled(dncp_ep ep)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
  return ep && l->enabled;
}

dncp_ext dncp_get_ext(dncp o)
{
  return o->ext;
}

hnetd_time_t dncp_node_get_origination_time(dncp_node n)
{
  return n->origination_time;
}

struct tlv_attr *dncp_tlv_get_attr(dncp_tlv tlv)
{
  return &tlv->tlv;
}
