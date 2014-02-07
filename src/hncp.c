/*
 * $Id: hncp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last_neighast modified: Thu Dec  5 10:34:22 2013 mstenber
 * Edit time:     383 min
 *
 */

#include "hncp_i.h"
#include <libubox/md5.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

int hncp_node_cmp(hncp_node n1, hncp_node n2)
{
  return memcmp(&n1->node_identifier_hash, &n2->node_identifier_hash,
                HNCP_HASH_LEN);
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

bool hncp_node_set_tlvs(hncp_node n, struct tlv_attr *a)
{
  L_DEBUG("hncp_node_set_tlvs %llx/%p %p",
          hncp_hash64(&n->node_identifier_hash), n, a);
  if (n->tlv_container)
    {
      if (a && tlv_attr_equal(n->tlv_container, a))
        {
          free(a);
          return false;
        }
      hncp_notify_subscribers_tlvs_changed(n, n->tlv_container, a);
      free(n->tlv_container);
    }
  else
    hncp_notify_subscribers_tlvs_changed(n, NULL, a);
  n->tlv_container = a;
  n->hncp->network_hash_dirty = true;
  n->node_data_hash_dirty = true;
  n->hncp->neighbors_dirty = true;
  return true;
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
      hncp_node_set_tlvs(n_old, NULL);
      hncp_notify_subscribers_node_changed(n_old, false);
      free(n_old);
    }
  if (n_new)
    {
      n_new->node_data_hash_dirty = true;
      hncp_notify_subscribers_node_changed(n_new, true);
    }
  o->network_hash_dirty = true;
  o->neighbors_dirty = true;
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

bool hncp_link_join(hncp_link l)
{
  hncp o = l->hncp;

  if (!hncp_io_set_ifname_enabled(o, l->ifname, true))
    {
      l->join_pending = true;
      o->join_failed_time = hncp_time(l->hncp);
      return false;
    }
  l->join_pending = false;
  return true;
}

static void update_link(struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hncp o = container_of(t, hncp_s, links);
  hncp_link t_old = container_of(node_old, hncp_link_s, in_links);
  __unused hncp_link t_new = container_of(node_new, hncp_link_s, in_links);

  if (t_old)
    {
      if (!t_new && o->io_init_done)
        hncp_io_set_ifname_enabled(o, t_old->ifname, false);
      vlist_flush_all(&t_old->neighbors);
      free(t_old);
    }
  else
    {
      hncp_link_join(t_new);
    }
  o->links_dirty = true;
  hncp_schedule(o);
}

static int
compare_neighbors(const void *a, const void *b, void *ptr __unused)
{
  hncp_neighbor n1 = (hncp_neighbor) a, n2 = (hncp_neighbor) b;
  int r;

  r = memcmp(&n1->node_identifier_hash, &n2->node_identifier_hash,
             HNCP_HASH_LEN);
  if (r)
    return r;
  return memcmp(&n1->iid, &n2->iid, sizeof(n1->iid));
}

static void update_neighbor(struct vlist_tree *t,
                            struct vlist_node *node_new,
                            struct vlist_node *node_old)
{
  hncp_link l = container_of(t, hncp_link_s, neighbors);
  hncp o = l->hncp;
  hncp_neighbor t_old = container_of(node_old, hncp_neighbor_s, in_neighbors);
  __unused hncp_neighbor t_new = container_of(node_new, hncp_neighbor_s, in_neighbors);

  if (t_old)
    free(t_old);
  o->links_dirty = true;
  hncp_schedule(o);
}

void hncp_calculate_hash(const void *buf, int len, hncp_hash dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}


hncp_node hncp_find_node_by_hash(hncp o, hncp_hash h, bool create)
{
  hncp_node ch = container_of(h, hncp_node_s, node_identifier_hash);
  hncp_node n = vlist_find(&o->nodes, ch, ch, in_nodes);

  if (n)
    return n;
  if (!create)
    return NULL;
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  n->node_identifier_hash = *h;
  n->hncp = o;
  vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}

bool hncp_init(hncp o, const void *node_identifier, int len)
{
  hncp_node n;
  hncp_hash_s h;

  memset(o, 0, sizeof(*o));
  INIT_LIST_HEAD(&o->subscribers);
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->links, compare_links, update_link);
  hncp_calculate_hash(node_identifier, len, &h);
  if (!inet_pton(AF_INET6, HNCP_MCAST_GROUP, &o->multicast_address))
    return false;
  n = hncp_find_node_by_hash(o, &h, true);
  if (!n)
    return false;
  o->own_node = n;
  o->tlvs_dirty = true; /* by default, they are, even if no neighbors yet. */
  o->first_free_iid = 1;
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
  if (c == buf)
    goto err;
  if (!hncp_init(o, buf, c-buf))
    goto err;
  if (!hncp_io_init(o))
    goto err2;
  o->io_init_done = true;
  if (o->should_schedule)
    hncp_schedule(o);
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

  return avl_is_empty(&o->nodes.avl) ? NULL :
    avl_first_element(&o->nodes.avl, n, in_nodes.avl);
}

static hncp_tlv _add_tlv(hncp o, struct tlv_attr *tlv)
{
  hncp_tlv t;
  int s = tlv_pad_len(tlv);

  t = calloc(1, sizeof(*t) + s - sizeof(*tlv));
  if (!t) return NULL;
  memcpy(&t->tlv, tlv, s);
  vlist_add(&o->tlvs, &t->in_tlvs, t);
  return t;
}

struct tlv_attr *hncp_add_tlv(hncp o, struct tlv_attr *tlv)
{
  hncp_tlv t = _add_tlv(o, tlv);

  if (t)
    {
      /* These are not expired. */
      t->in_tlvs.version = -1;
      return &t->tlv;
    }
  return NULL;
}

bool hncp_remove_tlv(hncp o, struct tlv_attr *tlv)
{
  /* kids, don't do this at home, the pointer itself is invalid,
     but it _should_ work as comparison operator only operates on
     n->tlv. */
  hncp_tlv t = container_of(tlv, hncp_tlv_s, tlv);
  hncp_tlv old = vlist_find(&o->tlvs, t, t, in_tlvs);

  if (!old)
    return false;
  vlist_delete(&o->tlvs, &old->in_tlvs);
  return true;
}

hncp_link hncp_find_link_by_name(hncp o, const char *ifname, bool create)
{
  hncp_link cl = container_of(ifname, hncp_link_s, ifname[0]);
  hncp_link l;

  if (!ifname)
    return NULL;

  l = vlist_find(&o->links, cl, cl, in_links);

  if (create && !l)
    {
      l = (hncp_link) calloc(1, sizeof(*l));
      if (!l)
        return NULL;
      l->hncp = o;
      l->iid = o->first_free_iid++;
      vlist_init(&l->neighbors, compare_neighbors, update_neighbor);
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

bool hncp_set_link_enabled(hncp o, const char *ifname, bool enabled)
{
  hncp_link old = hncp_find_link_by_name(o, ifname, false);

  L_DEBUG("hncp_set_link_enabled %s %s",
          ifname, enabled ? "enabled" : "disabled");
  if (!enabled)
    {
      if (!old)
        return false;
      vlist_delete(&o->links, &old->in_links);
      return true;
    }
  if (old)
    return false;
  return hncp_find_link_by_name(o, ifname, true) != NULL;
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
  return avl_next_element(n, in_nodes.avl);
}

void hncp_self_flush(hncp_node n)
{
  hncp o = n->hncp;
  hncp_tlv t;
  hncp_link l;
  hncp_neighbor ne;
  struct tlv_buf tb;

  if (o->links_dirty)
    {
      o->links_dirty = false;
      /* Rather crude: We simply get rid of existing link TLVs, and
       * publish new ones. Assumption: Whatever is added using
       * hncp_add_tlv will have version=-1, and dynamically generated
       * content (like links) won't => we can just add the new entries
       * and ignore manually added and/or outdated things. */
      vlist_update(&o->tlvs);

      vlist_for_each_element(&o->links, l, in_links)
        {
          vlist_for_each_element(&l->neighbors, ne, in_neighbors)
            {
              unsigned char buf[TLV_SIZE + sizeof(hncp_t_node_data_neighbor_s)];
              struct tlv_attr *nt = (struct tlv_attr *)buf;

              tlv_init(nt,
                       HNCP_T_NODE_DATA_NEIGHBOR,
                       TLV_SIZE + sizeof(hncp_t_node_data_neighbor_s));
              hncp_t_node_data_neighbor d = tlv_data(nt);

              d->neighbor_node_identifier_hash = ne->node_identifier_hash;
              d->neighbor_link_id = cpu_to_be32(ne->iid);
              d->link_id = cpu_to_be32(l->iid);

              _add_tlv(o, nt);
            }
        }

      vlist_flush(&o->tlvs);
    }

  if (!o->tlvs_dirty)
    return;

  hncp_notify_subscribers_about_to_republish_tlvs(n);

  /* Dump the contents of hncp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    if (!tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv)))
      {
        L_ERR("hncp_self_flush: tlv_put_raw failed?!?");
        tlv_buf_free(&tb);
        return;
      }
  tlv_fill_pad(tb.head);

  /* Ok, all puts _did_ succeed. */
  o->tlvs_dirty = false;

  /* Should we check if this caused a real change or not? If we
   * should, and there wasn't any, we should just free tb's contents
   * and bail out.*/

  /* Replace old state with new _if_ it's really new. */
  if (!hncp_node_set_tlvs(n, tb.head))
    {
      L_DEBUG("hncp_self_flush: state did not change -> nothing to flush");
      return;
    }
  n->update_number++;
  n->origination_time = hncp_time(o);
  o->network_hash_dirty = true;
  hncp_schedule(o);
  L_DEBUG("hncp_self_flush: %p -> update_number = %d @ %lld",
          n, n->update_number, (long long)n->origination_time);
}

struct tlv_attr *hncp_node_get_tlvs(hncp_node n)
{
  if (hncp_node_is_self(n))
    hncp_self_flush(n);
  return n->tlv_container;
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
  ndh->node_identifier_hash = n->node_identifier_hash;
  ndh->update_number = cpu_to_be32(n->update_number);
  md5_begin(&ctx);
  md5_hash(buf, sizeof(buf), &ctx);
  if (l)
    md5_hash(tlv_data(n->tlv_container), l, &ctx);
  md5_end(&n->node_data_hash, &ctx);
  n->node_data_hash_dirty = false;
  L_DEBUG("hncp_calculate_node_data_hash @%p %llx=%llx%s",
          n->hncp, hncp_hash64(&n->node_identifier_hash),
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
  vlist_for_each_element(&o->nodes, n, in_nodes)
    {
      hncp_calculate_node_data_hash(n);
      md5_hash(&n->node_data_hash, HNCP_HASH_LEN, &ctx);
    }
  md5_end(&o->network_hash, &ctx);
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


void
hncp_link_set_ipv6_address(hncp_link l, const struct in6_addr *addr)
{
  if (!addr && !l->has_ipv6_address)
    return;
  if (addr && l->has_ipv6_address
      && memcmp(&l->ipv6_address, addr, sizeof(*addr) == 0))
    return;
  l->has_ipv6_address = addr != NULL;
  if (addr)
    l->ipv6_address = *addr;
  hncp_notify_subscribers_link_ipv6_address_changed(l);
}

void
hncp_set_ipv6_address(hncp o, const char *ifname, const struct in6_addr *a)
{
  hncp_link l = hncp_find_link_by_name(o, ifname, false);
  if (l)
    hncp_link_set_ipv6_address(l, a);
}
