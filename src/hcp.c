/*
 * $Id: hcp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last_neighast modified: Thu Dec  5 10:34:22 2013 mstenber
 * Edit time:     361 min
 *
 */

#include "hcp_i.h"
#include <libubox/md5.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  hcp_node n1 = (hcp_node) a, n2 = (hcp_node) b;

  return memcmp(&n1->node_identifier_hash, &n2->node_identifier_hash,
                HCP_HASH_LEN);
}

void hcp_schedule(hcp o)
{
  if (o->io_init_done)
    {
      if (o->immediate_scheduled)
        return;
      hcp_io_schedule(o, 0);
      o->immediate_scheduled = true;
    }
  else
    o->should_schedule = true;
}

bool hcp_node_set_tlvs(hcp_node n, struct tlv_attr *a)
{
  L_DEBUG("hcp_node_set_tlvs %llx/%p %p",
          hcp_hash64(&n->node_identifier_hash), n, a);
  if (n->tlv_container)
    {
      if (a && tlv_attr_equal(n->tlv_container, a))
        {
          free(a);
          return false;
        }
      hcp_notify_subscribers_tlvs_changed(n, n->tlv_container, a);
      free(n->tlv_container);
    }
  else
    hcp_notify_subscribers_tlvs_changed(n, NULL, a);
  n->tlv_container = a;
  n->hcp->network_hash_dirty = true;
  n->node_data_hash_dirty = true;
  n->hcp->neighbors_dirty = true;
  return true;
}


static void update_node(__unused struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hcp o = container_of(t, hcp_s, nodes);
  hcp_node n_old = container_of(node_old, hcp_node_s, in_nodes);
  __unused hcp_node n_new = container_of(node_new, hcp_node_s, in_nodes);

  if (n_old == n_new)
    return;
  if (n_old)
    {
      hcp_node_set_tlvs(n_old, NULL);
      hcp_notify_subscribers_node_changed(n_old, false);
      free(n_old);
    }
  if (n_new)
    {
      n_new->node_data_hash_dirty = true;
      hcp_notify_subscribers_node_changed(n_new, true);
    }
  o->network_hash_dirty = true;
  o->neighbors_dirty = true;
  hcp_schedule(o);
}


static int
compare_tlvs(const void *a, const void *b, void *ptr __unused)
{
  hcp_tlv t1 = (hcp_tlv) a, t2 = (hcp_tlv) b;

  return tlv_attr_cmp(&t1->tlv, &t2->tlv);
}

static void update_tlv(struct vlist_tree *t,
                       struct vlist_node *node_new,
                       struct vlist_node *node_old)
{
  hcp o = container_of(t, hcp_s, tlvs);
  hcp_tlv t_old = container_of(node_old, hcp_tlv_s, in_tlvs);
  __unused hcp_tlv t_new = container_of(node_new, hcp_tlv_s, in_tlvs);

  if (t_old)
    free(t_old);
  o->tlvs_dirty = true;
  hcp_schedule(o);
}

static int
compare_links(const void *a, const void *b, void *ptr __unused)
{
  hcp_link t1 = (hcp_link) a, t2 = (hcp_link) b;

  return strcmp(t1->ifname, t2->ifname);
}

bool hcp_link_join(hcp_link l)
{
  hcp o = l->hcp;

  if (!hcp_io_set_ifname_enabled(o, l->ifname, true))
    {
      l->join_pending = true;
      o->join_failed_time = hcp_time(l->hcp);
      return false;
    }
  l->join_pending = false;
  return true;
}

static void update_link(struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hcp o = container_of(t, hcp_s, links);
  hcp_link t_old = container_of(node_old, hcp_link_s, in_links);
  __unused hcp_link t_new = container_of(node_new, hcp_link_s, in_links);

  if (t_old)
    {
      if (!t_new && o->io_init_done)
        hcp_io_set_ifname_enabled(o, t_old->ifname, false);
      vlist_flush_all(&t_old->neighbors);
      free(t_old);
    }
  else
    {
      hcp_link_join(t_new);
    }
  o->links_dirty = true;
  hcp_schedule(o);
}

static int
compare_neighbors(const void *a, const void *b, void *ptr __unused)
{
  hcp_neighbor n1 = (hcp_neighbor) a, n2 = (hcp_neighbor) b;
  int r;

  r = memcmp(&n1->node_identifier_hash, &n2->node_identifier_hash,
             HCP_HASH_LEN);
  if (r)
    return r;
  return memcmp(&n1->iid, &n2->iid, sizeof(n1->iid));
}

static void update_neighbor(struct vlist_tree *t,
                            struct vlist_node *node_new,
                            struct vlist_node *node_old)
{
  hcp_link l = container_of(t, hcp_link_s, neighbors);
  hcp o = l->hcp;
  hcp_neighbor t_old = container_of(node_old, hcp_neighbor_s, in_neighbors);
  __unused hcp_neighbor t_new = container_of(node_new, hcp_neighbor_s, in_neighbors);

  if (t_old)
    free(t_old);
  o->links_dirty = true;
  hcp_schedule(o);
}

void hcp_calculate_hash(const void *buf, int len, hcp_hash dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}


hcp_node hcp_find_node_by_hash(hcp o, hcp_hash h, bool create)
{
  hcp_node ch = container_of(h, hcp_node_s, node_identifier_hash);
  hcp_node n = vlist_find(&o->nodes, ch, ch, in_nodes);

  if (n)
    return n;
  if (!create)
    return NULL;
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  n->node_identifier_hash = *h;
  n->hcp = o;
  vlist_add(&o->nodes, &n->in_nodes, n);
  return n;
}

bool hcp_init(hcp o, const void *node_identifier, int len)
{
  hcp_node n;
  hcp_hash_s h;

  memset(o, 0, sizeof(*o));
  INIT_LIST_HEAD(&o->subscribers);
  vlist_init(&o->nodes, compare_nodes, update_node);
  o->nodes.keep_old = true;
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->links, compare_links, update_link);
  hcp_calculate_hash(node_identifier, len, &h);
  if (!inet_pton(AF_INET6, HCP_MCAST_GROUP, &o->multicast_address))
    return false;
  n = hcp_find_node_by_hash(o, &h, true);
  if (!n)
    return false;
  o->own_node = n;
  o->tlvs_dirty = true; /* by default, they are, even if no neighbors yet. */
  o->first_free_iid = 1;
  return true;
}

hcp hcp_create(void)
{
  hcp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  /* hcp_init does memset 0 -> we can just malloc here. */
  o = malloc(sizeof(*o));
  if (!o)
    return NULL;
  c += hcp_io_get_hwaddrs(buf, sizeof(buf));
  if (c == buf)
    goto err;
  if (!hcp_init(o, buf, c-buf))
    goto err;
  if (!hcp_io_init(o))
    goto err2;
  o->io_init_done = true;
  if (o->should_schedule)
    hcp_schedule(o);
  return o;
 err2:
  vlist_flush_all(&o->nodes);
 err:
  free(o);
  return NULL;
}

void hcp_uninit(hcp o)
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

void hcp_destroy(hcp o)
{
  if (!o) return;
  hcp_io_uninit(o);
  hcp_uninit(o);
  free(o);
}

hcp_node hcp_get_first_node(hcp o)
{
  hcp_node n;

  return avl_is_empty(&o->nodes.avl) ? NULL :
    avl_first_element(&o->nodes.avl, n, in_nodes.avl);
}

static hcp_tlv _add_tlv(hcp o, struct tlv_attr *tlv)
{
  hcp_tlv t;
  int s = tlv_pad_len(tlv);

  t = calloc(1, sizeof(*t) + s - sizeof(*tlv));
  if (!t) return NULL;
  memcpy(&t->tlv, tlv, s);
  vlist_add(&o->tlvs, &t->in_tlvs, t);
  return t;
}

struct tlv_attr *hcp_add_tlv(hcp o, struct tlv_attr *tlv)
{
  hcp_tlv t = _add_tlv(o, tlv);

  if (t)
    {
      /* These are not expired. */
      t->in_tlvs.version = -1;
      return &t->tlv;
    }
  return NULL;
}

bool hcp_remove_tlv(hcp o, struct tlv_attr *tlv)
{
  /* kids, don't do this at home, the pointer itself is invalid,
     but it _should_ work as comparison operator only operates on
     n->tlv. */
  hcp_tlv t = container_of(tlv, hcp_tlv_s, tlv);
  hcp_tlv old = vlist_find(&o->tlvs, t, t, in_tlvs);

  if (!old)
    return false;
  vlist_delete(&o->tlvs, &old->in_tlvs);
  return true;
}

hcp_link hcp_find_link_by_name(hcp o, const char *ifname, bool create)
{
  hcp_link cl = container_of(ifname, hcp_link_s, ifname[0]);
  hcp_link l;

  if (!ifname)
    return NULL;

  l = vlist_find(&o->links, cl, cl, in_links);

  if (create && !l)
    {
      l = (hcp_link) calloc(1, sizeof(*l));
      if (!l)
        return NULL;
      l->hcp = o;
      l->iid = o->first_free_iid++;
      vlist_init(&l->neighbors, compare_neighbors, update_neighbor);
      strcpy(l->ifname, ifname);
      vlist_add(&o->links, &l->in_links, l);
    }
  return l;
}

hcp_link hcp_find_link_by_id(hcp o, uint32_t link_id)
{
  hcp_link l;
  /* XXX - this could be also made more efficient. Oh well. */
  vlist_for_each_element(&o->links, l, in_links)
    if (l->iid == link_id)
      return l;
  return NULL;
}

bool hcp_set_link_enabled(hcp o, const char *ifname, bool enabled)
{
  hcp_link old = hcp_find_link_by_name(o, ifname, false);

  if (!enabled)
    {
      if (!old)
        return false;
      vlist_delete(&o->links, &old->in_links);
      return true;
    }
  if (old)
    return false;
  return hcp_find_link_by_name(o, ifname, true) != NULL;
}


bool hcp_node_is_self(hcp_node n)
{
  return n->hcp->own_node == n;
}

hcp_node hcp_node_get_next(hcp_node n)
{
  hcp o = n->hcp;
  hcp_node last = avl_last_element(&o->nodes.avl, n, in_nodes.avl);
  if (!n || n == last)
    return NULL;
  return avl_next_element(n, in_nodes.avl);
}

void hcp_self_flush(hcp_node n)
{
  hcp o = n->hcp;
  hcp_tlv t;
  hcp_link l;
  hcp_neighbor ne;
  struct tlv_buf tb;

  if (o->links_dirty)
    {
      o->links_dirty = false;
      /* Rather crude: We simply get rid of existing link TLVs, and
       * publish new ones. Assumption: Whatever is added using
       * hcp_add_tlv will have version=-1, and dynamically generated
       * content (like links) won't => we can just add the new entries
       * and ignore manually added and/or outdated things. */
      vlist_update(&o->tlvs);

      vlist_for_each_element(&o->links, l, in_links)
        {
          vlist_for_each_element(&l->neighbors, ne, in_neighbors)
            {
              unsigned char buf[TLV_SIZE + sizeof(hcp_t_node_data_neighbor_s)];
              struct tlv_attr *nt = (struct tlv_attr *)buf;

              tlv_init(nt,
                       HCP_T_NODE_DATA_NEIGHBOR,
                       TLV_SIZE + sizeof(hcp_t_node_data_neighbor_s));
              hcp_t_node_data_neighbor d = tlv_data(nt);

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

  hcp_notify_subscribers_about_to_republish_tlvs(n);

  /* Dump the contents of hcp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    if (!tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv)))
      {
        L_ERR("hcp_self_flush: tlv_put_raw failed?!?");
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
  if (!hcp_node_set_tlvs(n, tb.head))
    {
      L_DEBUG("hcp_self_flush: state did not change -> nothing to flush");
      return;
    }
  n->update_number++;
  n->origination_time = hcp_time(o);
  o->network_hash_dirty = true;
  hcp_schedule(o);
  L_DEBUG("hcp_self_flush: %p -> update_number = %d @ %lld",
          n, n->update_number, n->origination_time);
}

struct tlv_attr *hcp_node_get_tlvs(hcp_node n)
{
  if (hcp_node_is_self(n))
    hcp_self_flush(n);
  return n->tlv_container;
}


void hcp_calculate_node_data_hash(hcp_node n)
{
  md5_ctx_t ctx;
  int l;
  unsigned char buf[TLV_SIZE + sizeof(hcp_t_node_data_header_s)];
  struct tlv_attr *h = (struct tlv_attr *)buf;
  hcp_t_node_data_header ndh = tlv_data(h);

  if (!n->node_data_hash_dirty)
    return;

  l = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  tlv_init(h, HCP_T_NODE_DATA, sizeof(buf) + l);
  ndh->node_identifier_hash = n->node_identifier_hash;
  ndh->update_number = cpu_to_be32(n->update_number);
  md5_begin(&ctx);
  md5_hash(buf, sizeof(buf), &ctx);
  if (l)
    md5_hash(tlv_data(n->tlv_container), l, &ctx);
  md5_end(&n->node_data_hash, &ctx);
  n->node_data_hash_dirty = false;
  L_DEBUG("hcp_calculate_node_data_hash @%p %llx=%llx%s",
          n->hcp, hcp_hash64(&n->node_identifier_hash),
          hcp_hash64(&n->node_data_hash),
          n == n->hcp->own_node ? " [self]" : "");
}

void hcp_calculate_network_hash(hcp o)
{
  hcp_node n;
  md5_ctx_t ctx;

  if (!o->network_hash_dirty)
    return;
  md5_begin(&ctx);
  vlist_for_each_element(&o->nodes, n, in_nodes)
    {
      hcp_calculate_node_data_hash(n);
      md5_hash(&n->node_data_hash, HCP_HASH_LEN, &ctx);
    }
  md5_end(&o->network_hash, &ctx);
  L_DEBUG("hcp_calculate_network_hash @%p =%llx",
          o, hcp_hash64(&o->network_hash));
  o->network_hash_dirty = false;
}
