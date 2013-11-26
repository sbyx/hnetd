/*
 * $Id: hcp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Tue Nov 26 08:22:10 2013 mstenber
 * Edit time:     199 min
 *
 */

#include "hcp_i.h"
#include <libubox/md5.h>
#include <net/ethernet.h>

/* Once per second */
#define HCP_REJOIN_INTERVAL 1000

static int
compare_nodes(const void *a, const void *b, void *ptr __unused)
{
  hcp_node n1 = (hcp_node) a, n2 = (hcp_node) b;

  return memcmp(n1->node_identifier_hash, n2->node_identifier_hash,
                HCP_HASH_LEN);
}

static void update_node(__unused struct vlist_tree *t,
                        struct vlist_node *node_new,
                        struct vlist_node *node_old)
{
  hcp o = container_of(t, hcp_s, nodes);
  hcp_node n_old = container_of(node_old, hcp_node_s, in_nodes);
  __unused hcp_node n_new = container_of(node_new, hcp_node_s, in_nodes);

  if (n_old)
    {
      if (n_old->tlv_container)
        free(n_old->tlv_container);
      free(n_old);
    }
  o->network_hash_dirty = true;
  hcp_io_schedule(o, 0);
}


static int
compare_tlvs(const void *a, const void *b, void *ptr __unused)
{
  hcp_tlv t1 = (hcp_tlv) a, t2 = (hcp_tlv) b;
  int s1 = tlv_pad_len(&t1->tlv);
  int s2 = tlv_pad_len(&t2->tlv);
  int s = s1 < s2 ? s1 : s2;
  int r = memcmp(&t1->tlv, &t2->tlv, s);

  if (r == 0 && s1 != s2)
    return s1 < s2 ? -1 : 1;
  return r;
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
}

static int
compare_links(const void *a, const void *b, void *ptr __unused)
{
  hcp_link t1 = (hcp_link) a, t2 = (hcp_link) b;

  return strcmp(t1->ifname, t2->ifname);
}

static bool _join(hcp o, hcp_link l, hnetd_time_t now)
{
  if (!hcp_io_set_ifname_enabled(o, l->ifname, true))
    {
      l->join_pending = true;
      o->join_failed_time = now ? now : hnetd_time();
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
      if (!t_new)
        {
          hcp_io_set_ifname_enabled(o, t_old->ifname, false);
        }
      vlist_flush_all(&t_old->neighbors);
      free(t_old);
    }
  else
    {
      if (!_join(o, t_new, 0))
        hcp_io_schedule(o, 0);
    }
  o->links_dirty = true;
}

static int
compare_neighbors(const void *a, const void *b, void *ptr __unused)
{
  hcp_neighbor n1 = (hcp_neighbor) a, n2 = (hcp_neighbor) b;
  int r;

  r = memcmp(n1->node_identifier_hash, n2->node_identifier_hash,
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
}



void hcp_hash(const void *buf, int len, unsigned char *dest)
{
  md5_ctx_t ctx;

  md5_begin(&ctx);
  md5_hash(buf, len, &ctx);
  md5_end(dest, &ctx);
}


bool hcp_init(hcp o, unsigned char *node_identifier, int len)
{
  hcp_node n;

  vlist_init(&o->nodes, compare_nodes, update_node);
  vlist_init(&o->tlvs, compare_tlvs, update_tlv);
  vlist_init(&o->links, compare_links, update_link);
  n = calloc(1, sizeof(*n));
  if (!n)
    return false;
  hcp_hash(node_identifier, len, n->node_identifier_hash);
  n->hcp = o;
  vlist_add(&o->nodes, &n->in_nodes, n);
  o->own_node = n;
  return true;
}

hcp hcp_create(void)
{
  hcp o;
  unsigned char buf[ETHER_ADDR_LEN * 2], *c = buf;

  o = calloc(1, sizeof(*o));
  if (!o)
    goto err;
  /* XXX - this is very arbitrary and Linux-only. However, hopefully
   * it is enough (should probably have ifname(s) as argument). */
  c += hcp_io_get_hwaddr("eth0", c, sizeof(buf) + buf - c);
  c += hcp_io_get_hwaddr("eth1", c, sizeof(buf) + buf - c);
  if (c == buf)
    goto err;
  if (!hcp_init(o, buf, c-buf))
    goto err;
  if (!hcp_io_init(o))
    goto err;
  return o;
 err:
  if (o) free(o);
  return NULL;
}

void hcp_destroy(hcp o)
{
  if (!o) return;
  hcp_io_uninit(o);
  vlist_flush_all(&o->nodes);
  vlist_flush_all(&o->tlvs);
  vlist_flush_all(&o->links);
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

bool hcp_add_tlv(hcp o, struct tlv_attr *tlv)
{
  hcp_tlv t = _add_tlv(o, tlv);

  /* These are not expired. */
  if (t)
    t->in_tlvs.version = -1;
  return t != NULL;
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

bool hcp_set_link_enabled(hcp o, const char *ifname, bool enabled)
{
  hcp_link l = container_of(ifname, hcp_link_s, ifname);
  hcp_link old = vlist_find(&o->links, l, l, in_links);

  if (!enabled)
    {
      if (!old)
        return false;
      vlist_delete(&o->links, &old->in_links);
      return true;
    }
  if (old)
    return false;

  l = (hcp_link) calloc(1, sizeof(*l));
  if (!l)
    return false;
  l->iid = o->first_free_iid++;
  vlist_init(&l->neighbors, compare_neighbors, update_neighbor);
  strcpy(l->ifname, ifname);
  vlist_add(&o->links, &l->in_links, l);
  return true;
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

static void _flush(hcp_node n)
{
  hcp o = n->hcp;
  hcp_tlv t;
  hcp_link l;
  hcp_neighbor ne;
  struct tlv_buf tb;

  if (o->links_dirty)
    {
      unsigned char buf[HCP_MAXIMUM_PAYLOAD_SIZE];;
      unsigned char *e = buf + sizeof(buf);;
      /* Rather crude: We simply get rid of existing link TLVs, and
       * publish new ones. Assumption: Whatever is added using
       * hcp_add_tlv will have version=-1, and dynamically generated
       * content (like links) won't => we can just add the new entries
       * and ignore manually added and/or outdated things. */
      vlist_update(&o->tlvs);

      vlist_for_each_element(&o->links, l, in_links)
        {
          /* Due to how node link TLV is specified, we can't use
           * tlv.[ch]'s convenience stuff directly. Oh well. */
          struct tlv_attr *a = (struct tlv_attr *)buf;
          unsigned char *c = buf + 4; /* 4 = tlv header. */
          int32_t *iid = (int32_t *)c;
          *iid = cpu_to_be32(l->iid);
          c += 4;
          vlist_for_each_element(&l->neighbors, ne, in_neighbors)
            {
              struct tlv_attr *nt = (struct tlv_attr *)c;
              if ((c + HCP_NEIGHBOR_TLV_SIZE) >= e)
                return;
              tlv_init(nt, HCP_T_NODE_DATA_LINK_NEIGHBOR, HCP_NEIGHBOR_TLV_SIZE);
              c += 4; /* skip header */

              memcpy(c, ne->node_identifier_hash, HCP_HASH_LEN);
              c += HCP_HASH_LEN;

              iid = (int32_t *)c;
              *iid = cpu_to_be32(ne->iid);
              c += 4;
            }
          tlv_init(a, HCP_T_NODE_DATA_LINK, c-buf);
          tlv_fill_pad(a);
          _add_tlv(o, a);
        }

      vlist_flush(&o->tlvs);
    }

  if (!o->tlvs_dirty)
    return;
  /* Dump the contents of hcp->tlvs to single tlv_buf. */
  /* Based on whether or not that would cause change in things, 'do stuff'. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  vlist_for_each_element(&o->tlvs, t, in_tlvs)
    if (!tlv_put_raw(&tb, &t->tlv, tlv_pad_len(&t->tlv)))
      {
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
  if (n->tlv_container)
    {
      /* Consider state being same.. */
      if (tlv_attr_equal(n->tlv_container, tb.head))
        {
          tlv_buf_free(&tb);
          return;
        }
      free(n->tlv_container);
    }
  n->tlv_container = tb.head;
  n->update_number++;
  n->origination_time = hnetd_time();
  o->network_hash_dirty = true;
  hcp_calculate_node_data_hash(n, n->node_data_hash);
  hcp_io_schedule(o, 0);
}

void hcp_node_get_tlvs(hcp_node n, struct tlv_attr **r)
{
  if (hcp_node_is_self(n))
    _flush(n);
  *r = n->tlv_container;
}

void hcp_calculate_network_hash(hcp o, unsigned char *dest)
{
  hcp_node n;
  md5_ctx_t ctx;

  md5_begin(&ctx);
  vlist_for_each_element(&o->nodes, n, in_nodes)
    md5_hash(n->node_data_hash, HCP_HASH_LEN, &ctx);
  md5_end(dest, &ctx);
}

void hcp_calculate_node_data_hash(hcp_node n, unsigned char *dest)
{
  md5_ctx_t ctx;
  struct tlv_attr h;
  int l = tlv_len(n->tlv_container);

  tlv_init(&h, HCP_T_NODE_DATA, HCP_HASH_LEN + 4 + l);
  md5_begin(&ctx);
  md5_hash(&h, sizeof(h), &ctx);
  md5_hash(n->node_identifier_hash, HCP_HASH_LEN, &ctx);
  md5_hash(&n->update_number, 4, &ctx);
  if (n->tlv_container)
    md5_hash(tlv_data(n->tlv_container), l, &ctx);
  md5_end(dest, &ctx);
}

#define TRICKLE_IMIN 250

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define TRICKLE_IMAX ((TRICKLE_IMIN*4)*64)

/* Redundancy constant. */
#define TRICKLE_K 1

static void trickle_set_i(hcp_link l, hnetd_time_t now, int i)
{
  l->i = i;
  l->send_time = now + l->i * (1000 + random() % 1000) / 2000;
  l->interval_end_time = now + l->i;
}

static void trickle_upgrade(hcp_link l, hnetd_time_t now)
{
  int i = l->i * 2;
  i = i < TRICKLE_IMIN ? TRICKLE_IMIN : i > TRICKLE_IMAX ? TRICKLE_IMAX : i;
  trickle_set_i(l, now, i);
}

#define HCP_T_NODE_STATE_V_SIZE (2 * HCP_HASH_LEN + 2 * 4)

static void trickle_send(hcp_link l)
{
  hcp_node n;
  hcp o = l->hcp;
  struct tlv_buf tb;
  struct tlv_attr *a;
  unsigned char *c;

  if (l->c < TRICKLE_K)
    {
      hnetd_time_t now = hnetd_time();

      tlv_buf_init(&tb, 0); /* not passed anywhere */
      vlist_for_each_element(&o->nodes, n, in_nodes)
        {
          a = tlv_new(&tb, HCP_T_NODE_STATE, HCP_T_NODE_STATE_V_SIZE);
          if (!a)
            {
              tlv_buf_free(&tb);
              return;
            }
          c = tlv_data(a);

          memcpy(c, n->node_identifier_hash, HCP_HASH_LEN);
          c += HCP_HASH_LEN;

          *((uint32_t *)c) = cpu_to_be32(n->update_number);
          c += 4;

          *((uint32_t *)c) = cpu_to_be32(now - n->origination_time);
          c += 4;

          memcpy(c, n->node_data_hash, HCP_HASH_LEN);
        }
      tlv_fill_pad(tb.head);
      /* -4 = not including the dummy TLV header */
      /* rest = network state TLV size */
      if ((tlv_pad_len(tb.head) - 4 + 4 + HCP_HASH_LEN)
          > HCP_MAXIMUM_MULTICAST_SIZE)
        {
          /* Clear the buffer - just send the network state hash. */
          tlv_buf_free(&tb);
          tlv_buf_init(&tb, 0); /* not passed anywhere */
        }
      a = tlv_new(&tb, HCP_T_NETWORK_HASH, HCP_HASH_LEN);
      if (!a)
        {
          tlv_buf_free(&tb);
          return;
        }
      c = tlv_data(a);
      memcpy(c, o->network_hash, HCP_HASH_LEN);
      if (hcp_io_sendto(o,
                        tlv_data(tb.head),
                        tlv_len(tb.head),
                        l->ifname,
                        &o->multicast_address) < 0)
        {
          tlv_buf_free(&tb);
          return;
        }
      tlv_buf_free(&tb);
    }
  l->send_time = 0;
}

#define TMIN(x,y) ((x) == 0 ? (y) : (y) == 0 ? (x) : (x) < (y) ? (x) : (y))

void hcp_run(hcp o)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = hnetd_time();
  hcp_link l;
  int time_since_failed_join = (now - o->join_failed_time);

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      unsigned char buf[HCP_HASH_LEN];

      memcpy(buf, o->network_hash, HCP_HASH_LEN);
      hcp_calculate_network_hash(o, o->network_hash);
      if (memcmp(buf, o->network_hash, HCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle. */
          vlist_for_each_element(&o->links, l, in_links)
            trickle_set_i(l, now, TRICKLE_IMIN);
        }
      o->network_hash_dirty = false;
    }

  vlist_for_each_element(&o->links, l, in_links)
    {
      /* If we're in join pending state, we retry every
       * HCP_REJOIN_INTERVAL if necessary. */
      if (l->join_pending
          && (time_since_failed_join < HCP_REJOIN_INTERVAL
              || !_join(o, l, now)))
        {
          next = TMIN(next, HCP_REJOIN_INTERVAL - (now - o->join_failed_time));
          continue;
        }
      if (l->interval_end_time <= now)
        {
          trickle_upgrade(l, now);
          next = TMIN(next, l->send_time);
          continue;
        }

      if (l->send_time)
        {
          if (l->send_time > now)
            {
              next = TMIN(next, l->send_time);
              continue;
            }

          trickle_send(l);
        }
      next = TMIN(next, l->interval_end_time);
    }
  if (next)
    hcp_io_schedule(o, next-now);
}

void hcp_poll(hcp o)
{
  unsigned char buf[HCP_MAXIMUM_PAYLOAD_SIZE];
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct in6_addr src;

  while ((read = hcp_io_recvfrom(o, buf, sizeof(buf), srcif, &src)) > 0)
    {
      
    }
}
