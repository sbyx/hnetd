/*
 * $Id: hncp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Mon Apr 14 19:03:59 2014 mstenber
 * Edit time:     330 min
 *
 */

#include "hncp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in hncp_io.
 */

/***************************************************** Low-level TLV pushing */

static bool _push_node_state_tlv(struct tlv_buf *tb, hncp_node n)
{
  hnetd_time_t now = hncp_time(n->hncp);
  hncp_t_node_state s;
  struct tlv_attr *a = tlv_new(tb, HNCP_T_NODE_STATE, sizeof(*s));

  if (!a)
    return false;
  s = tlv_data(a);
  s->node_identifier_hash = n->node_identifier_hash;
  s->update_number = cpu_to_be32(n->update_number);
  s->ms_since_origination = cpu_to_be32(now - n->origination_time);
  s->node_data_hash = n->node_data_hash;
  return true;
}

static bool _push_node_data_tlv(struct tlv_buf *tb, hncp_node n)
{
  int s = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  hncp_t_node_data_header h;
  struct tlv_attr *a = tlv_new(tb, HNCP_T_NODE_DATA, sizeof(*h) + s);

  if (!a)
    return false;
  h = tlv_data(a);
  h->node_identifier_hash = n->node_identifier_hash;
  h->update_number = cpu_to_be32(n->update_number);
  memcpy((void *)h + sizeof(*h), tlv_data(n->tlv_container), s);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, hncp o)
{
  struct tlv_attr *a = tlv_new(tb, HNCP_T_NETWORK_HASH, HNCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  memcpy(c, &o->network_hash, HNCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, hncp_link l)
{
  struct tlv_attr *a = tlv_new(tb, HNCP_T_LINK_ID, sizeof(hncp_t_link_id_s));
  hncp_t_link_id lid;

  if (!a)
    return false;
  lid = tlv_data(a);
  lid->node_identifier_hash = l->hncp->own_node->node_identifier_hash;
  lid->link_id = cpu_to_be32(l->iid);
  return true;
}

/****************************************** Actual payload sending utilities */

bool hncp_link_send_network_state(hncp_link l,
                                  struct in6_addr *dst,
                                  size_t maximum_size)
{
  struct tlv_buf tb;
  hncp o = l->hncp;
  bool r = false;
  int nn = 0;
  hncp_node n;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (!_push_link_id_tlv(&tb, l))
    goto err;
  hncp_calculate_network_hash(o);
  if (!_push_network_state_tlv(&tb, o))
    goto err;
  vlist_for_each_element(&o->nodes, n, in_nodes)
    nn++;
  if (!maximum_size
      || maximum_size >= (tlv_len(tb.head) + nn * sizeof(hncp_t_node_state_s)))
    {
      vlist_for_each_element(&o->nodes, n, in_nodes)
        {
          if (!_push_node_state_tlv(&tb, n))
            goto err;
        }
    }
  if (maximum_size && tlv_len(tb.head) > maximum_size)
    goto err;
  int rc = hncp_io_sendto(o, tlv_data(tb.head), tlv_len(tb.head),
                          l->ifname, dst);
  L_DEBUG("hncp_link_send_network_state %p", l);
  r = rc > 0;
 err:
  tlv_buf_free(&tb);
  return r;
}

bool hncp_link_send_node_data(hncp_link l,
                              struct in6_addr *dst,
                              hncp_node n)
{
  /* Send two things:
     - node state tlv
     - node data tlv
  */
  struct tlv_buf tb;
  bool r = false;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_node_state_tlv(&tb, n)
      && _push_node_data_tlv(&tb, n))
    {
      int rc = hncp_io_sendto(l->hncp,
                              tlv_data(tb.head),
                              tlv_len(tb.head),
                              l->ifname,
                              dst);
      r = rc > 0;
      L_DEBUG("hncp_link_send_node_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

bool hncp_link_send_req_network_state(hncp_link l,
                                      struct in6_addr *dst)
{
  struct tlv_buf tb;
  bool r = false;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && tlv_new(&tb, HNCP_T_REQ_NET_HASH, 0))
    {
      int rc = hncp_io_sendto(l->hncp,
                              tlv_data(tb.head),
                              tlv_len(tb.head),
                              l->ifname,
                              dst);
      r = rc > 0;
      L_DEBUG("hncp_link_send_req_network_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

bool hncp_link_send_req_node_data(hncp_link l,
                                  struct in6_addr *dst,
                                  hncp_t_node_state ns)
{
  struct tlv_buf tb;
  bool r = false;
  struct tlv_attr *a;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && (a = tlv_new(&tb, HNCP_T_REQ_NODE_DATA, HNCP_HASH_LEN)))
    {
      memcpy(tlv_data(a), &ns->node_identifier_hash, HNCP_HASH_LEN);
      int rc = hncp_io_sendto(l->hncp,
                              tlv_data(tb.head),
                              tlv_len(tb.head),
                              l->ifname,
                              dst);
      r = rc > 0;
      L_DEBUG("hncp_link_send_req_node_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

/************************************************************ Input handling */

static hncp_neighbor
_heard(hncp_link l, hncp_t_link_id lid, struct in6_addr *src)
{
  hncp_neighbor_s nc;
  hncp_neighbor n;
  hncp o = l->hncp;

  memset(&nc, 0, sizeof(nc));
  nc.node_identifier_hash = lid->node_identifier_hash;
  nc.iid = be32_to_cpu(lid->link_id);
  n = vlist_find(&l->neighbors, &nc, &nc, in_neighbors);
  if (!n)
    {
      /* new neighbor */
      n = malloc(sizeof(nc));
      if (!n)
        return NULL;
      memcpy(n, &nc, sizeof(nc));
      vlist_add(&l->neighbors, &n->in_neighbors, n);
      L_DEBUG("_heard %llx on link %p",
              hncp_hash64(&lid->node_identifier_hash), l);
    }

  n->last_address = *src;
  if (o->assume_bidirectional_reachability)
    n->ping_count = 0;
  n->last_heard = hncp_time(o);
  return n;
}

static bool
_handle_collision(hncp o)
{
  /* XXX - consider also case where security is enabled; for now,
   * we just handle collisions insecurely. */
  int delta = hncp_io_time(o) - o->collisions[o->last_collision];
  if (delta < HNCP_UPDATE_COLLISION_N)
    {
      L_ERR("%d hash conflicts encountered in %.3fs - changing own id",
            HNCP_UPDATE_COLLISIONS_IN_N,
            1.0 * delta / HNETD_TIME_PER_SECOND);
      hncp_hash_s h;
      int i;

      for (i = 0 ; i < HNCP_HASH_LEN ; i++)
        h.buf[i] = rand() % 256;
      hncp_set_own_hash(o, &h);
      return true;
    }
  else
    {
      int c = o->last_collision;
      o->collisions[c] = hncp_io_time(o);
      c = (c + 1) % HNCP_UPDATE_COLLISIONS_IN_N;
      o->last_collision = c;
    }
  return false;
}

/* Handle a single received message. */
static void
handle_message(hncp_link l,
               struct in6_addr *src,
               unsigned char *data, ssize_t len,
               bool multicast)
{
  hncp o = l->hncp;
  struct tlv_attr *a;
  hncp_node n;
  hncp_t_link_id lid = NULL;
  unsigned char *nethash = NULL;
  int nodestates = 0;
  hncp_neighbor ne = NULL;
  hncp_t_node_state ns;
  hncp_t_node_data_header nd;
  unsigned char *nd_data = NULL;
  int nd_len = 0;
  struct tlv_buf tb;
  uint32_t new_update_number;

  /* Validate that link id exists. */
  tlv_for_each_in_buf(a, data, len)
    if (tlv_id(a) == HNCP_T_LINK_ID)
      {
        /* Error to have multiple top level link id's. */
        if (lid)
          {
            L_INFO("got multiple link ids - ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(*lid))
          {
            L_INFO("got invalid sized link ids - ignoring");
            return; /* weird link id */
          }
        lid = tlv_data(a);
      }

  if (!lid)
    {
      L_INFO("did not get link ids - ignoring");
      return;
    }

  if (memcmp(&lid->node_identifier_hash,
             &l->hncp->own_node->node_identifier_hash,
             HNCP_HASH_LEN) != 0)
    {
      ne = _heard(l, lid, src);
      if (!ne)
        return;
    }

  /* Estimates what's in the payload + handles the few
   * request messages we support. */
  tlv_for_each_in_buf(a, data, len)
    {
      switch (tlv_id(a))
        {
        case HNCP_T_NETWORK_HASH:
          if (tlv_len(a) != HNCP_HASH_LEN)
            {
              L_DEBUG("got invalid network hash length: %d", tlv_len(a));
              return;
            }
          nethash = tlv_data(a);
          /* We don't care, if network hash state IS same. */
          if (memcmp(nethash, &o->network_hash, HNCP_HASH_LEN) == 0)
            {
              L_DEBUG("received network state which is consistent");
              return;
            }
          break;
        case HNCP_T_NODE_STATE:
          nodestates++;
          break;
        case HNCP_T_REQ_NET_HASH:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in multicast");
              return;
            }
          (void)hncp_link_send_network_state(l, src, 0);
          return;
        case HNCP_T_REQ_NODE_DATA:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in unicast");
              return;
            }
          if (tlv_len(a) != HNCP_HASH_LEN)
            return;
          n = hncp_find_node_by_hash(o, tlv_data(a), false);
          if (n)
            (void)hncp_link_send_node_data(l, src, n);
          return;
        }
    }
  /* Three different cases:
     - raw network hash
     - network hash + node states
     - node state + node data
  */
  if (!multicast && ne)
    {
      ne->last_response = hncp_time(l->hncp);
      ne->ping_count = 0;
    }
  if (nethash)
    {
      /* Short form (raw network hash) */
      if (!nodestates)
        {
          if (multicast)
            (void)hncp_link_send_req_network_state(l, src);
          else
            L_INFO("unicast short form network status received - ignoring");
          return;
        }
      /* Long form (has node states). */
      /* The exercise becomes just to ask for any node state that
       * differs from local and is more recent. */
      tlv_for_each_in_buf(a, data, len)
        if (tlv_id(a) == HNCP_T_NODE_STATE)
          {
            if (tlv_len(a) != sizeof(hncp_t_node_state_s))
              {
                L_INFO("invalid length node state TLV received - ignoring");
                return;
              }
            ns = tlv_data(a);
            n = hncp_find_node_by_hash(o, &ns->node_identifier_hash, false);
            new_update_number = be32_to_cpu(ns->update_number);
            if (n == o->own_node)
              {
                if (new_update_number > n->update_number
                    || (new_update_number == n->update_number
                        && memcmp(&n->node_data_hash,
                                  &ns->node_data_hash,
                                  sizeof(n->node_data_hash)) != 0))
                  {
                    L_ERR("detected conflicting node state update %d>=%d",
                          new_update_number, n->update_number);
                    _handle_collision(o);
                    return;
                  }
                continue;
              }
            if (!n || n->update_number < new_update_number)
              {
                L_DEBUG("saw something new for %llx/%p (update number %d)",
                        hncp_hash64(&ns->node_identifier_hash),
                        n, new_update_number);
                hncp_link_send_req_node_data(l, src, ns);
              }
            else
              {
                L_DEBUG("saw something old for %llx/%p (update number %d)",
                        hncp_hash64(&ns->node_identifier_hash),
                        n, new_update_number);
              }
          }
      return;
    }
  /* We don't accept node data via multicast. */
  if (multicast)
    {
      L_INFO("received node data via multicast, ignoring");
      return;
    }
  /* Look for node state + node data. */
  ns = NULL;
  nd = NULL;
  tlv_for_each_in_buf(a, data, len)
    switch(tlv_id(a))
      {
      case HNCP_T_NODE_STATE:
        if (ns)
          {
            L_INFO("received multiple node state TLVs, ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(hncp_t_node_state_s))
          {
            L_INFO("received invalid node state TLVs, ignoring");
            return;
          }
        ns = tlv_data(a);
        break;
      case HNCP_T_NODE_DATA:
        if (nd)
          {
            L_INFO("received multiple node data TLVs, ignoring");
            return;
          }
        nd_len = tlv_len(a) - sizeof(hncp_t_node_data_header_s);
        if (nd_len < 0)
          {
            L_INFO("received invalid node data TLV, ignoring");
            return;
          }
        nd = tlv_data(a);
        nd_data = (unsigned char *)nd + sizeof(hncp_t_node_data_header_s);
        break;
      }
  if (!ns || !nd)
    {
      L_INFO("node data or node state TLV missing, ignoring");
      return;
    }
  /* If they're for different nodes, not interested. */
  if (memcmp(&ns->node_identifier_hash, &nd->node_identifier_hash, HNCP_HASH_LEN))
    {
      L_INFO("node data and state identifier mismatch, ignoring");
      return;
    }
  /* Is it actually valid? Should be same update #. */
  if (ns->update_number != nd->update_number)
    {
      L_INFO("node data and state update number mismatch, ignoring");
      return;
    }
  /* Let's see if it's more recent. */
  n = hncp_find_node_by_hash(o, &ns->node_identifier_hash, true);
  if (!n)
    return;
  new_update_number = be32_to_cpu(ns->update_number);
  if (n->update_number >= new_update_number)
    {
      L_DEBUG("received update number %d, but already have %d",
              new_update_number, n->update_number);
      return;
    }
  if (hncp_node_is_self(n))
    {
      L_DEBUG("received %d update number from network, own %d",
              new_update_number, n->update_number);
      if (_handle_collision(o))
        return;
      /* Don't accept updates to 'self' from network. Instead,
       * increment own update number. */
      n->update_number = new_update_number + 1;
      n->node_data_hash_dirty = true;
      o->network_hash_dirty = true;
      n->origination_time = hncp_time(o);
      hncp_schedule(o);
      return;
    }
  /* Ok. nd contains more recent TLV data than what we have
   * already. Woot. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (tlv_put_raw(&tb, nd_data, nd_len))
    {
      L_DEBUG("updated node %p %d -> %d",
              n, n->update_number, new_update_number);
      n->update_number = new_update_number;
      n->node_data_hash_dirty = true;
      o->network_hash_dirty = true;
      n->origination_time = hncp_time(o) - be32_to_cpu(ns->ms_since_origination);
      L_DEBUG("received origination time:%lld (-%d)",
              (long long)n->origination_time,
              (int)be32_to_cpu(ns->ms_since_origination));
      hncp_node_set_tlvs(n, tb.head);
      hncp_schedule(o);
    }
  else
    {
      L_DEBUG("tlv_put_raw failed");
      tlv_buf_free(&tb);
    }
}


void hncp_poll(hncp o)
{
  unsigned char buf[HNCP_MAXIMUM_PAYLOAD_SIZE];
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct in6_addr src;
  struct in6_addr dst;
  hncp_link l;

  while ((read = hncp_io_recvfrom(o, buf, sizeof(buf), srcif, &src, &dst)) > 0)
    {
      /* First off. If it's off some link we aren't supposed to use, ignore. */
      l = hncp_find_link_by_name(o, srcif, false);
      if (!l)
        continue;
      /* If it's multicast, it's valid if and only if it's aimed at
       * the multicast address. */
      if (IN6_IS_ADDR_MULTICAST(&dst))
        {
          if (memcmp(&dst, &o->multicast_address, sizeof(dst)) != 0)
            continue;
          /* XXX - should we care about source address too? */
          handle_message(l, &src, buf, read, true);
          continue;
        }
      /* If it's not aimed at our linklocal address, we don't care. */
      if (!IN6_IS_ADDR_LINKLOCAL(&dst))
        continue;
      handle_message(l, &src, buf, read, false);
    }
}

/* Utilities for formatting TLVs. */
void hncp_tlv_ap_update(hncp o,
                        const struct prefix *prefix,
                        const char *ifname,
                        bool authoritative,
                        unsigned int preference,
                        bool add)
{
  struct prefix p;
  int mlen = TLV_SIZE + sizeof(hncp_t_assigned_prefix_header_s) + 16 + 3;
  unsigned char buf[mlen];
  struct tlv_attr *a = (struct tlv_attr *) buf;
  int plen = ROUND_BITS_TO_BYTES(prefix->plen);
  int flen = TLV_SIZE + sizeof(hncp_t_delegated_prefix_header_s) + plen;
  hncp_t_assigned_prefix_header ah;
  hncp_link l;

  memset(buf, 0, mlen);
  p = *prefix;
  prefix_canonical(&p, &p);
  /* XXX - what if links renumber? let's hope they don't */
  tlv_init(a, HNCP_T_ASSIGNED_PREFIX, flen);
  ah = tlv_data(a);
  l = hncp_find_link_by_name(o, ifname, false);
  if (l)
    ah->link_id = cpu_to_be32(l->iid);
  ah->flags =
    HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(preference)
    | authoritative ? HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE : 0;
  ah->prefix_length_bits = p.plen;
  ah++;
  memcpy(ah, &p, plen);

  hncp_update_tlv(o, (struct tlv_attr *)buf, add);
}
