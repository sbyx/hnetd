/*
 * $Id: hncp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Thu Dec  4 19:26:19 2014 mstenber
 * Edit time:     605 min
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
  s->node_identifier = n->node_identifier;
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
  h->node_identifier = n->node_identifier;
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
  lid->node_identifier = l->hncp->own_node->node_identifier;
  lid->link_id = cpu_to_be32(l->iid);
  return true;
}

/****************************************** Actual payload sending utilities */

void hncp_link_send_network_state(hncp_link l,
                                  struct sockaddr_in6 *dst,
                                  size_t maximum_size)
{
  struct tlv_buf tb;
  hncp o = l->hncp;
  int nn = 0;
  hncp_node n;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (!_push_link_id_tlv(&tb, l))
    goto done;
  hncp_calculate_network_hash(o);
  if (!_push_network_state_tlv(&tb, o))
    goto done;
  hncp_for_each_node(o, n)
    if (!o->graph_dirty || n == o->own_node)
      nn++;
  if (!maximum_size
      || maximum_size >= (tlv_len(tb.head) + nn * sizeof(hncp_t_node_state_s)))
    {
      hncp_for_each_node(o, n)
        {
          if (!o->graph_dirty || n == o->own_node)
            if (!_push_node_state_tlv(&tb, n))
              goto done;
        }
    }
  if (maximum_size && tlv_len(tb.head) > maximum_size)
    goto done;
  L_DEBUG("hncp_link_send_network_state -> " SA6_F "%%" HNCP_LINK_F,
          SA6_D(dst), HNCP_LINK_D(l));
  hncp_io_sendto(o, tlv_data(tb.head), tlv_len(tb.head), dst);
 done:
  tlv_buf_free(&tb);
}

void hncp_link_send_node_data(hncp_link l,
                              struct sockaddr_in6 *dst,
                              hncp_node n)
{
  /* Send two things:
     - node state tlv
     - node data tlv
  */
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_node_state_tlv(&tb, n)
      && _push_node_data_tlv(&tb, n))
    {
      L_DEBUG("hncp_link_send_node_state %s -> " SA6_F " %%" HNCP_LINK_F,
              HNCP_NODE_REPR(n), SA6_D(dst), HNCP_LINK_D(l));
      hncp_io_sendto(l->hncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

void hncp_link_send_req_network_state(hncp_link l,
                                      struct sockaddr_in6 *dst)
{
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && tlv_new(&tb, HNCP_T_REQ_NET_HASH, 0))
    {
      L_DEBUG("hncp_link_send_req_network_state -> " SA6_F "%%" HNCP_LINK_F,
              SA6_D(dst), HNCP_LINK_D(l));
      hncp_io_sendto(l->hncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

void hncp_link_send_req_node_data(hncp_link l,
                                  struct sockaddr_in6 *dst,
                                  hncp_t_node_state ns)
{
  struct tlv_buf tb;
  struct tlv_attr *a;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && (a = tlv_new(&tb, HNCP_T_REQ_NODE_DATA, HNCP_HASH_LEN)))
    {
      L_DEBUG("hncp_link_send_req_node_state -> " SA6_F "%%" HNCP_LINK_F,
              SA6_D(dst), HNCP_LINK_D(l));
      memcpy(tlv_data(a), &ns->node_identifier, DNCP_NI_LEN);
      hncp_io_sendto(l->hncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

/************************************************************ Input handling */

static hncp_neighbor
_heard(hncp_link l, hncp_t_link_id lid, struct sockaddr_in6 *src,
       bool allow_add, bool multicast)
{
  hncp_neighbor_s nc;
  hncp_neighbor n;

  memset(&nc, 0, sizeof(nc));
  nc.node_identifier = lid->node_identifier;
  nc.iid = be32_to_cpu(lid->link_id);
  n = vlist_find(&l->neighbors, &nc, &nc, in_neighbors);
  if (!n)
    {
      if (!allow_add)
        return NULL;
      /* new neighbor */
      n = malloc(sizeof(nc));
      if (!n)
        return NULL;
      *n = nc;
      n->last_sync = hncp_time(l->hncp);
      n->keepalive_interval = l->conf->keepalive_interval;
      vlist_add(&l->neighbors, &n->in_neighbors, n);
      L_DEBUG(HNCP_NEIGH_F " added on " HNCP_LINK_F,
              HNCP_NEIGH_D(n), HNCP_LINK_D(l));
    }

  if (!multicast)
    n->last_sa6 = *src;
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
      L_ERR("%d node id conflicts encountered in %.3fs - changing own id",
            HNCP_UPDATE_COLLISIONS_IN_N,
            1.0 * delta / HNETD_TIME_PER_SECOND);
      hncp_node_identifier_s ni;
      int i;

      for (i = 0; i < DNCP_NI_LEN; i++)
        ni.buf[i] = random() % 256;
      hncp_set_own_node_identifier(o, &ni);
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

#define GET_NE(allow_add, multicast)                                    \
do {                                                                    \
  if (memcmp(&lid->node_identifier, &o->own_node->node_identifier,      \
             DNCP_NI_LEN) != 0)                                         \
    {                                                                   \
      ne = _heard(l, lid, src, allow_add, multicast);                   \
      if (!ne && allow_add)                                             \
        return;                                                         \
    }                                                                   \
  if (ne && !multicast)                                                 \
    {                                                                   \
    tlv_for_each_in_buf(a, data, len)                                   \
      if (tlv_id(a) == DNCP_T_KEEPALIVE_INTERVAL                        \
          && tlv_len(a) == 4)                                           \
        {                                                               \
          uint32_t interval = be32_to_cpu(*((uint32_t *)tlv_data(a)));  \
          ne->keepalive_interval = interval;                            \
        }                                                               \
    }                                                                   \
 } while(0)


/* Handle a single received message. */
static void
handle_message(hncp_link l,
               struct sockaddr_in6 *src,
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
            L_INFO("got invalid sized link id - ignoring");
            return;
          }
        lid = tlv_data(a);
      }

  if (!lid)
    {
      L_INFO("did not get link ids - ignoring");
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
          if (nethash)
            {
              L_DEBUG("ignoring message with multiple network hashes");
              return;
            }
          nethash = tlv_data(a);
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
          GET_NE(true, multicast);
          hncp_link_send_network_state(l, src, 0);
          return;
        case HNCP_T_REQ_NODE_DATA:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in unicast");
              return;
            }
          void *p = tlv_data(a);
          int len = tlv_len(a);
          if (!len || tlv_len(a) % HNCP_HASH_LEN)
            return;
          GET_NE(true, multicast);
          for (; len > 0 ; len = len - HNCP_HASH_LEN, p = p + HNCP_HASH_LEN)
            {
              n = hncp_find_node_by_node_identifier(o, p, false);
              if (!n)
                continue;
              if (n != o->own_node)
                {
                  if (o->graph_dirty)
                    {
                      L_DEBUG("prune pending, ignoring node data request");
                      continue;
                    }

                  if (n->last_reachable_prune != o->last_prune)
                    {
                      L_DEBUG("not reachable request, ignoring");
                      continue;
                    }
                }
              hncp_link_send_node_data(l, src, n);
            }
          return;
        }
    }

  GET_NE(false, multicast);

  /* Requests were handled above. So what's left is response
   * processing here. If it was unicast, it was probably solicited
   * response, so we can mark the node as having been in touch with us
   * recently. */
  if (!multicast)
    {
      L_DEBUG("unicast received from %s on " HNCP_LINK_F,
              HNCP_NODE_REPR(lid), HNCP_LINK_D(l));
    }

  /* Three different cases to be handled for solicited/unsolicited responses:
     - raw network hash
     - network hash + node states
     - node state + node data
  */
  if (nethash)
    {
      /* We don't care, if network hash state IS same. */
      if (memcmp(nethash, &o->network_hash, HNCP_HASH_LEN) == 0)
        {
          L_DEBUG("received network state which is consistent");

          /* Increment Trickle count + last in sync time.*/
          if (ne)
            {
              l->trickle_c++;
              ne->last_sync = hncp_time(l->hncp);
            }
          return;
        }

      if (multicast)
        {
          /* No need to reset Trickle anymore, but log the fact */
          L_DEBUG("received inconsistent multicast network state %s != %s",
                  HEX_REPR(nethash, HNCP_HASH_LEN),
                  HEX_REPR(&o->network_hash, HNCP_HASH_LEN));
        }

      /* Short form (raw network hash) */
      if (!nodestates)
        {
          if (multicast)
            hncp_link_send_req_network_state(l, src);
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
            n = hncp_find_node_by_node_identifier(o, &ns->node_identifier,
                                                  false);
            new_update_number = be32_to_cpu(ns->update_number);
            bool interesting = !n
              || (new_update_number > n->update_number
                  || (new_update_number == n->update_number
                      && memcmp(&n->node_data_hash,
                                &ns->node_data_hash,
                                sizeof(n->node_data_hash)) != 0));
            if (interesting)
              {
                L_DEBUG("saw something new for %s/%p (update number %d)",
                        HNCP_NODE_REPR(ns), n, new_update_number);
                hncp_link_send_req_node_data(l, src, ns);
              }
            else
              {
                L_DEBUG("saw something old for %s/%p (update number %d)",
                        HNCP_NODE_REPR(ns), n, new_update_number);
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
  if (memcmp(&ns->node_identifier, &nd->node_identifier, DNCP_NI_LEN))
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
  n = hncp_find_node_by_node_identifier(o, &ns->node_identifier, true);
  if (!n)
    return;
  new_update_number = be32_to_cpu(ns->update_number);
  if (new_update_number < n->update_number
      || (n->update_number == new_update_number
          && !memcmp(&n->node_data_hash,
                     &ns->node_data_hash,
                     sizeof(n->node_data_hash))))
    {
      L_DEBUG("received update number %d, but already have %d",
              new_update_number, n->update_number);
      return;
    }
  assert(new_update_number >= n->update_number);
  if (hncp_node_is_self(n))
    {
      L_DEBUG("received %d update number from network, own %d",
              new_update_number, n->update_number);
      if (_handle_collision(o))
        return;
      n->update_number = new_update_number;
      o->republish_tlvs = true;
      hncp_schedule(o);
      return;
    }
  /* Ok. nd contains more recent TLV data than what we have
   * already. Woot. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (tlv_put_raw(&tb, nd_data, nd_len))
    {
      hncp_node_set(n, new_update_number,
                    hncp_time(o) - be32_to_cpu(ns->ms_since_origination),
                    tb.head);
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
  struct sockaddr_in6 src;
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
      /* If it's not aimed _a_ linklocal address, we don't care. */
      if (!IN6_IS_ADDR_LINKLOCAL(&dst))
        continue;
      handle_message(l, &src, buf, read, false);
    }
}

/* Utilities for formatting TLVs. */
void hncp_tlv_ra_update(hncp o,
                        uint32_t lid,
                        const struct in6_addr *address,
                        bool add)
{
  hncp_t_router_address_s ra;

  ra.link_id = cpu_to_be32(lid);
  ra.address = *address;
  hncp_update_tlv_raw(o, HNCP_T_ROUTER_ADDRESS, &ra, sizeof(ra), add);
}


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
    | (authoritative ? HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE : 0);
  ah->prefix_length_bits = p.plen;
  ah++;
  memcpy(ah, &p, plen);

  hncp_update_tlv(o, (struct tlv_attr *)buf, add);
}
