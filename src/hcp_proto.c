/*
 * $Id: hcp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Tue Dec  3 14:17:54 2013 mstenber
 * Edit time:     191 min
 *
 */

#include "hcp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in hcp_io.
 */

/***************************************************** Low-level TLV pushing */

#define MS_PER_SECOND 1000

static bool _push_node_state_tlv(struct tlv_buf *tb, hcp_node n)
{
  hnetd_time_t now = hcp_time(n->hcp);
  hcp_t_node_state s;
  struct tlv_attr *a = tlv_new(tb, HCP_T_NODE_STATE, sizeof(*s));

  if (!a)
    return false;
  s = tlv_data(a);
  s->node_identifier_hash = n->node_identifier_hash;
  s->update_number = cpu_to_be32(n->update_number);
  s->ms_since_origination =
    cpu_to_be32((now - n->origination_time) * MS_PER_SECOND / HNETD_TIME_PER_SECOND);
  return true;
}

static bool _push_node_data_tlv(struct tlv_buf *tb, hcp_node n)
{
  int s = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  hcp_t_node_data_header h;
  struct tlv_attr *a = tlv_new(tb, HCP_T_NODE_DATA, sizeof(*h) + s);

  if (!a)
    return false;
  h = tlv_data(a);
  h->node_identifier_hash = n->node_identifier_hash;
  h->update_number = cpu_to_be32(n->update_number);
  memcpy((void *)h + sizeof(*h), tlv_data(n->tlv_container), s);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, hcp o)
{
  struct tlv_attr *a = tlv_new(tb, HCP_T_NETWORK_HASH, HCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  memcpy(c, &o->network_hash, HCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, hcp_link l)
{
  struct tlv_attr *a = tlv_new(tb, HCP_T_LINK_ID, sizeof(hcp_t_link_id_s));
  hcp_t_link_id lid;

  if (!a)
    return false;
  lid = tlv_data(a);
  lid->node_identifier_hash = l->hcp->own_node->node_identifier_hash;
  lid->link_id = cpu_to_be32(l->iid);
  return true;
}

/****************************************** Actual payload sending utilities */

bool hcp_link_send_network_state(hcp_link l,
                                 struct in6_addr *dst,
                                 size_t maximum_size)
{
  struct tlv_buf tb;
  hcp_node n;
  hcp o = l->hcp;
  bool r = false;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */

  if (!_push_link_id_tlv(&tb, l))
    goto err;
  vlist_for_each_element(&o->nodes, n, in_nodes)
    if (!_push_node_state_tlv(&tb, n))
      goto err;
  tlv_fill_pad(tb.head);
  /* -4 = not including the dummy TLV header */
  /* rest = network state TLV size */
  if (maximum_size
      && (tlv_len(tb.head) + 2 * TLV_SIZE +
          sizeof(hcp_t_link_id) +
          HCP_HASH_LEN) > maximum_size)
    {
      /* Clear the buffer - just send the network state hash. */
      tlv_buf_free(&tb);
      tlv_buf_init(&tb, 0); /* not passed anywhere */
      if (!_push_link_id_tlv(&tb, l))
        goto err;
    }
  if (_push_network_state_tlv(&tb, o))
    {
      int rc = hcp_io_sendto(o,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      L_DEBUG("hcp_link_send_network_state %p", l);
      r = rc > 0;
    }
 err:
  tlv_buf_free(&tb);
  return r;
}

bool hcp_link_send_node_data(hcp_link l,
                             struct in6_addr *dst,
                             hcp_node n)
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
      int rc = hcp_io_sendto(l->hcp,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      r = rc > 0;
      L_DEBUG("hcp_link_send_node_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

bool hcp_link_send_req_network_state(hcp_link l,
                                     struct in6_addr *dst)
{
  struct tlv_buf tb;
  bool r = false;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && tlv_new(&tb, HCP_T_REQ_NET_HASH, 0))
    {
      int rc = hcp_io_sendto(l->hcp,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      r = rc > 0;
      L_DEBUG("hcp_link_send_req_network_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

bool hcp_link_send_req_node_data(hcp_link l,
                                 struct in6_addr *dst,
                                 hcp_t_node_state ns)
{
  struct tlv_buf tb;
  bool r = false;
  struct tlv_attr *a;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && (a = tlv_new(&tb, HCP_T_REQ_NODE_DATA, HCP_HASH_LEN)))
    {
      memcpy(tlv_data(a), &ns->node_identifier_hash, HCP_HASH_LEN);
      int rc = hcp_io_sendto(l->hcp,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      r = rc > 0;
      L_DEBUG("hcp_link_send_req_node_state %p", l);
    }
  tlv_buf_free(&tb);
  return r;
}

/************************************************************ Input handling */

static hcp_neighbor
_heard(hcp_link l, hcp_t_link_id lid, struct in6_addr *src)
{
  hcp_neighbor_s nc;
  hcp_neighbor n;
  hcp o = l->hcp;

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
              hcp_hash64(&lid->node_identifier_hash), l);
    }

  n->last_address = *src;
  if (o->assume_bidirectional_reachability)
    n->ping_count = 0;
  n->last_heard = hcp_time(o);
  return n;
}

/* Handle a single received message. */
static void
handle_message(hcp_link l,
               struct in6_addr *src,
               unsigned char *data, ssize_t len,
               bool multicast)
{
  hcp o = l->hcp;
  struct tlv_attr *a;
  hcp_node n;
  hcp_t_link_id lid = NULL;
  unsigned char *nethash = NULL;
  int nodestates = 0;
  hcp_neighbor ne = NULL;
  hcp_t_node_state ns;
  hcp_t_node_data_header nd;
  unsigned char *nd_data = NULL;
  int nd_len = 0;
  struct tlv_buf tb;
  uint32_t new_update_number;

  /* Validate that link id exists. */
  tlv_for_each_in_buf(a, data, len)
    if (tlv_id(a) == HCP_T_LINK_ID)
      {
        /* Error to have multiple top level link id's. */
        if (lid)
          {
            L_INFO("got multiple link ids - ignoring");
            return;
          }
        if (tlv_len(a) == sizeof(hcp_t_link_id_s))
          {
            lid = tlv_data(a);
            if (memcmp(&lid->node_identifier_hash,
                       &l->hcp->own_node->node_identifier_hash,
                       HCP_HASH_LEN) == 0)
              {
                L_DEBUG("received looped message from self - ignoring");
                return;
              }
          }
        else
          {
            L_INFO("got invalid sized link ids - ignoring");
            return; /* weird link id */
          }
      }

  if (!lid)
    {
      L_INFO("did not get link ids - ignoring");
      return;
    }

  ne = _heard(l, lid, src);

  if (!ne)
    return;

  /* Estimates what's in the payload + handles the few
   * request messages we support. */
  tlv_for_each_in_buf(a, data, len)
    {
      switch (tlv_id(a))
        {
        case HCP_T_NETWORK_HASH:
          nethash = tlv_data(a);
          break;
        case HCP_T_NODE_STATE:
          nodestates++;
          break;
        case HCP_T_REQ_NET_HASH:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in multicast");
              return;
            }
          (void)hcp_link_send_network_state(l, src, 0);
          return;
        case HCP_T_REQ_NODE_DATA:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in unicast");
              return;
            }
          if (tlv_len(a) == HCP_HASH_LEN)
            {
              n = hcp_find_node_by_hash(o, tlv_data(a), false);
              if (n)
                (void)hcp_link_send_node_data(l, src, n);
            }
          return;
        }
    }
  /* Three different cases:
     - raw network hash
     - network hash + node states
     - node state + node data
  */
  if (!multicast)
    {
      ne->last_response = hcp_time(l->hcp);
      ne->ping_count = 0;
    }
  /* We don't care, if network hash state IS same. */
  if (nethash)
    {
      if (memcmp(nethash, &o->network_hash, HCP_HASH_LEN) == 0)
        {
          L_DEBUG("received network state which is consistent");
          return;
        }
      /* Short form (raw network hash) */
      if (!nodestates)
        {
          if (multicast)
            (void)hcp_link_send_req_network_state(l, src);
          else
            {
              L_INFO("unicast short form network status received - ignoring");
            }
          return;
        }
      /* Long form (has node states). */
      /* The exercise becomes just to ask for any node state that
       * differs from local and is more recent. */
      tlv_for_each_in_buf(a, data, len)
        if (tlv_id(a) == HCP_T_NODE_STATE)
          {
            if (tlv_len(a) != sizeof(hcp_t_node_state_s))
              {
                L_INFO("invalid length node state TLV received - ignoring");
                return;
              }
            ns = tlv_data(a);
            n = hcp_find_node_by_hash(o, &ns->node_identifier_hash, false);
            new_update_number = be32_to_cpu(ns->update_number);
            if (!n || n->update_number < new_update_number)
              {
                L_DEBUG("saw something new for %llx/%p (update number %d)",
                        hcp_hash64(&ns->node_identifier_hash),
                        n, new_update_number);
                hcp_link_send_req_node_data(l, src, ns);
              }
            else
              {
                L_DEBUG("saw something old for %llx/%p (update number %d)",
                        hcp_hash64(&ns->node_identifier_hash),
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
      case HCP_T_NODE_STATE:
        if (ns)
          {
            L_INFO("received multiple node state TLVs, ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(hcp_t_node_state_s))
          {
            L_INFO("received invalid node state TLVs, ignoring");
            return;
          }
        ns = tlv_data(a);
        break;
      case HCP_T_NODE_DATA:
        if (nd)
          {
            L_INFO("received multiple node data TLVs, ignoring");
            return;
          }
        nd_len = tlv_len(a) - sizeof(hcp_t_node_data_header_s);
        if (nd_len < 0)
          {
            L_INFO("received invalid node data TLV, ignoring");
            return;
          }
        nd = tlv_data(a);
        nd_data = (unsigned char *)nd + sizeof(hcp_t_node_data_header_s);
        break;
      }
  if (!ns || !nd)
    {
      L_INFO("node data or node state TLV missing, ignoring");
      return;
    }
  /* If they're for different nodes, not interested. */
  if (memcmp(&ns->node_identifier_hash, &nd->node_identifier_hash, HCP_HASH_LEN))
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
  n = hcp_find_node_by_hash(o, &ns->node_identifier_hash, true);
  if (!n)
    return;
  new_update_number = be32_to_cpu(ns->update_number);
  if (n->update_number >= new_update_number)
    {
      L_DEBUG("received update number %d, but already have %d",
              new_update_number, n->update_number);
      return;
    }
  if (hcp_node_is_self(n))
    {
      L_DEBUG("received %d update number from network, own %d",
              new_update_number, n->update_number);
      /* Don't accept updates to 'self' from network. Instead,
       * increment own update number. */
      n->update_number = new_update_number + 1;
      n->node_data_hash_dirty = true;
      o->network_hash_dirty = true;
      n->origination_time = hcp_time(o);
      hcp_schedule(o);
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
      hcp_node_set_tlvs(n, tb.head);
      n->origination_time = hcp_time(o) - be32_to_cpu(ns->ms_since_origination) * HNETD_TIME_PER_SECOND / MS_PER_SECOND;
      hcp_schedule(o);
    }
  else
    {
      L_DEBUG("tlv_put_raw failed");
      tlv_buf_free(&tb);
    }
}


void hcp_poll(hcp o)
{
  unsigned char buf[HCP_MAXIMUM_PAYLOAD_SIZE];
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct in6_addr src;
  struct in6_addr dst;
  hcp_link l;

  while ((read = hcp_io_recvfrom(o, buf, sizeof(buf), srcif, &src, &dst)) > 0)
    {
      /* First off. If it's off some link we aren't supposed to use, ignore. */
      l = hcp_find_link(o, srcif, false);
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
