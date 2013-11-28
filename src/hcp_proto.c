/*
 * $Id: hcp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Thu Nov 28 11:19:24 2013 mstenber
 * Edit time:     141 min
 *
 */

#include "hcp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in hcp_io.
 */

/***************************************************** Low-level TLV pushing */

static bool _push_node_state_tlv(struct tlv_buf *tb, hcp_node n)
{
  hnetd_time_t now = hcp_time(n->hcp);
  struct tlv_attr *a = tlv_new(tb, HCP_T_NODE_STATE,
                               sizeof(hcp_t_node_state_s));
  hcp_t_node_state s;

  if (!a)
    return false;
  s = tlv_data(a);
  memcpy(s->node_identifier_hash, n->node_identifier_hash, HCP_HASH_LEN);
  s->update_number = cpu_to_be32(n->update_number);
  s->seconds_since_origination = cpu_to_be32(now - n->origination_time);
  return true;
}

static bool _push_node_data_tlv(struct tlv_buf *tb, hcp_node n)
{
  int s = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  struct tlv_attr *a = tlv_new(tb, HCP_T_NODE_DATA,
                               sizeof(hcp_t_node_data_header_s) + s);
  hcp_t_node_data_header h;

  if (!a)
    return false;
  h = tlv_data(a);
  memcpy(h->node_identifier_hash, n->node_identifier_hash, HCP_HASH_LEN);
  h->update_number = cpu_to_be32(n->update_number);
  memcpy((unsigned char *)h + sizeof(hcp_t_node_data_header_s),
         n->tlv_container, s);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, hcp o)
{
  struct tlv_attr *a = tlv_new(tb, HCP_T_NETWORK_HASH, HCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  memcpy(c, o->network_hash, HCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, hcp_link l)
{
  struct tlv_attr *a = tlv_new(tb, HCP_T_LINK_ID, sizeof(hcp_t_link_id_s));
  hcp_t_link_id lid;

  if (!a)
    return false;
  lid = tlv_data(a);
  memcpy(lid->node_identifier_hash, l->hcp->own_node->node_identifier_hash,
         HCP_HASH_LEN);
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

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
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
    }
  if (_push_link_id_tlv(&tb, l)
      && _push_network_state_tlv(&tb, o))
    {
      int rc = hcp_io_sendto(o,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      tlv_buf_free(&tb);
      /* printf("hcp_link_send_network_state %p\n", l); */
      return rc > 0;
    }
 err:
  tlv_buf_free(&tb);
  return false;
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
      /* printf("hcp_link_send_node_data %p\n", l); */
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
      /* printf("hcp_link_send_req_network_state %p\n", l); */
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
      memcpy(tlv_data(a), ns->node_identifier_hash, HCP_HASH_LEN);
      int rc = hcp_io_sendto(l->hcp,
                             tlv_data(tb.head),
                             tlv_len(tb.head),
                             l->ifname,
                             dst);
      r = rc > 0;
      /* printf("hcp_link_send_req_node_data %p\n", l); */
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
  memcpy(nc.node_identifier_hash, lid->node_identifier_hash, HCP_HASH_LEN);
  nc.iid = cpu_to_be32(lid->link_id);
  n = vlist_find(&l->neighbors, &nc, &nc, in_neighbors);
  if (!n)
    {
      /* new neighbor */
      n = malloc(sizeof(nc));
      if (!n)
        return NULL;
      memcpy(n, &nc, sizeof(nc));
      vlist_add(&l->neighbors, &n->in_neighbors, n);
      /* printf("_heard - added new neighbor %p\n", n); */
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
          return;
        if (tlv_len(a) == sizeof(hcp_t_link_id_s))
          lid = tlv_data(a);
        else
          return; /* weird link id */
      }

  if (!lid)
    return;

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
            return;
          (void)hcp_link_send_network_state(l, src, 0);
          return;
        case HCP_T_REQ_NODE_DATA:
          /* Ignore if in multicast. */
          if (multicast)
            return;
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
      if (memcmp(nethash, o->network_hash, HCP_HASH_LEN) == 0)
        return;
      /* Short form (raw network hash) */
      if (!nodestates)
        {
          if (multicast)
            (void)hcp_link_send_req_network_state(l, src);
          return;
        }
      /* Long form (has node states). */
      /* The exercise becomes just to ask for any node state that
       * differs from local and is more recent. */
      tlv_for_each_in_buf(a, data, len)
        if (tlv_id(a) == HCP_T_NODE_STATE)
          {
            if (tlv_len(a) != sizeof(hcp_t_node_state_s))
              return;
            ns = tlv_data(a);
            n = hcp_find_node_by_hash(o, ns->node_identifier_hash, false);
            if (!n || n->update_number < cpu_to_be32(ns->update_number))
              hcp_link_send_req_node_data(l, src, ns);
          }
      return;
    }
  /* We don't accept node data via multicast. */
  if (multicast)
    return;
  /* Look for node state + node data. */
  ns = NULL;
  nd = NULL;
  tlv_for_each_in_buf(a, data, len)
    switch(tlv_id(a))
      {
      case HCP_T_NODE_STATE:
        if (ns)
          return;
        if (tlv_len(a) != sizeof(hcp_t_node_state_s))
          return;
        ns = tlv_data(a);
        break;
      case HCP_T_NODE_DATA:
        if (nd)
          return;
        nd_len = tlv_len(a) - sizeof(hcp_t_node_data_header_s);
        if (nd_len < 0)
          return;
        nd = tlv_data(a);
        nd_data = (unsigned char *)nd + nd_len;
        break;
      }
  if (!ns || !nd)
    return;
  /* If they're for different nodes, not interested. */
  if (memcmp(ns->node_identifier_hash, nd->node_identifier_hash, HCP_HASH_LEN))
    return;
  /* Is it actually valid? Should be same update #. */
  if (ns->update_number != nd->update_number)
    return;
  /* Let's see if it's more recent. */
  n = hcp_find_node_by_hash(o, ns->node_identifier_hash, true);
  if (!n)
    return;
  new_update_number = cpu_to_be32(ns->update_number);
  if (n->update_number >= new_update_number)
    return;
  if (hcp_node_is_self(n))
    {
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
      n->update_number = new_update_number;
      n->node_data_hash_dirty = true;
      o->network_hash_dirty = true;
      hcp_node_set_tlvs(n, tb.head);
      hcp_schedule(o);
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
