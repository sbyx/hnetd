/*
 * $Id: hcp_recv.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Wed Nov 27 18:57:13 2013 mstenber
 * Edit time:     73 min
 *
 */

#include "hcp_i.h"

/*
 * This module contains the logic to handle reception of traffic from
 * single- or multicast sources. The actual low-level IO is performed
 * in hcp_io.
 */

/* TLV attribute iteration for raw buffer. */

#define tlv_for_each_attr_raw(buf, len, attr, pos)      \
for (pos = 0 ;                                          \
     (pos + sizeof(struct tlv_attr)) <= (size_t)len     \
       && (attr = ((struct tlv_attr *)(buf+pos)))       \
       && (pos + tlv_pad_len(attr)) <= (size_t)len ;    \
     pos += tlv_pad_len(attr))

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
  struct tlv_attr *a = tlv_new(tb, HCP_T_NETWORK_HASH,
                               sizeof(hcp_t_node_data_header_s) +
                               n->tlv_container ?
                               tlv_len(n->tlv_container) : 0);
  hcp_t_node_data_header h;

  if (!a)
    return false;
  h = tlv_data(a);
  memcpy(h->node_identifier_hash, n->node_identifier_hash, HCP_HASH_LEN);
  h->update_number = cpu_to_be32(n->update_number);
  memcpy((unsigned char *)h + sizeof(hcp_t_node_data_header_s),
         n->tlv_container, tlv_len(n->tlv_container));
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
  memcpy(lid->node_identifier_hash, l->hcp->own_node->node_identifier_hash, HCP_HASH_LEN);
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
      return rc > 0;
    }
 err:
  tlv_buf_free(&tb);
  return false;
}

bool hcp_link_send_node_state(hcp_link l,
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
    }
  tlv_buf_free(&tb);
  return r;
}

/************************************************************ Input handling */

static void
_heard(hcp_link l, hcp_t_link_id lid)
{
  /* XXX */
}

/* Handle a single received message. */
static void
handle_message(hcp_link l,
               struct in6_addr *src,
               unsigned char *data, ssize_t len,
               bool multicast)
{
  hcp o = l->hcp;
  unsigned int pos;
  struct tlv_attr *a;
  hcp_node n;
  hcp_t_link_id lid = NULL;
  struct tlv_attr *nethash = NULL;
  int nodestates = 0;

  /* Validate that link id exists. */
  tlv_for_each_attr_raw(data, len, a, pos)
    if (tlv_id(a) == HCP_T_LINK_ID)
      {
        /* Error to have multiple top level link id's. */
        if (lid)
          return;
        if (tlv_len(a) == sizeof(hcp_t_link_id_s))
          {
            lid = tlv_data(a);
            _heard(l, lid);
          }
        else
          return; /* weird link id */
      }

  if (!lid)
    return;

  _heard(l, lid);

  /* Estimates what's in the payload + handles the few
   * request messages we support. */
  tlv_for_each_attr_raw(data, len, a, pos)
    {
      switch (tlv_id(a))
        {
        case HCP_T_LINK_ID:
          /* nop - already handled */
          break;
        case HCP_T_NETWORK_HASH:
          nethash = a;
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
                (void)hcp_link_send_node_state(l, src, n);
            }
          return;
        }
    }
  /* XXX - handle normal state synchronization

     Three different cases:
     - raw network hash
     - network hash + node states
     - node data(s)
  */
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
