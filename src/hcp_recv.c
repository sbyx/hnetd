/*
 * $Id: hcp_recv.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Wed Nov 27 14:42:41 2013 mstenber
 * Edit time:     32 min
 *
 */

#include "hcp_i.h"

/*
 * This module contains the logic to handle reception of traffic from
 * single- or multicast sources. The actual low-level IO is performed
 * in hcp_io.
 */

#define tlv_for_each_attr_raw(buf, len, attr, pos)      \
for (pos = 0 ;                                          \
     (pos + sizeof(struct tlv_attr)) <= (size_t)len     \
       && (attr = ((struct tlv_attr *)(buf+pos)))       \
       && (pos + tlv_pad_len(attr)) <= (size_t)len ;    \
     pos += tlv_pad_len(attr))

bool hcp_link_send_node_state(hcp_link l,
                              struct in6_addr *dst,
                              hcp_node n)
{
  /* XXX */
  return false;
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
  struct tlv_attr *nid = NULL;
  struct tlv_attr *nethash = NULL;
  int nodestates = 0;

  /* First pass just estimates what's in the payload + handles the few
   * request messages we support. */
  tlv_for_each_attr_raw(data, len, a, pos)
    {
      switch (tlv_id(a))
        {
        case HCP_T_NODE_ID:
          nid = a;
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
          break;
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
          break;
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
