/*
 * $Id: hcp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Tue Nov 26 08:33:04 2013 mstenber
 * Edit time:     1 min
 *
 */

#include "hcp_i.h"

/* Once per second */
#define HCP_REJOIN_INTERVAL 1000

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
              || !hcp_link_join(l, now)))
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
