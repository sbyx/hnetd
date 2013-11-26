/*
 * $Id: hcp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Tue Nov 26 15:48:16 2013 mstenber
 * Edit time:     24 min
 *
 */

#include "hcp_i.h"
#include <assert.h>

static void trickle_set_i(hcp_link l, hnetd_time_t now, int i)
{
  l->i = i;
  l->send_time = now + l->i * (1000 + random() % 1000) / 2000;
  l->interval_end_time = now + l->i;
}

static void trickle_upgrade(hcp_link l, hnetd_time_t now)
{
  int i = l->i * 2;
  i = i < HCP_TRICKLE_IMIN ? HCP_TRICKLE_IMIN
    : i > HCP_TRICKLE_IMAX ? HCP_TRICKLE_IMAX : i;
  trickle_set_i(l, now, i);
}

#define HCP_T_NODE_STATE_V_SIZE (2 * HCP_HASH_LEN + 2 * 4)

static void trickle_send(hcp_link l, hnetd_time_t now)
{
  hcp_node n;
  hcp o = l->hcp;
  struct tlv_buf tb;
  struct tlv_attr *a;
  unsigned char *c;

  if (l->c < HCP_TRICKLE_K)
    {
      memset(&tb, 0, sizeof(tb));
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

  /* If we weren't before, we are now; processing within timeout (no
   * sense scheduling extra timeouts within hcp_self_flush). */
  o->immediate_scheduled = true;

  /* Refresh locally originated data; by doing this, we can avoid
   * replicating code. */
  hcp_self_flush(o->own_node, now);

  /* Release the flag to allow more change-triggered zero timeouts to
   * be scheduled. (We don't want to do this before hcp_node_get_tlvs
   * for efficiency reasons.) */
  o->immediate_scheduled = false;

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
           * trickle (that is actually running; join_pending ones
           * don't really count). */
          vlist_for_each_element(&o->links, l, in_links)
            if (!l->join_pending)
              trickle_set_i(l, now, HCP_TRICKLE_IMIN);
        }
      o->network_hash_dirty = false;
      /* printf("network_hash_dirty -> false\n"); */
    }

  vlist_for_each_element(&o->links, l, in_links)
    {
      /* If we're in join pending state, we retry every
       * HCP_REJOIN_INTERVAL if necessary. */
      if (l->join_pending)
        {
          if (time_since_failed_join >= HCP_REJOIN_INTERVAL
              && hcp_link_join(l, now))
            trickle_set_i(l, now, HCP_TRICKLE_IMIN);
          else
            {
              next = TMIN(next, now + HCP_REJOIN_INTERVAL - (now - o->join_failed_time));
              continue;
            }
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

          trickle_send(l, now);
        }
      next = TMIN(next, l->interval_end_time);
    }

  /* Trickle algorithm should NOT cause any immediate scheduling. If
   * it does, something is broken. */
  assert(!o->immediate_scheduled);

  if (next)
    hcp_io_schedule(o, next-now);
}
