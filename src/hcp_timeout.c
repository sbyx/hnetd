/*
 * $Id: hcp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Wed Nov 27 21:33:02 2013 mstenber
 * Edit time:     59 min
 *
 */

#include "hcp_i.h"
#include <assert.h>

static void trickle_set_i(hcp_link l, int i)
{
  hnetd_time_t now = hcp_time(l->hcp);

  l->i = i;
  l->send_time = now + l->i * (1000 + random() % 1000) / 2000;
  l->interval_end_time = now + l->i;
}

static void trickle_upgrade(hcp_link l)
{
  int i = l->i * 2;

  i = i < HCP_TRICKLE_IMIN ? HCP_TRICKLE_IMIN
    : i > HCP_TRICKLE_IMAX ? HCP_TRICKLE_IMAX : i;
  trickle_set_i(l, i);
}

static void trickle_send(hcp_link l)
{
  if (l->c < HCP_TRICKLE_K)
    {
      if (!hcp_link_send_network_state(l, &l->hcp->multicast_address,
                                       HCP_MAXIMUM_MULTICAST_SIZE))
        return;
    }
  l->send_time = 0;
}

void hcp_run(hcp o)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = hcp_io_time(o);
  hcp_link l;
  hcp_neighbor n, n2;
  int time_since_failed_join = now - o->join_failed_time;
  
  /* Assumption: We're within RTC step here -> can use same timestamp
   * all the way. */
  o->now = now;

  /* If we weren't before, we are now; processing within timeout (no
   * sense scheduling extra timeouts within hcp_self_flush). */
  o->immediate_scheduled = true;

  /* Refresh locally originated data; by doing this, we can avoid
   * replicating code. */
  hcp_self_flush(o->own_node);

  /* Release the flag to allow more change-triggered zero timeouts to
   * be scheduled. (We don't want to do this before hcp_node_get_tlvs
   * for efficiency reasons.) */
  o->immediate_scheduled = false;

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      unsigned char buf[HCP_HASH_LEN];

      /* Store original network hash for future study. */
      memcpy(buf, o->network_hash, HCP_HASH_LEN);

      hcp_calculate_network_hash(o, o->network_hash);
      if (memcmp(buf, o->network_hash, HCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle (that is actually running; join_pending ones
           * don't really count). */
          vlist_for_each_element(&o->links, l, in_links)
            if (!l->join_pending)
              trickle_set_i(l, HCP_TRICKLE_IMIN);
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
              && hcp_link_join(l))
            trickle_set_i(l, HCP_TRICKLE_IMIN);
          else
            {
              next = TMIN(next, now + HCP_REJOIN_INTERVAL - (now - o->join_failed_time));
              continue;
            }
        }
      if (l->interval_end_time <= now)
        {
          trickle_upgrade(l);
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

      /* Look at neighbors we should be worried about.. */
      /* vlist_for_each_element(&l->neighbors, n, in_neighbors) */
      avl_for_each_element_safe(&l->neighbors.avl, n, in_neighbors.avl, n2)
        {
          hnetd_time_t next_time = HCP_INTERVAL_WORRIED
            + o->assume_bidirectional_reachability ? n->last_heard
            : n->last_response;

          /* Maybe we're not worried yet.. */
          if (next_time > now)
            {
              next = TMIN(next, next_time);
              continue;
            }

          /* We _are_ worried. But should we ping right now? */
          next_time = HCP_INTERVAL_WORRIED + n->last_ping;
          if (next_time > now)
            {
              next = TMIN(next, next_time);
              continue;
            }

          /* Yes, we should! */
          if (n->ping_count++ == HCP_INTERVAL_RETRIES)
            {
              /* Zap the neighbor */
              /* printf("neighbor gone\n"); */
              vlist_delete(&l->neighbors, &n->in_neighbors);
              continue;
            }

          /* Send a ping */
          n->last_ping = now;
          hcp_link_send_req_network_state(l, &n->last_address);
          /* printf("pinging neighbor %d\n", n->ping_count); */
        }
    }

  if (next && !o->immediate_scheduled)
    hcp_io_schedule(o, next-now);

  /* Clear the cached time, it's most likely no longer valid. */
  o->now = 0;
}
