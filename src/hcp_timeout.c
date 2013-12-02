/*
 * $Id: hcp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Mon Dec  2 12:58:45 2013 mstenber
 * Edit time:     90 min
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

static void hcp_prune_rec(hcp_node n)
{
  struct tlv_attr *tlvs, *a;
  unsigned int rem;
  hcp_t_node_data_neighbor ne;
  hcp_node n2;

  if (!n)
    return;

  /* Stop the iteration if we're already added to current
   * generation. */
  if (n->in_nodes.version == n->hcp->nodes.version)
    return;

  hcp_node_get_tlvs(n, &tlvs);

  /* No TLVs? No point recursing, unless the node is us (we have to
   * visit it always in any case). */
  if (!tlvs && n != n->hcp->own_node)
    return;

  /* Refresh the entry - we clearly did reach it. */
  vlist_add(&n->hcp->nodes, &n->in_nodes, n);

  /* Look at it's neighbors. */
  tlv_for_each_attr(a, tlvs, rem)
    if (tlv_id(a) == HCP_T_NODE_DATA_NEIGHBOR)
      if (tlv_len(a) == sizeof(hcp_t_node_data_neighbor_s))
        {
          ne = tlv_data(a);
          n2 = hcp_find_node_by_hash(n->hcp, &ne->neighbor_node_identifier_hash,
                                     false);
          hcp_prune_rec(n2);
        }
}

static void hcp_prune(hcp o)
{
  /* Prune the node graph. IOW, start at own node, flood fill, and zap
   * anything that didn't seem appropriate. */
  vlist_update(&o->nodes);
  if (o->assume_bidirectional_reachability)
    {
      /* If we assume reachability is bidirectional, we can just
       * traverse the graph. */
      hcp_prune_rec(o->own_node);
    }
  else
    {
      hcp_link l;
      hcp_neighbor ne;
      hcp_node n = o->own_node;

      /* We're always reachable. */
      vlist_add(&o->nodes, &n->in_nodes, n);

      /* Only neighbors we believe to be reachable are the ones we can
       * find in our own link -> neighbor relations, with non-zero
       * last_response. */
      vlist_for_each_element(&o->links, l, in_links)
        {
          vlist_for_each_element(&l->neighbors, ne, in_neighbors)
            {
              if (ne->last_response)
                {
                  /* Ok, this is clearly reachable neighbor. */
                  n = hcp_find_node_by_hash(o,
                                            &ne->node_identifier_hash, false);
                  hcp_prune_rec(n);
                }
            }
        }
    }
  vlist_flush(&o->nodes);
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

  if (o->neighbors_dirty && !o->disable_prune)
    {
      hnetd_time_t prune_at = HCP_MINIMUM_PRUNE_INTERVAL + o->last_prune;

      if (prune_at > now)
        {
          next = TMIN(next, prune_at);
        }
      else
        {
          hcp_prune(o);
          o->neighbors_dirty = false;
          o->last_prune = now;
        }
    }

  /* Release the flag to allow more change-triggered zero timeouts to
   * be scheduled. (We don't want to do this before we're done with
   * our mutations of state that can be addressed by the ordering of
   * events within hcp_run). */
  o->immediate_scheduled = false;

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      /* Store original network hash for future study. */
      hcp_hash_s old_hash = o->network_hash;

      hcp_calculate_network_hash(o);
      if (memcmp(&old_hash, &o->network_hash, HCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle (that is actually running; join_pending ones
           * don't really count). */
          vlist_for_each_element(&o->links, l, in_links)
            if (!l->join_pending)
              trickle_set_i(l, HCP_TRICKLE_IMIN);
        }
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
            + (o->assume_bidirectional_reachability
               ? n->last_heard
               : n->last_response);

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
