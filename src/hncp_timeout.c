/*
 * $Id: hncp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Tue Apr 29 22:10:31 2014 mstenber
 * Edit time:     205 min
 *
 */

#include "hncp_i.h"
#include <assert.h>

static void trickle_set_i(hncp_link l, int i)
{
  hnetd_time_t now = hncp_time(l->hncp);

  l->trickle_i = i;
  l->trickle_send_time = now + i * (1000 + random() % 1000) / 2000;
  l->trickle_interval_end_time = now + i;
  l->trickle_c = 0;
}

static void trickle_upgrade(hncp_link l)
{
  int i = l->trickle_i * 2;

  i = i < HNCP_TRICKLE_IMIN ? HNCP_TRICKLE_IMIN
    : i > HNCP_TRICKLE_IMAX ? HNCP_TRICKLE_IMAX : i;
  trickle_set_i(l, i);
}

static void trickle_send(hncp_link l)
{
  if (l->trickle_c < HNCP_TRICKLE_K)
    {
      if (!hncp_link_send_network_state(l, &l->hncp->multicast_address,
                                        HNCP_MAXIMUM_MULTICAST_SIZE))
        return;
    }
  l->trickle_send_time = 0;
}

static void _node_set_reachable(hncp_node n, bool value)
{
  hncp o = n->hncp;
  bool is_reachable = o->last_prune == n->last_reachable_prune;

  if (is_reachable != value)
    {
      o->network_hash_dirty = true;

      if (!value)
        hncp_notify_subscribers_tlvs_changed(n, n->tlv_container, NULL);

      hncp_notify_subscribers_node_changed(n, value);

      if (value)
        hncp_notify_subscribers_tlvs_changed(n, NULL, n->tlv_container);
    }
  if (value)
    n->last_reachable_prune = hncp_time(o);
}

static void hncp_prune_rec(hncp_node n)
{
  struct tlv_attr *tlvs, *a;
  hncp_t_node_data_neighbor ne;
  hncp_node n2;

  if (!n)
    return;

  /* Stop the iteration if we're already added to current
   * generation. */
  if (n->in_nodes.version == n->hncp->nodes.version)
    return;

  tlvs = hncp_node_get_tlvs(n);

  L_DEBUG("hncp_prune_rec %llx / %p = %p",
          hncp_hash64(&n->node_identifier_hash), n, tlvs);

  /* No TLVs? No point recursing, unless the node is us (we have to
   * visit it always in any case). */
  if (!tlvs && n != n->hncp->own_node)
    return;

  /* Refresh the entry - we clearly did reach it. */
  vlist_add(&n->hncp->nodes, &n->in_nodes, n);
  _node_set_reachable(n, true);

  /* Look at it's neighbors. */
  tlv_for_each_attr(a, tlvs)
    if ((ne = hncp_tlv_neighbor(a)))
      {
        /* Ignore if it's not _bidirectional_ neighbor. Unidirectional
         * ones lead to graph not settling down. */
        if ((n2 = hncp_node_find_neigh_bidir(n, ne)))
          hncp_prune_rec(n2);
      }
}

static void hncp_prune(hncp o)
{
  hnetd_time_t now = hncp_time(o);
  hnetd_time_t grace_after = now - HNCP_PRUNE_GRACE_PERIOD;

  L_DEBUG("hncp_prune %p", o);
  /* Prune the node graph. IOW, start at own node, flood fill, and zap
   * anything that didn't seem appropriate. */
  vlist_update(&o->nodes);
  if (o->assume_bidirectional_reachability)
    {
      /* If we assume reachability is bidirectional, we can just
       * traverse the graph. */
      hncp_prune_rec(o->own_node);
    }
  else
    {
      hncp_link l;
      hncp_neighbor ne;
      hncp_node n = o->own_node, n2;

      /* We're always reachable. */
      vlist_add(&o->nodes, &n->in_nodes, n);
      _node_set_reachable(n, true);

      /* Only neighbors we believe to be reachable are the ones we can
       * find in our own link -> neighbor relations, with non-zero
       * last_response. */
      vlist_for_each_element(&o->links, l, in_links)
        {
          vlist_for_each_element(&l->neighbors, ne, in_neighbors)
            {
              if (!ne->last_response)
                  continue;
              n2 = hncp_node_find_neigh_bidir2(n,
                                               cpu_to_be32(l->iid),
                                               cpu_to_be32(ne->iid),
                                               &ne->node_identifier_hash);
              if (n2)
                hncp_prune_rec(n2);
            }
        }
    }

  hncp_node n;
  vlist_for_each_element(&o->nodes, n, in_nodes)
    {
      if (n->in_nodes.version != o->nodes.version)
        {
          if (!n->last_reachable_prune)
            n->last_reachable_prune = now - 1;
          else if (n->last_reachable_prune < grace_after)
            continue;
          vlist_add(&o->nodes, &n->in_nodes, n);
          _node_set_reachable(n, false);
        }
    }
  vlist_flush(&o->nodes);
  o->last_prune = now;
}

void hncp_link_reset_trickle(hncp_link l)
{
  if (l->join_pending)
    return;
  trickle_set_i(l, HNCP_TRICKLE_IMIN);
  hncp_schedule(l->hncp);
}

void hncp_run(hncp o)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = hncp_io_time(o);
  hncp_link l;
  hncp_neighbor n, n2;
  int time_since_failed_join = now - o->join_failed_time;

  /* Assumption: We're within RTC step here -> can use same timestamp
   * all the way. */
  o->now = now;

  /* If we weren't before, we are now processing within timeout (no
   * sense scheduling extra timeouts within hncp_self_flush or hncp_prune). */
  o->immediate_scheduled = true;

  /* Refresh locally originated data; by doing this, we can avoid
   * replicating code. */
  hncp_self_flush(o->own_node);

  if (o->graph_dirty && !o->disable_prune)
    {
      hnetd_time_t prune_at = HNCP_MINIMUM_PRUNE_INTERVAL + o->last_prune;

      if (prune_at > now)
        {
          next = TMIN(next, prune_at);
        }
      else
        {
          /* Prune may re-set graph dirty, if it removes nodes.
           * So mark graph non-dirty before the call. */
          o->graph_dirty = false;

          hncp_prune(o);
        }
    }

  /* Release the flag to allow more change-triggered zero timeouts to
   * be scheduled. (We don't want to do this before we're done with
   * our mutations of state that can be addressed by the ordering of
   * events within hncp_run). */
  o->immediate_scheduled = false;

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      /* Store original network hash for future study. */
      hncp_hash_s old_hash = o->network_hash;

      hncp_calculate_network_hash(o);
      if (memcmp(&old_hash, &o->network_hash, HNCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle (that is actually running; join_pending ones
           * don't really count). */
          vlist_for_each_element(&o->links, l, in_links)
            hncp_link_reset_trickle(l);
        }
    }

  vlist_for_each_element(&o->links, l, in_links)
    {
      /* If we're in join pending state, we retry every
       * HNCP_REJOIN_INTERVAL if necessary. */
      if (l->join_pending)
        {
          if (time_since_failed_join >= HNCP_REJOIN_INTERVAL
              && hncp_link_join(l))
            trickle_set_i(l, HNCP_TRICKLE_IMIN);
          else
            {
              next = TMIN(next, now + HNCP_REJOIN_INTERVAL - (now - o->join_failed_time));
              continue;
            }
        }

      if (l->trickle_interval_end_time <= now)
        {
          trickle_upgrade(l);
          next = TMIN(next, l->trickle_send_time);
        }
      else
        {
          next = TMIN(next, l->trickle_interval_end_time);
          if (l->trickle_send_time)
            {
              if (l->trickle_send_time > now)
                next = TMIN(next, l->trickle_send_time);
              else
                trickle_send(l);
            }
        }

      /* Look at neighbors we should be worried about.. */
      /* vlist_for_each_element(&l->neighbors, n, in_neighbors) */
      avl_for_each_element_safe(&l->neighbors.avl, n, in_neighbors.avl, n2)
        {
          hnetd_time_t next_time = HNCP_INTERVAL_WORRIED
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
          next_time = HNCP_INTERVAL_WORRIED + n->last_ping;
          if (next_time > now)
            {
              next = TMIN(next, next_time);
              continue;
            }

          /* Yes, we should! */
          if (n->ping_count++ == HNCP_INTERVAL_RETRIES)
            {
              /* Zap the neighbor */
              L_DEBUG("neighbor %llx is gone - no response to pings",
                      hncp_hash64(&n->node_identifier_hash));
              vlist_delete(&l->neighbors, &n->in_neighbors);
              continue;
            }

          /* Send a ping */
          n->last_ping = now;
          L_DEBUG("pinging neighbor %llx", hncp_hash64(&n->node_identifier_hash));
          hncp_link_send_req_network_state(l, &n->last_address);
        }
    }

  if (next && !o->immediate_scheduled)
    hncp_io_schedule(o, next-now);

  /* Clear the cached time, it's most likely no longer valid. */
  o->now = 0;
}
