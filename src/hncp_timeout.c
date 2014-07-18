/*
 * $Id: hncp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Thu Jul 17 09:28:37 2014 mstenber
 * Edit time:     330 min
 *
 */

#include "hncp_i.h"

static void trickle_set_i(hncp_link l, int i)
{
  hnetd_time_t now = hncp_time(l->hncp);
  int imin = l->conf->trickle_imin;
  if (!imin) imin = HNCP_TRICKLE_IMIN;
  int imax = l->conf->trickle_imax;
  if (!imax) imax = HNCP_TRICKLE_IMAX;

  i = i < imin ? imin : i > imax ? imax : i;
  l->trickle_i = i;
#if 0

  /* !!! XXX document this change somewhere; normal Trickle
   * does t=[I/2,I). We do t=[Imin/2,I) to ensure we are never
   * send starved even if someone else operates at Imin all the time.
   *
   * Note that as this doesn't change trickle interval end time,
   * unless this causes conflicts, it will _not_ cause extra traffic
   * in stable state.
  */
  /* (HNCP_TRICKLE_MAXIMUM_SEND_INTERVAL takes care of this. Which is
   * better solution should be studied.) */
  int t = imin / 2 + random() % (i - imin / 2); /* our variant */
#else
  int t = i / 2 + random() % (i / 2);
#endif /* 0 */
  l->trickle_send_time = now + t;
  l->trickle_interval_end_time = now + i;
  l->trickle_c = 0;
  L_DEBUG(HNCP_LINK_F " trickle set to %d/%d", HNCP_LINK_D(l), t, i);
}

static void trickle_upgrade(hncp_link l)
{
  trickle_set_i(l, l->trickle_i * 2);
}

static void trickle_send(hncp_link l)
{
  if (l->trickle_c < l->conf->trickle_k
      || (HNCP_TRICKLE_MAXIMUM_SEND_INTERVAL &&
          (l->last_trickle_sent + HNCP_TRICKLE_MAXIMUM_SEND_INTERVAL) <= hncp_time(l->hncp)))
    {
      l->num_trickle_sent++;
      l->last_trickle_sent = hncp_time(l->hncp);
      hncp_link_send_network_state(l, &l->hncp->multicast_address,
                                   HNCP_MAXIMUM_MULTICAST_SIZE);
    }
  else
    {
      l->num_trickle_skipped++;
      L_DEBUG(HNCP_LINK_F " trickle already has c=%d >= k=%d, not sending",
              HNCP_LINK_D(l), l->trickle_c, l->conf->trickle_k);
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
        hncp_notify_subscribers_tlvs_changed(n, n->tlv_container_valid, NULL);

      hncp_notify_subscribers_node_changed(n, value);

      if (value)
        hncp_notify_subscribers_tlvs_changed(n, NULL, n->tlv_container_valid);
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

  /* Logic fails if time isn't moving forward-ish */
  assert(now != o->last_prune);

  L_DEBUG("hncp_prune %p", o);

  /* Prune the node graph. IOW, start at own node, flood fill, and zap
   * anything that didn't seem appropriate. */
  vlist_update(&o->nodes);

  hncp_prune_rec(o->own_node);

  hncp_node n;
  hnetd_time_t next_time = 0;
  vlist_for_each_element(&o->nodes, n, in_nodes)
    {
      if (n->in_nodes.version == o->nodes.version)
        continue;
      if (n->last_reachable_prune < grace_after)
        continue;
      next_time = TMIN(next_time,
                       n->last_reachable_prune + HNCP_PRUNE_GRACE_PERIOD + 1);
      vlist_add(&o->nodes, &n->in_nodes, n);
      _node_set_reachable(n, false);
    }
  o->next_prune = next_time;
  vlist_flush(&o->nodes);
  o->last_prune = now;
}

void hncp_link_reset_trickle(hncp_link l)
{
  if (l->join_pending)
    return;
  trickle_set_i(l, l->conf->trickle_imin);
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

  if (!o->disable_prune)
    {
      if (o->graph_dirty)
        o->next_prune = HNCP_MINIMUM_PRUNE_INTERVAL + o->last_prune;

      if (o->next_prune && o->next_prune <= now)
        {
          o->graph_dirty = false;
          hncp_prune(o);
        }

      /* next_prune may be set _by_ hncp_prune, therefore redundant
       * looking check */
      next = TMIN(next, o->next_prune);
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
            trickle_set_i(l, l->conf->trickle_imin);
          else
            {
              next = TMIN(next, now + HNCP_REJOIN_INTERVAL - (now - o->join_failed_time));
              continue;
            }
        }

      if (l->trickle_interval_end_time <= now)
        trickle_upgrade(l);
      else if (l->trickle_send_time && l->trickle_send_time <= now)
        trickle_send(l);

      next = TMIN(next, l->trickle_interval_end_time);
      next = TMIN(next, l->trickle_send_time);

      /* Look at neighbors we should be worried about.. */
      /* vlist_for_each_element(&l->neighbors, n, in_neighbors) */
      avl_for_each_element_safe(&l->neighbors.avl, n, in_neighbors.avl, n2)
        {
          hnetd_time_t next_time;

          if (!n->ping_count)
            {
              /* For new neighbors, send ~immediate ping */
              if (!n->last_response)
                next_time = now;
              /* if they're in sync with me, we can just use last_heard */
              else if (n->last_heard > n->last_response && n->in_sync)
                next_time = n->last_heard + l->conf->ping_worried_t;
              else
                next_time = n->last_response + l->conf->ping_worried_t;
            }
          else
            next_time = n->last_ping + (l->conf->ping_retry_base_t << n->ping_count);

          /* No cause to do anything right now. */
          if (next_time > now)
            {
              next = TMIN(next, next_time);
              continue;
            }

          if (n->ping_count++== l->conf->ping_retries)
            {
              /* Zap the neighbor */
              L_DEBUG(HNCP_NEIGH_F " gone on " HNCP_LINK_F,
                      HNCP_NEIGH_D(n), HNCP_LINK_D(l));
              vlist_delete(&l->neighbors, &n->in_neighbors);
              continue;
            }

          n->last_ping = hncp_time(o);
          /* Send a ping */
          L_DEBUG("pinging " HNCP_NEIGH_F "  on " HNCP_LINK_F,
                  HNCP_NEIGH_D(n), HNCP_LINK_D(l));
          hncp_link_send_req_network_state(l, &n->last_address);
        }
    }

  if (next && !o->immediate_scheduled)
    hncp_io_schedule(o, next - now);

  /* Clear the cached time, it's most likely no longer valid. */
  o->now = 0;
}
