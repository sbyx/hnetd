/*
 * $Id: dncp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Wed Feb 11 12:19:39 2015 mstenber
 * Edit time:     488 min
 *
 */

#include "dncp_i.h"

static void trickle_set_i(dncp_link l, int i)
{
  hnetd_time_t now = dncp_time(l->dncp);
  int imin = l->conf->trickle_imin;
  if (!imin) imin = DNCP_TRICKLE_IMIN;
  int imax = l->conf->trickle_imax;
  if (!imax) imax = DNCP_TRICKLE_IMAX;

  i = i < imin ? imin : i > imax ? imax : i;
  l->trickle_i = i;
  int t = i / 2 + random() % (i / 2);
  l->trickle_send_time = now + t;
  l->trickle_interval_end_time = now + i;
  l->trickle_c = 0;
  L_DEBUG(DNCP_LINK_F " trickle set to %d/%d", DNCP_LINK_D(l), t, i);
}

static void trickle_upgrade(dncp_link l)
{
  trickle_set_i(l, l->trickle_i * 2);
}

static void trickle_send_nocheck(dncp_link l)
{
  l->num_trickle_sent++;
  l->last_trickle_sent = dncp_time(l->dncp);
  dncp_profile_link_send_network_state(l);
  if (l->conf->keepalive_interval)
    l->next_keepalive_time = l->last_trickle_sent + l->conf->keepalive_interval;
}

static void trickle_send(dncp_link l)
{
  if (l->trickle_c < l->conf->trickle_k)
    {
      trickle_send_nocheck(l);
    }
  else
    {
      l->num_trickle_skipped++;
      L_DEBUG(DNCP_LINK_F " trickle already has c=%d >= k=%d, not sending",
              DNCP_LINK_D(l), l->trickle_c, l->conf->trickle_k);
    }
  l->trickle_send_time = 0;
}

static void _node_set_reachable(dncp_node n, bool value)
{
  dncp o = n->dncp;
  bool is_reachable = o->last_prune == n->last_reachable_prune;

  if (is_reachable != value)
    {
      o->network_hash_dirty = true;

      if (!value)
        dncp_notify_subscribers_tlvs_changed(n, n->tlv_container_valid, NULL);

      dncp_notify_subscribers_node_changed(n, value);

      if (value)
        dncp_notify_subscribers_tlvs_changed(n, NULL, n->tlv_container_valid);
    }
  if (value)
    n->last_reachable_prune = dncp_time(o);
}

static void _prune_rec(dncp_node n)
{
  struct tlv_attr *tlvs, *a;
  dncp_t_node_data_neighbor ne;
  dncp_node n2;

  if (!n)
    return;

  /* Stop the iteration if we're already added to current
   * generation. */
  if (n->in_nodes.version == n->dncp->nodes.version)
    return;

  tlvs = dncp_node_get_tlvs(n);

  L_DEBUG("_prune_rec %s / %p = %p",
          DNCP_NODE_REPR(n), n, tlvs);

  /* No TLVs? No point recursing, unless the node is us (we have to
   * visit it always in any case). */
  if (!tlvs && n != n->dncp->own_node)
    return;

  /* Refresh the entry - we clearly did reach it. */
  vlist_add(&n->dncp->nodes, &n->in_nodes, n);
  _node_set_reachable(n, true);

  /* Look at it's neighbors. */
  tlv_for_each_attr(a, tlvs)
    if ((ne = dncp_tlv_neighbor(a)))
      {
        /* Ignore if it's not _bidirectional_ neighbor. Unidirectional
         * ones lead to graph not settling down. */
        if ((n2 = dncp_node_find_neigh_bidir(n, ne)))
          _prune_rec(n2);
      }
}

static void dncp_prune(dncp o)
{
  hnetd_time_t now = dncp_time(o);
  hnetd_time_t grace_after = now - DNCP_PRUNE_GRACE_PERIOD;

  /* Logic fails if time isn't moving forward-ish */
  assert(now != o->last_prune);

  L_DEBUG("dncp_prune %p", o);

  /* Prune the node graph. IOW, start at own node, flood fill, and zap
   * anything that didn't seem appropriate. */
  vlist_update(&o->nodes);

  _prune_rec(o->own_node);

  dncp_node n;
  hnetd_time_t next_time = 0;
  vlist_for_each_element(&o->nodes, n, in_nodes)
    {
      if (n->in_nodes.version == o->nodes.version)
        continue;
      if (n->last_reachable_prune < grace_after)
        continue;
      next_time = TMIN(next_time,
                       n->last_reachable_prune + DNCP_PRUNE_GRACE_PERIOD + 1);
      vlist_add(&o->nodes, &n->in_nodes, n);
      _node_set_reachable(n, false);
    }
  o->next_prune = next_time;
  vlist_flush(&o->nodes);
  o->last_prune = now;
}

#if L_LEVEL >= 7

#define SET_NEXT(_v, reason)                                    \
do {                                                            \
  hnetd_time_t v = _v;                                          \
  if (v)                                                        \
    {                                                           \
      if (v < now)                                              \
        {                                                       \
          L_DEBUG("invalid value due to %s: %d in past",        \
                  reason, (int)(now-v));                        \
        }                                                       \
      else if (!next || next > v)                               \
        {                                                       \
          L_DEBUG("setting next to %d due to %s",               \
                  (int)(v-now), reason);                        \
          next = v;                                             \
        }                                                       \
    }                                                           \
 } while(0)

#else

#define SET_NEXT(v, reason) next = TMIN(next, v)

#endif /* L_LEVEL >= 7 */

static hnetd_time_t
_neighbor_interval(dncp o, struct tlv_attr *neighbor_tlv)
{
  dncp_t_node_data_neighbor neigh = dncp_tlv_neighbor(neighbor_tlv);
  if (!neigh)
    {
      L_ERR("invalid (internally generated) dncp_t_node_data_neighbor");
      return 1;
    }
  dncp_node n = dncp_find_node_by_node_identifier(o, &neigh->neighbor_node_identifier, false);
  if (!n)
    {
      return DNCP_KEEPALIVE_INTERVAL;
    }

  struct tlv_attr *a;
  uint32_t value = DNCP_KEEPALIVE_INTERVAL;
  dncp_node_for_each_tlv_with_type(n, a, DNCP_T_KEEPALIVE_INTERVAL)
    {
      dncp_t_keepalive_interval ka = tlv_data(a);
      if (tlv_len(a) != sizeof(*ka))
        {
          L_DEBUG("invalid keepalive tlv length");
          continue;
        }
      if (ka->link_id && ka->link_id != neigh->neighbor_link_id)
        {
          continue;
        }
      value = be32_to_cpu(ka->interval_in_ms) * HNETD_TIME_PER_SECOND / 1000;
      if (ka->link_id)
        break;
    }
  /* L_DEBUG("using keepalive %d", value); */
  return value;
}

void dncp_run(dncp o)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = dncp_io_time(o);
  dncp_link l;
  dncp_tlv t, t2;

  /* Assumption: We're within RTC step here -> can use same timestamp
   * all the way. */
  o->now = now;

  /* If we weren't before, we are now processing within timeout (no
   * sense scheduling extra timeouts within dncp_self_flush or dncp_prune). */
  o->immediate_scheduled = true;

  /* Handle the own TLV roll-over first. */
  if (!o->tlvs_dirty && !o->republish_tlvs)
    {
      hnetd_time_t next_time =
        o->own_node->origination_time + (1LL << 32) - (1LL << 16);
      if (next_time <= now)
        o->republish_tlvs = true;
      else
        SET_NEXT(next_time, "roll-over");
    }

  /* Refresh locally originated data; by doing this, we can avoid
   * replicating code. */
  dncp_self_flush(o->own_node);

  if (!o->disable_prune)
    {
      if (o->graph_dirty)
        o->next_prune = DNCP_MINIMUM_PRUNE_INTERVAL + o->last_prune;

      if (o->next_prune && o->next_prune <= now)
        {
          o->graph_dirty = false;
          dncp_prune(o);
        }

      /* next_prune may be set _by_ dncp_prune, therefore redundant
       * looking check */
      SET_NEXT(o->next_prune, "next_prune");
    }

  /* Release the flag to allow more change-triggered zero timeouts to
   * be scheduled. (We don't want to do this before we're done with
   * our mutations of state that can be addressed by the ordering of
   * events within dncp_run). */
  o->immediate_scheduled = false;

  /* First off: If the network hash is dirty, recalculate it (and hope
   * the outcome ISN'T). */
  if (o->network_hash_dirty)
    {
      /* Store original network hash for future study. */
      dncp_hash_s old_hash = o->network_hash;

      dncp_calculate_network_hash(o);
      if (memcmp(&old_hash, &o->network_hash, DNCP_HASH_LEN))
        {
          /* Shocker. The network hash changed -> reset _every_
           * trickle (that is actually running; join_pending ones
           * don't really count). */
          vlist_for_each_element(&o->links, l, in_links)
            trickle_set_i(l, l->conf->trickle_imin);
        }
    }

  vlist_for_each_element(&o->links, l, in_links)
    {
      /* Update the 'active' link's published keepalive interval, if need be */
      dncp_link_set_keepalive_interval(l, l->conf->keepalive_interval);

      /* If we're in join pending state, we retry every
       * DNCP_REJOIN_INTERVAL if necessary. */
      if (l->join_failed_time)
        {
          hnetd_time_t next_time =
            l->join_failed_time + DNCP_REJOIN_INTERVAL;
          if (next_time <= now)
            {
              if (!dncp_io_set_ifname_enabled(o, l->ifname, true))
                {
                  l->join_failed_time = now;
                }
              else
                {
                  l->join_failed_time = 0;

                  /* This is essentially second-stage init for a
                   * link. Before multicast join succeeds, it is
                   * essentially zombie. */
                  if (l->conf->keepalive_interval)
                    l->next_keepalive_time =
                      dncp_time(l->dncp) + l->conf->keepalive_interval;
                  trickle_set_i(l, l->conf->trickle_imin);
                }
            }
          /* If still join pending, do not use this for anything. */
          if (l->join_failed_time)
            {
              /* join_failed_time may have changed.. */
              hnetd_time_t next_time =
                l->join_failed_time + DNCP_REJOIN_INTERVAL;
              SET_NEXT(next_time, "rejoin");
              continue;
            }
        }

      if (l->trickle_interval_end_time <= now)
        trickle_upgrade(l);
      else if (l->trickle_send_time && l->trickle_send_time <= now)
        trickle_send(l);
      else if (l->next_keepalive_time && l->next_keepalive_time <= now)
        {
          L_DEBUG("sending keep-alive");
          trickle_send_nocheck(l);
          /* Do not increment Trickle i, but set next t to i/2 .. i */
          trickle_set_i(l, l->trickle_i);
        }
      SET_NEXT(l->trickle_interval_end_time, "trickle_interval_end_time");
      SET_NEXT(l->trickle_send_time, "trickle_send_time");
      SET_NEXT(l->next_keepalive_time, "next_keepalive_time");
    }

  /* Look at neighbors we should be worried about.. */
  /* vlist_for_each_element(&l->neighbors, n, in_neighbors) */
  dncp_for_each_local_tlv_safe(o, t, t2)
    if (tlv_id(&t->tlv) == DNCP_T_NODE_DATA_NEIGHBOR)
      {
        dncp_neighbor n = dncp_tlv_get_extra(t);

        hnetd_time_t next_time =
          n->last_sync +
          _neighbor_interval(o, &t->tlv) * DNCP_KEEPALIVE_MULTIPLIER;

        /* No cause to do anything right now. */
        if (next_time > now)
          {
            SET_NEXT(next_time, "neighbor validity");
            continue;
          }

        /* Zap the neighbor */
#if L_LEVEL >= 7
        dncp_t_node_data_neighbor ne = tlv_data(&t->tlv);
        l = dncp_find_link_by_id(o, ne->link_id);
        L_DEBUG("Neighbor %s gone on " DNCP_LINK_F " - nothing in %d ms",
                DNCP_STRUCT_REPR(ne->neighbor_node_identifier),
                DNCP_LINK_D(l), (int) (now - n->last_sync));
#endif /* L_LEVEL >= 7 */
        dncp_remove_tlv(o, t);
    }

  if (next && !o->immediate_scheduled)
    {
      hnetd_time_t delta = next - now;
      if (delta < 0)
        delta = 0;
      else if (delta > (1 << 16))
        delta = 1 << 16;
      dncp_io_schedule(o, delta);
      L_DEBUG("next scheduled in %d", (int)delta);
    }

  /* Clear the cached time, it's most likely no longer valid. */
  o->now = 0;
}
