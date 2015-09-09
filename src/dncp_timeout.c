/*
 * $Id: dncp_timeout.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:28:59 2013 mstenber
 * Last modified: Wed Sep  9 15:12:29 2015 mstenber
 * Edit time:     609 min
 *
 */

#include "dncp_i.h"

static void ep_i_set_keepalive_interval(dncp_ep_i l, uint32_t value)
{
  if (l->published_keepalive_interval == value)
    return;
  dncp o = l->dncp;
  if (l->published_keepalive_interval != DNCP_KEEPALIVE_INTERVAL(o))
    {
      dncp_t_keepalive_interval_s ka = { .ep_id = l->ep_id,
                                         .interval_in_ms = cpu_to_be32(l->published_keepalive_interval) };
      dncp_remove_tlv_matching(o, DNCP_T_KEEPALIVE_INTERVAL, &ka, sizeof(ka));
    }
  if (value != DNCP_KEEPALIVE_INTERVAL(o))
    {
      dncp_t_keepalive_interval_s ka = { .ep_id = l->ep_id,
                                         .interval_in_ms = cpu_to_be32(value) };
      dncp_add_tlv(o, DNCP_T_KEEPALIVE_INTERVAL, &ka, sizeof(ka), 0);
    }
  l->published_keepalive_interval = value;
}


static void trickle_set_i(dncp_trickle t, dncp_ep_i l, int i)
{
  hnetd_time_t now = dncp_time(l->dncp);
  int imin = l->conf.trickle_imin;
  int imax = l->conf.trickle_imax;

  i = i < imin ? imin : i > imax ? imax : i;
  t->i = i;
  t->send_time = now + i / 2 + random() % (i / 2);
  t->interval_end_time = now + i;
  t->c = 0;
}

static void trickle_upgrade(dncp_trickle t, dncp_ep_i l)
{
  trickle_set_i(t, l, t->i * 2);
}

static void trickle_send_nocheck(dncp_trickle t, dncp_ep_i l, dncp_peer ne)
{
  t->num_sent++;
  t->last_sent = dncp_time(l->dncp);
  int maximum_size = ne ? 0 : l->conf.maximum_multicast_size;
  /* If Trickle has backed off, just send the short form, i.e. at most
   * just endpoint id + network state. */
  if (t->i != l->conf.trickle_imin)
    maximum_size = 4 + sizeof(dncp_t_ep_id_s) + DNCP_NI_LEN(l->dncp)
      + 4 + DNCP_HASH_LEN(l->dncp);
  dncp_ep_i_send_network_state(l, NULL, ne ? &ne->last_sa6: NULL,
                               maximum_size, false);
}

static void trickle_send(dncp_trickle t, dncp_ep_i l, dncp_peer ne)
{
  if (t->c < l->conf.trickle_k
      && (!l->conf.unicast_is_reliable_stream ||
          t->i == l->conf.trickle_imin))
    trickle_send_nocheck(t, l, ne);
  else
    t->num_skipped++;
  t->send_time = 0;
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
  struct tlv_attr *a;
  dncp_t_peer ne;
  dncp_node n2;

  if (!n)
    return;

  /* Stop the iteration if we're already added to current
   * generation. */
  if (n->in_nodes.version == n->dncp->nodes.version)
    return;

  /* If it was expired, we can ignore it and pretend it did not happen. */
  if (dncp_time(n->dncp) >= n->expiration_time)
    return;

  L_DEBUG("_prune_rec %s / %p", DNCP_NODE_REPR(n), n);

  /* Refresh the entry - we clearly did reach it. */
  vlist_add(&n->dncp->nodes, &n->in_nodes, n);
  _node_set_reachable(n, true);

  /* Look at it's neighbors. */
  /* Ignore if it's not _bidirectional_ neighbor. Unidirectional
   * ones lead to graph not settling down. */
  dncp_node_for_each_tlv_with_t_v(n, a, DNCP_T_PEER, false)
    if ((ne = dncp_tlv_peer(n->dncp, a)))
      if ((n2 = dncp_node_find_neigh_bidir(n, ne)))
        _prune_rec(n2);
}

static void dncp_prune(dncp o)
{
  hnetd_time_t now = dncp_time(o);
  int grace_interval = o->ext->conf.grace_interval;
  hnetd_time_t grace_after = now - grace_interval;

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
        {
          /* Determine when the origination time overflows */
          next_time = TMIN(next_time, n->expiration_time);
          continue;
        }
      if (n->last_reachable_prune < grace_after)
        continue;
      next_time = TMIN(next_time,
                       n->last_reachable_prune + grace_interval + 1);
      vlist_add(&o->nodes, &n->in_nodes, n);
      _node_set_reachable(n, false);
    }
  o->next_prune = next_time;
  vlist_flush(&o->nodes);
  o->last_prune = now;
}

#if L_LEVEL >= 8

#define SET_NEXT(_v, reason)                                    \
  do {                                                          \
    hnetd_time_t v = _v;                                        \
    if (v)                                                      \
      {                                                         \
        if (v < now)                                            \
          {                                                     \
            L_DEBUG("invalid value due to %s: %d in past",      \
                    reason, (int)(now-v));                      \
          }                                                     \
        else if (!next || next > v)                             \
          {                                                     \
            L_DEBUG("setting next to %ld due to %s",            \
                    (long int)(v-now), reason);                 \
            next = v;                                           \
          }                                                     \
      }                                                         \
  } while(0)

#else

#define SET_NEXT(v, reason) next = TMIN(next, v)

#endif /* L_LEVEL >= 8 */

static hnetd_time_t
_neighbor_interval(dncp o, dncp_t_peer neigh)
{
  dncp_node_id ni = dncp_tlv_get_node_id(o, neigh);
  dncp_node n = dncp_find_node_by_node_id(o, ni, false);

  if (!n)
    {
      L_DEBUG("using keepalive (default) for %s", DNCP_NI_REPR(o, ni));
      return DNCP_KEEPALIVE_INTERVAL(o);
    }

  struct tlv_attr *a;
  uint32_t value = DNCP_KEEPALIVE_INTERVAL(o);
  dncp_node_for_each_tlv_with_t_v(n, a, DNCP_T_KEEPALIVE_INTERVAL, false)
    {
      dncp_t_keepalive_interval ka = tlv_data(a);
      if (tlv_len(a) != sizeof(*ka))
        {
          L_DEBUG("invalid keepalive tlv length");
          continue;
        }
      if (ka->ep_id && ka->ep_id != neigh->peer_ep_id)
        continue;
      value = be32_to_cpu(ka->interval_in_ms) * HNETD_TIME_PER_SECOND / 1000;
      if (ka->ep_id)
        break;
    }
#if L_LEVEL >= 8
  L_DEBUG("using keepalive %d for %s", value, DNCP_NI_REPR(o, ni));
#endif /* L_LEVEL >= 8 */
  return value;
}

static hnetd_time_t handle_trickle_and_ka(dncp_trickle t,
                                          dncp_ep_i l,
                                          dncp_peer ne)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = dncp_time(l->dncp);

  if (l->published_keepalive_interval)
    {
      hnetd_time_t next_time =
        t->last_sent + l->published_keepalive_interval;
      if (next_time <= now)
        {
          L_DEBUG("sending keep-alive");
          trickle_send_nocheck(t, l, ne);
          /* Do not increment Trickle i, but set next t to i/2 .. i */
          trickle_set_i(t, l, t->i);
          next_time =
            t->last_sent + l->published_keepalive_interval;
        }
      SET_NEXT(next_time, "next keep-alive");
    }
  if (t->interval_end_time <= now)
    trickle_upgrade(t, l);
  else if (t->send_time && t->send_time <= now)
    trickle_send(t, l, ne);

  SET_NEXT(t->interval_end_time, "trickle_interval_end_time");
  SET_NEXT(t->send_time, "trickle_send_time");
  return next;
}

void dncp_ext_timeout(dncp o)
{
  hnetd_time_t next = 0;
  hnetd_time_t now = o->ext->cb.get_time(o->ext);
  dncp_ep ep;
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
        o->next_prune = o->ext->conf.minimum_prune_interval + o->last_prune;

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

  /* Recalculate network hash if necessary. */
  dncp_calculate_network_hash(o);

  dncp_for_each_enabled_ep(o, ep)
    {
      /* Update the 'active' link's published keepalive interval, if need be */
      dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);

      if (l->send_reply_at)
        {
          if (l->send_reply_at <= now)
            {
              dncp_reply_send(&l->reply);
              l->send_reply_at = 0;
            }
          else
            SET_NEXT(l->send_reply_at, "mc-reply");
        }

      ep_i_set_keepalive_interval(l, ep->keepalive_interval);

      if (ep->unicast_only)
        continue;

      hnetd_time_t next_time = handle_trickle_and_ka(&l->trickle, l, NULL);
      SET_NEXT(next_time, "l-trickle-ka");
    }

  /* Look at neighbors we should be worried about.. */
  /* vlist_for_each_element(&l->neighbors, n, in_neighbors) */
  dncp_t_peer ne;
  dncp_for_each_tlv_safe(o, t, t2)
    if ((ne = dncp_tlv_peer(o, &t->tlv)))
      {
        dncp_ep ep = dncp_find_ep_by_id(o, ne->ep_id);
        dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
        dncp_peer n = dncp_tlv_get_extra(t);
        hnetd_time_t interval = _neighbor_interval(o, ne);

        if (ep->unicast_only)
          {
            hnetd_time_t next_time = handle_trickle_and_ka(&n->trickle, l, n);
            SET_NEXT(next_time, "n-trickle-ka");
          }

        /* Zero interval is valid only on unicast stream connection
         * (=~TCP/TLS/..). In that case, we can ignore keepalive
         * handling here. */
        if (!interval && ep->unicast_is_reliable_stream)
          continue;

        hnetd_time_t next_time = n->last_contact
          + interval * o->ext->conf.keepalive_multiplier_percent / 100;

        /* No cause to do anything right now. */
        if (next_time > now)
          {
            SET_NEXT(next_time, "neighbor validity");
            continue;
          }

        /* Zap the neighbor */
#if L_LEVEL >= 7
        L_DEBUG("Neighbor %s gone on " DNCP_LINK_F " - nothing in %d ms",
                DNCP_NI_REPR(o, dncp_tlv_get_node_id(o, ne)),
                DNCP_LINK_D(l), (int) (now - n->last_contact));
#endif /* L_LEVEL >= 7 */
        dncp_remove_tlv(o, t);
        o->num_neighbor_dropped++;
      }

  if (next && !o->immediate_scheduled)
    {
      hnetd_time_t delta = next - o->ext->cb.get_time(o->ext);
      if (delta < 0)
        delta = 0;
      else if (delta > (1 << 16))
        delta = 1 << 16;
      o->ext->cb.schedule_timeout(o->ext, delta);
      L_DEBUG("next scheduled in %d", (int)delta);
    }

  /* Clear the cached time, it's most likely no longer valid. */
  o->now = 0;
}

void dncp_trickle_reset(dncp o)
{
  dncp_ep ep;

  /* This function does not care if Trickle is actually in per-peer or
   * per-link mode here; resetting the variables does nothing harmful
   * anyway. */

  /* Per-link */
  dncp_for_each_ep(o, ep)
    {
      dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);
      trickle_set_i(&l->trickle, l, ep->trickle_imin);
    }

  /* Per-peer */
  dncp_t_peer ne;
  dncp_tlv t;
  dncp_for_each_tlv(o, t)
    if ((ne = dncp_tlv_peer(o, &t->tlv)))
      {
        dncp_peer n = dncp_tlv_get_extra(t);
        dncp_ep ep = dncp_find_ep_by_id(o, ne->ep_id);
        dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);

        trickle_set_i(&n->trickle, l, ep->trickle_imin);
      }
}

void dncp_ext_ep_ready(dncp_ep ep, bool enabled)
{
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);

  L_DEBUG("dncp_ext_ep_ready %s %s %s", ep->ifname, enabled ? "+" : "-",
          !l->enabled == !enabled ? "(redundant)" : "");
  if (!l->enabled == !enabled)
    return;
  l->enabled = enabled;
  if (enabled)
    {
      trickle_set_i(&l->trickle, l, l->conf.trickle_imin);
      l->trickle.last_sent = dncp_time(l->dncp);
      dncp_schedule(l->dncp);
    }
  else
    {
      dncp o = l->dncp;
      dncp_tlv t, t2;
      dncp_t_peer ne;

      dncp_for_each_tlv_safe(o, t, t2)
        if ((ne = dncp_tlv_peer(o, &t->tlv)))
          if (ne->ep_id == l->ep_id)
            dncp_remove_tlv(o, t);

      /* kill TLV, if any */
      ep_i_set_keepalive_interval(l, DNCP_KEEPALIVE_INTERVAL(o));
    }
  dncp_notify_subscribers_ep_changed(ep, enabled ? DNCP_EVENT_ADD : DNCP_EVENT_REMOVE);
}
