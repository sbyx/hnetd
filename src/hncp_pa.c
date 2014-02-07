/*
 * $Id: hncp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:32:50 2013 mstenber
 * Last modified: Tue Feb  4 18:21:47 2014 mstenber
 * Edit time:     182 min
 *
 */

/* Glue code between hncp and pa. */

/* What does it do:

   - subscribes to HNCP and PA events

   - produces / consumes HNCP TLVs related to PA

   _Ideally_ this could actually use external hncp API only. In
   practise, though, I can't be bothered. So I don't.

   Strategy for dealing with different data types:

   - assigned prefixes received from hncp: pushed pa _every time_
   there's some local TLV change (this hopefully reflects also changes
   in neighbor relations and potential changes in interface names etc)
   (also handled on TLV change notification)

   - delegated prefixes received from hncp: just added/deleted
   dynamically based on TLV change notification

   - assigned prefixes from pa: added/deleted dynamically as hncp TLVs
   (no data that changes)

   - delegated prefixes received from pa: maintained locally (hncp_dp),
   and republished to hncp whenever local TLVs change (as otherwise
   timestamps which are per-node and not per-TLV would be wrong).
*/

#include "hncp_pa.h"
#include "hncp_i.h"
#include "prefix_utils.h"

typedef struct {
  struct vlist_node in_dps;

  /* Container for 'stuff' we want to stick in hncp. */
  struct prefix prefix;
  char ifname[IFNAMSIZ];
  hnetd_time_t valid_until;
  hnetd_time_t preferred_until;
  void *dhcpv6_data;
  size_t dhcpv6_len;

  /* What have already stuck in hncp :-) */
  struct tlv_attr *dp_tlv;
} hncp_dp_s, *hncp_dp;

struct hncp_glue_struct {
  /* Delegated prefix list (hncp_dp) */
  struct vlist_tree dps;

  /* HNCP notification subscriber structure */
  hncp_subscriber_s subscriber;

  /* What are we gluing together anyway? */
  hncp hncp;
  pa_t pa;
};

static int
compare_dps(const void *a, const void *b, void *ptr __unused)
{
  hncp_dp t1 = (hncp_dp) a, t2 = (hncp_dp) b;

  return prefix_cmp(&t1->prefix, &t2->prefix);
}

static void update_dp(struct vlist_tree *t,
                      struct vlist_node *node_new,
                      struct vlist_node *node_old)
{
  hncp_glue g = container_of(t, hncp_glue_s, dps);
  hncp_dp old = container_of(node_old, hncp_dp_s, in_dps);
  __unused hncp_dp new = container_of(node_new, hncp_dp_s, in_dps);

  /* nop? */
  if (old == new)
    return;

  /* We don't publish TLVs here; instead, we do it in the
   * republish callback for every currently valid TLV. So all we need
   * to do is just remove the old ones.
   */
  if (old)
    {
      if (old->dp_tlv)
        hncp_remove_tlv(g->hncp, old->dp_tlv);
      if (old->dhcpv6_data)
        free(old->dhcpv6_data);
      free(old);
    }
}

static hncp_dp _find_or_create_dp(hncp_glue g,
                                  const struct prefix *prefix,
                                  bool allow_add)
{
  hncp_dp dpt = container_of(prefix, hncp_dp_s, prefix);
  hncp_dp dp = vlist_find(&g->dps, dpt, dpt, in_dps);

  if (!dp && allow_add)
    {
      dp = calloc(1, sizeof(*dp));
      if (!dp)
        return NULL;
      dp->prefix = *prefix;
      prefix_canonical(&dp->prefix, &dp->prefix);

      vlist_add(&g->dps, &dp->in_dps, dp);
    }
  return dp;
}

static hncp_link _find_local_link(hncp_node onode, uint32_t olink_no)
{
  hncp o = onode->hncp;
  struct tlv_attr *a;
  int i;

  /* We're lazy and just compare published information; we _could_
   * of course also look at per-link and per-neighbor structures,
   * but this is simpler.. */
  hncp_node_for_each_tlv_i(o->own_node, a, i)
    if (tlv_id(a) == HNCP_T_NODE_DATA_NEIGHBOR)
      {
        hncp_t_node_data_neighbor nh = tlv_data(a);

        if (nh->neighbor_link_id != olink_no)
          continue;
        if (memcmp(&onode->node_identifier_hash,
                   &nh->neighbor_node_identifier_hash, HNCP_HASH_LEN) != 0)
          continue;
        /* Yay, it is this one. */
        return hncp_find_link_by_id(o, be32_to_cpu(nh->link_id));
      }
  return NULL;
}

static void _update_a_tlv(hncp_glue g, hncp_node n,
                          struct tlv_attr *tlv, bool add)
{
  hncp_t_assigned_prefix_header ah;
  int plen;
  struct prefix p;
  hncp_link l;

  if (!hncp_tlv_ap_valid(tlv))
    return;
  memset(&p, 0, sizeof(p));
  ah = tlv_data(tlv);
  p.plen = ah->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  memcpy(&p, tlv_data(tlv) + sizeof(*ah), plen);
  l = _find_local_link(n, ah->link_id);
  (void)pa_update_eap(g->pa, &p,
                      (struct pa_rid *)&n->node_identifier_hash,
                      l ? l->ifname : NULL,
                      !add);
  return;
}

static void _update_d_tlv(hncp_glue g, hncp_node n,
                          struct tlv_attr *tlv, bool add)
{
  hnetd_time_t preferred, valid;
  void *dhcpv6_data = NULL;
  size_t dhcpv6_len = 0;
  hncp_t_delegated_prefix_header dh;
  int plen;
  struct prefix p;

  if (!hncp_tlv_dp_valid(tlv))
    return;
  memset(&p, 0, sizeof(p));
  dh = tlv_data(tlv);
  p.plen = dh->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  memcpy(&p, tlv_data(tlv) + sizeof(*dh), plen);
  if (!add)
    {
      valid = 0;
      preferred = 0;
    }
  else
    {
      valid = n->origination_time + be32_to_cpu(dh->ms_valid_at_origination);
      preferred = n->origination_time + be32_to_cpu(dh->ms_preferred_at_origination);
    }
  /* XXX - handle dhcpv6 data */
  unsigned int flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;
  if (tlv_len(tlv) > flen)
    {
      struct tlv_attr *stlv;
      int left;
      void *start;

      /* Account for prefix padding */
      flen = ROUND_BYTES_TO_4BYTES(flen);

      start = tlv_data(tlv) + flen;
      left = tlv_len(tlv) - flen;
      L_DEBUG("considering what is at offset %lu->%u: %s",
              sizeof(hncp_t_delegated_prefix_header_s) + plen,
              flen,
              HEX_REPR(start, left));
      /* Now, flen is actually padded length of stuff, _before_ DHCPv6
       * options. */
      tlv_for_each_in_buf(stlv, start, left)
        {
          if (tlv_id(stlv) == HNCP_T_DHCPV6_OPTIONS)
            {
              dhcpv6_data = tlv_data(stlv);
              dhcpv6_len = tlv_len(stlv);
            }
          else
            {
              L_NOTICE("unknown delegated prefix option seen:%d", tlv_id(stlv));
            }
        }
    }

  (void)pa_update_edp(g->pa,
                      &p,
                      (struct pa_rid *)&n->node_identifier_hash,
                      NULL, /* TBD excluded - ignoring for now */
                      valid, preferred,
                      dhcpv6_data, dhcpv6_len);


}

static void _tlv_cb(hncp_subscriber s,
                    hncp_node n, struct tlv_attr *tlv, bool add)
{
  hncp_glue g = container_of(s, hncp_glue_s, subscriber);
  hncp o = g->hncp;

  L_NOTICE("_tlv_cb %s %s %s",
           add ? "add" : "remove",
           HNCP_NODE_REPR(n),
           TLV_REPR(tlv));

  /* Ignore our own TLV changes (otherwise bad things might happen) */
  if (hncp_node_is_self(n))
    {
      return;
    }

  switch (tlv_id(tlv))
    {
    case HNCP_T_DELEGATED_PREFIX:
      _update_d_tlv(g, n, tlv, add);
      break;
    case HNCP_T_ASSIGNED_PREFIX:
      _update_a_tlv(g, n, tlv, add);
      break;
    case HNCP_T_NODE_DATA_NEIGHBOR:
      /* Someone else may be our neighbor; set tlvs_dirty to force
       * republish attempt to recalculate next hops to assigned
       * prefixes. */
      o->tlvs_dirty = true;
      hncp_schedule(o);
      break;
    default:
      return;
    }

}

static void _republish_cb(hncp_subscriber s)
{
  hncp_glue g = container_of(s, hncp_glue_s, subscriber);
  hncp o = g->hncp;
  hnetd_time_t now = hncp_time(o);
  hncp_dp dp;
  int len, flen, plen;
  struct tlv_attr *t, *st;
  hncp_t_delegated_prefix_header dph;
  hncp_node n;
  struct tlv_attr *a;
  int i;

  /* This is very brute force. Oh well. */

  /* As we don't keep track of interface changes that actively, nor of
     neighbor changes, we push _every_ assigned prefix at pa API every
     time this callback is called. */
  hncp_for_each_node(o, n)
    {
      if (n == o->own_node)
        continue;
      hncp_node_for_each_tlv_i(n, a, i)
        {
          if (tlv_id(a) == HNCP_T_ASSIGNED_PREFIX)
            _update_a_tlv(g, n, a, true);
        }
    }

  vlist_for_each_element(&g->dps, dp, in_dps)
    {
      if (dp->dp_tlv)
        hncp_remove_tlv(o, dp->dp_tlv);

      /* Determine how much space we need for TLV. */
      plen = ROUND_BITS_TO_BYTES(dp->prefix.plen);
      flen = TLV_SIZE + sizeof(hncp_t_delegated_prefix_header_s) + plen;
      len = ROUND_BYTES_TO_4BYTES(flen);
      if (dp->dhcpv6_len)
        len += TLV_SIZE + ROUND_BYTES_TO_4BYTES(dp->dhcpv6_len);
      t = calloc(1, len);
      if (t)
        {
          tlv_init(t, HNCP_T_DELEGATED_PREFIX, flen);
          dph = tlv_data(t);
          if (dp->valid_until >= now)
            dph->ms_valid_at_origination =
              cpu_to_be32(dp->valid_until - now);
          else
            dph->ms_valid_at_origination = 0;
          if (dp->preferred_until >= now)
            dph->ms_preferred_at_origination =
              cpu_to_be32(dp->preferred_until - now);
          else
            dph->ms_preferred_at_origination = 0;
          dph->prefix_length_bits = dp->prefix.plen;
          dph++;
          memcpy(dph, &dp->prefix, plen);
          if (dp->dhcpv6_len)
            {
              st = tlv_next(t);
              tlv_init(st, HNCP_T_DHCPV6_OPTIONS, TLV_SIZE + dp->dhcpv6_len);
              memcpy(tlv_data(st), dp->dhcpv6_data, dp->dhcpv6_len);
              tlv_init(t, HNCP_T_DELEGATED_PREFIX, len);
            }
          dp->dp_tlv = hncp_add_tlv(o, t);
          free(t);
        }
    }
}

#if 0
/* Not sure if we have anything node specific we care about? */
static void _node_cb(hncp_subscriber s, hncp_node n, bool add)
{
  hncp_glue g = container_of(s, hncp_glue_s, subscriber);

}
#endif /* 0 */

static void _updated_lap(const struct prefix *prefix, const char *ifname,
                         int to_delete, void *priv)
{
  hncp_glue g = priv;
  hncp o = g->hncp;

  return hncp_tlv_ap_update(o, prefix, ifname, false, 0, !to_delete);
}

static void _updated_ldp(const struct prefix *prefix,
                         const struct prefix *excluded __unused,
                         const char *dp_ifname,
                         hnetd_time_t valid_until, hnetd_time_t preferred_until,
                         const void *dhcpv6_data, size_t dhcpv6_len,
                         void *priv)
{
  hncp_glue g = priv;
  hncp o = g->hncp;
  bool add = valid_until != 0;
  hncp_dp dp = _find_or_create_dp(g, prefix, add);

  /* Nothing to update, and it was delete. Do nothing. */
  if (!dp)
    return;

  /* Delete, and we existed? Bye bye. */
  if (!add)
    {
      vlist_delete(&g->dps, &dp->in_dps);
      return;
    }

  /* Add or update. So update the fields. */
  if (dp_ifname)
    strcpy(dp->ifname, dp_ifname);
  else
    dp->ifname[0] = 0;
  dp->valid_until = valid_until;
  dp->preferred_until = preferred_until;
  if (dp->dhcpv6_data)
    {
      free(dp->dhcpv6_data);
      dp->dhcpv6_data = NULL;
    }
  if (dhcpv6_data)
    {
      dp->dhcpv6_data = malloc(dhcpv6_len);
      if (!dp->dhcpv6_data)
        {
          dp->dhcpv6_len = 0;
          L_ERR("oom in dhcpv6_data malloc %d", (int)dhcpv6_len);
        }
      else
        {
          dp->dhcpv6_len = dhcpv6_len;
          memcpy(dp->dhcpv6_data, dhcpv6_data, dhcpv6_len);
        }
    }

  /* Force republish (the actual TLV will be actually refreshed in the
   * subscriber callback) */
  o->tlvs_dirty = true;
  hncp_schedule(o);
}


hncp_glue hncp_pa_glue_create(hncp o, pa_t pa)
{
  struct pa_rid *rid = (struct pa_rid *)&o->own_node->node_identifier_hash;
  hncp_glue g = calloc(1, sizeof(*g));
  struct pa_flood_callbacks pa_cbs = {
    .priv = g,
    .updated_lap = _updated_lap,
    .updated_ldp = _updated_ldp,
  };
  if (!g)
    return false;

  vlist_init(&g->dps, compare_dps, update_dp);
  g->subscriber.tlv_change_callback = _tlv_cb;
  /* g->subscriber.node_change_callback = _node_cb; */
  g->subscriber.republish_callback = _republish_cb;
  g->pa = pa;
  g->hncp = o;

  /* Set the rid */
  pa_set_rid(pa, rid);

  /* And let the floodgates open. pa SHOULD NOT call anything yet, as
   * it isn't started. hncp, on the other hand, most likely will. */
  pa_flood_subscribe(pa, &pa_cbs);
  hncp_subscribe(o, &g->subscriber);

  return g;
}

void hncp_pa_glue_destroy(hncp_glue g)
{
  vlist_flush_all(&g->dps);
  free(g);
}
