/*
 * $Id: hcp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:32:50 2013 mstenber
 * Last modified: Fri Dec  6 22:16:55 2013 mstenber
 * Edit time:     164 min
 *
 */

/* Glue code between hcp and pa. */

/* What does it do:

   - subscribes to HCP and PA events

   - produces / consumes HCP TLVs related to PA

   _Ideally_ this could actually use external hcp API only. In
   practise, though, I can't be bothered. So I don't.

   Strategy for dealing with different data types:

   - assigned prefixes received from hcp: pushed pa _every time_
   there's some local TLV change (this hopefully reflects also changes
   in neighbor relations and potential changes in interface names etc)
   (also handled on TLV change notification)

   - delegated prefixes received from hcp: just added/deleted
   dynamically based on TLV change notification

   - assigned prefixes from pa: added/deleted dynamically as hcp TLVs
     (no data that changes)

   - delegated prefixes received from pa: maintained locally (hcp_dp),
     and republished to hcp whenever local TLVs change (as otherwise
     timestamps which are per-node and not per-TLV would be wrong).
*/

#include "hcp_pa.h"
#include "hcp_i.h"

typedef struct {
  struct vlist_node in_dps;

  /* Container for 'stuff' we want to stick in hcp. */
  struct prefix prefix;
  char ifname[IFNAMSIZ];
  hnetd_time_t valid_until;
  hnetd_time_t preferred_until;
  void *dhcpv6_data;
  size_t dhcpv6_len;

  /* What have already stuck in hcp :-) */
  struct tlv_attr *dp_tlv;
} hcp_dp_s, *hcp_dp;

struct hcp_glue_struct {
  /* Delegated prefix list (hcp_dp) */
  struct vlist_tree dps;

  /* HCP notification subscriber structure */
  hcp_subscriber_s subscriber;

  /* What are we gluing together anyway? */
  hcp hcp;
  pa_t pa;
};

static int
compare_dps(const void *a, const void *b, void *ptr __unused)
{
  hcp_dp t1 = (hcp_dp) a, t2 = (hcp_dp) b;

  return prefix_cmp(&t1->prefix, &t2->prefix);
}

static void update_dp(struct vlist_tree *t,
                       struct vlist_node *node_new,
                       struct vlist_node *node_old)
{
  hcp_glue g = container_of(t, hcp_glue_s, dps);
  hcp_dp old = container_of(node_old, hcp_dp_s, in_dps);
  __unused hcp_dp new = container_of(node_new, hcp_dp_s, in_dps);

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
        hcp_remove_tlv(g->hcp, old->dp_tlv);
      free(old);
    }
}

static hcp_dp _find_or_create_dp(hcp_glue g,
                                 const struct prefix *prefix,
                                 bool allow_add)
{
  hcp_dp dpt = container_of(prefix, hcp_dp_s, prefix);
  hcp_dp dp = vlist_find(&g->dps, dpt, dpt, in_dps);

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

static hcp_link _find_local_link(hcp_node onode, uint32_t olink_no)
{
  hcp o = onode->hcp;
  struct tlv_attr *a;
  int i;

  /* We're lazy and just compare published information; we _could_
   * of course also look at per-link and per-neighbor structures,
   * but this is simpler.. */
  hcp_node_for_each_tlv_i(o->own_node, a, i)
    if (tlv_id(a) == HCP_T_NODE_DATA_NEIGHBOR)
      {
        hcp_t_node_data_neighbor nh = tlv_data(a);

        if (nh->neighbor_link_id != olink_no)
          continue;
        if (memcmp(&onode->node_identifier_hash,
                   &nh->neighbor_node_identifier_hash, HCP_HASH_LEN) != 0)
          continue;
        /* Yay, it is this one. */
        return hcp_find_link_by_id(o, be32_to_cpu(nh->link_id));
      }
  return NULL;
}

static void _update_a_tlv(hcp_glue g, hcp_node n,
                           struct tlv_attr *tlv, bool add)
{
  hcp_t_assigned_prefix_header ah;
  int plen;
  struct prefix p;
  hcp_link l;

  if (tlv_len(tlv) < sizeof(*ah))
    return;
  memset(&p, 0, sizeof(p));
  ah = tlv_data(tlv);
  p.plen = ah->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  if (tlv_len(tlv) < (sizeof(*ah) + plen))
    return;
  memcpy(&p, tlv_data(tlv) + sizeof(*ah), plen);
  l = _find_local_link(n, ah->link_id);
  (void)pa_update_eap(g->pa, &p,
                      (struct pa_rid *)&n->node_identifier_hash,
                      l ? l->ifname : NULL,
                      add);
  return;
}

static void _update_d_tlv(hcp_glue g, hcp_node n,
                          struct tlv_attr *tlv, bool add)
{
  hnetd_time_t preferred, valid;
  void *dhcpv6_data = NULL;
  size_t dhcpv6_len = 0;
  hcp_t_delegated_prefix_header dh;
  int plen;
  struct prefix p;

  if (tlv_len(tlv) < sizeof(*dh))
    return;
  memset(&p, 0, sizeof(p));
  dh = tlv_data(tlv);
  p.plen = dh->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  if (tlv_len(tlv) < (sizeof(*dh) + plen))
    return;
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
  unsigned int flen = sizeof(hcp_t_delegated_prefix_header_s) + plen;
  if (tlv_len(tlv) > flen)
    {
      struct tlv_attr *stlv;
      int left;
      void *start;

      /* Account for prefix padding */
      flen = ROUND_BYTES_TO_4BYTES(flen);

      start = tlv_data(tlv) + flen;
      left = tlv_len(tlv) - flen;
      L_DEBUG("considering what is at offset %d->%d: %s",
              sizeof(hcp_t_delegated_prefix_header_s) + plen,
              flen,
              HEX_REPR(start, left));
      /* Now, flen is actually padded length of stuff, _before_ DHCPv6
       * options. */
      tlv_for_each_in_buf(stlv, start, left)
        {
          if (tlv_id(stlv) == HCP_T_DHCPV6_OPTIONS)
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

static void _tlv_cb(hcp_subscriber s,
                    hcp_node n, struct tlv_attr *tlv, bool add)
{
  hcp_glue g = container_of(s, hcp_glue_s, subscriber);

  L_NOTICE("_tlv_cb %s %s %s",
           add ? "add" : "remove",
           HCP_NODE_REPR(n),
           TLV_REPR(tlv));

  /* Ignore our own TLV changes (otherwise bad things might happen) */
  if (hcp_node_is_self(n))
    return;

  switch (tlv_id(tlv))
    {
    case HCP_T_DELEGATED_PREFIX:
      _update_d_tlv(g, n, tlv, add);
      break;
    case HCP_T_ASSIGNED_PREFIX:
      _update_a_tlv(g, n, tlv, add);
      break;
    default:
      return;
    }

}

static void _republish_cb(hcp_subscriber s)
{
  hcp_glue g = container_of(s, hcp_glue_s, subscriber);
  hcp o = g->hcp;
  hnetd_time_t now = hcp_time(o);
  hcp_dp dp;
  int len, flen, plen;
  struct tlv_attr *t, *st;
  hcp_t_delegated_prefix_header dph;
  hcp_node n;
  struct tlv_attr *a;
  int i;

  /* This is very brute force. Oh well. */

  /* As we don't keep track of interface changes that actively, nor of
     neighbor changes, we push _every_ assigned prefix at pa API every
     time this callback is called. */
  hcp_for_each_node(o, n)
    {
      if (n == o->own_node)
        continue;
      hcp_node_for_each_tlv_i(n, a, i)
        {
          if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
            _update_a_tlv(g, n, a, true);
        }
    }

  vlist_for_each_element(&g->dps, dp, in_dps)
    {
      if (dp->dp_tlv)
        hcp_remove_tlv(o, dp->dp_tlv);

      /* Determine how much space we need for TLV. */
      plen = ROUND_BITS_TO_BYTES(dp->prefix.plen);
      flen = TLV_SIZE + sizeof(hcp_t_delegated_prefix_header_s) + plen;
      len = ROUND_BYTES_TO_4BYTES(flen);
      if (dp->dhcpv6_len)
        len += TLV_SIZE + ROUND_BYTES_TO_4BYTES(dp->dhcpv6_len);
      t = calloc(1, len);
      if (t)
        {
          tlv_init(t, HCP_T_DELEGATED_PREFIX, flen);
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
              tlv_init(st, HCP_T_DHCPV6_OPTIONS, TLV_SIZE + dp->dhcpv6_len);
              memcpy(tlv_data(st), dp->dhcpv6_data, dp->dhcpv6_len);
              tlv_init(t, HCP_T_DELEGATED_PREFIX, len);
            }
          dp->dp_tlv = hcp_add_tlv(o, t);
          free(t);
        }
    }
}

#if 0
/* Not sure if we have anything node specific we care about? */
static void _node_cb(hcp_subscriber s, hcp_node n, bool add)
{
  hcp_glue g = container_of(s, hcp_glue_s, subscriber);

}
#endif /* 0 */

static void _updated_lap(const struct prefix *prefix, const char *ifname,
                         int to_delete, void *priv)
{
  struct prefix p;
  hcp_glue g = priv;
  hcp o = g->hcp;
  int mlen = TLV_SIZE + sizeof(hcp_t_assigned_prefix_header_s) + 16 + 3;
  unsigned char buf[mlen];
  struct tlv_attr *a = (struct tlv_attr *) buf;
  int plen = ROUND_BITS_TO_BYTES(prefix->plen);
  int flen = TLV_SIZE + sizeof(hcp_t_delegated_prefix_header_s) + plen;
  hcp_t_assigned_prefix_header ah;
  hcp_link l;

  memset(buf, 0, mlen);
  p = *prefix;
  prefix_canonical(&p, &p);
  /* XXX - what if links renumber? let's hope they don't */
  tlv_init(a, HCP_T_ASSIGNED_PREFIX, flen);
  ah = tlv_data(a);
  l = hcp_find_link_by_name(o, ifname, false);
  if (l)
    ah->link_id = cpu_to_be32(l->iid);
  ah->prefix_length_bits = p.plen;
  ah++;
  memcpy(ah, &p, plen);

  if (to_delete)
    hcp_remove_tlv(o, (struct tlv_attr *)buf);
  else
    hcp_add_tlv(o, (struct tlv_attr *)buf);
}

static void _updated_ldp(const struct prefix *prefix,
                         const struct prefix *excluded __unused,
                         const char *dp_ifname,
                         hnetd_time_t valid_until, hnetd_time_t preferred_until,
                         const void *dhcpv6_data, size_t dhcpv6_len,
                         void *priv)
{
  hcp_glue g = priv;
  hcp o = g->hcp;
  bool add = valid_until != 0;
  hcp_dp dp = _find_or_create_dp(g, prefix, add);

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
  hcp_schedule(o);
}


hcp_glue hcp_pa_glue_create(hcp o, pa_t pa)
{
  struct pa_rid *rid = (struct pa_rid *)&o->own_node->node_identifier_hash;
  hcp_glue g = calloc(1, sizeof(*g));
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
  g->hcp = o;

  /* Set the rid */
  pa_set_rid(pa, rid);

  /* And let the floodgates open. pa SHOULD NOT call anything yet, as
   * it isn't started. hcp, on the other hand, most likely will. */
  pa_flood_subscribe(pa, &pa_cbs);
  hcp_subscribe(o, &g->subscriber);

  return g;
}

void hcp_pa_glue_destroy(hcp_glue g)
{
  vlist_flush_all(&g->dps);
  free(g);
}
