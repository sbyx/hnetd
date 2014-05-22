/*
 * $Id: hncp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:32:50 2013 mstenber
 * Last modified: Thu May 22 14:06:20 2014 mstenber
 * Edit time:     404 min
 *
 */

/* Glue code between hncp and pa. */

/* What does it do:

   - subscribes to HNCP and PA events

   - produces / consumes HNCP TLVs related to PA

   _Ideally_ this could actually use external hncp API only. In
   practise, though, I can't be bothered. So I don't.

   Strategy for dealing with different data types:

   - assigned prefixes

    - from hncp: pushed pa when we get tlv callback from HNCP

    - from pa: added/deleted dynamically as hncp TLVs (no data that
      changes)

   - delegated prefixes

    - from hncp: pushed pa when we get tlv callback from HNCP

    - from pa: maintained locally (hncp_dp), and republished to hncp
    whenever local TLVs change (as otherwise timestamps which are
    per-node and not per-TLV would be wrong).

   As fun additional piece of complexity, as of -00 draft, the
   delegated prefixes are inside external connection TLV.
*/

#include "hncp_pa.h"
#include "hncp_i.h"
#include "prefix_utils.h"
#include "dhcpv6.h"
#include "iface.h"
#include "pa_data.h"
#include "dhcp.h"
#include "dns_util.h"

#define HNCP_PA_EDP_DELAYED_DELETE_MS 50
#define HNCP_PA_AP_LINK_UPDATE_MS 50

typedef struct {
  struct vlist_node in_dps;

  /* Container for 'stuff' we want to stick in hncp. */
  struct prefix prefix;
  char ifname[IFNAMSIZ];
  hnetd_time_t valid_until;
  hnetd_time_t preferred_until;
  void *dhcpv6_data;
  size_t dhcpv6_len;
} hncp_dp_s, *hncp_dp;

struct hncp_glue_struct {
  /* Delegated prefix list (hncp_dp) */
  struct vlist_tree dps;

  /* HNCP notification subscriber structure */
  hncp_subscriber_s subscriber;

  /* Timeout for updating assigned prefixes links */
  struct uloop_timeout ap_if_update_timeout;

  /* What are we gluing together anyway? */
  hncp hncp;
  struct pa_data *pa_data;
  struct pa_data_user data_user;
};

static void _refresh_ec(hncp_glue g, bool publish);

static int compare_dps(const void *a, const void *b, void *ptr __unused)
{
  hncp_dp t1 = (hncp_dp) a, t2 = (hncp_dp) b;

  return prefix_cmp(&t1->prefix, &t2->prefix);
}

static void update_dp(struct vlist_tree *t __unused,
                      struct vlist_node *node_new,
                      struct vlist_node *node_old)
{
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
  hncp_t_node_data_neighbor nh;

  /* We're lazy and just compare published information; we _could_
   * of course also look at per-link and per-neighbor structures,
   * but this is simpler.. */
  hncp_node_for_each_tlv_i(o->own_node, a)
    if ((nh = hncp_tlv_neighbor(a)))
      {
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

  if (!(ah = hncp_tlv_ap(tlv)))
    return;
  memset(&p, 0, sizeof(p));
  p.plen = ah->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  memcpy(&p, ah->prefix_data, plen);
  l = _find_local_link(n, ah->link_id);

  struct pa_ap *ap = pa_ap_get(g->pa_data, &p, (struct pa_rid *)&n->node_identifier_hash, add);
  if (!ap)
    return;

  struct pa_iface *iface = NULL;
  if (l)
    iface = pa_iface_get(g->pa_data, l->ifname, add);

  if (!add) {
    pa_ap_todelete(ap);
  } else {
    pa_ap_set_iface(ap, iface);
    pa_ap_set_priority(ap, HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(ah->flags));
    pa_ap_set_authoritative(ap, ah->flags & HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE);
  }

  pa_ap_notify(g->pa_data, ap);
  return;
}

static void _update_pa_eaa(struct pa_data *data, const struct in6_addr *addr,
		const struct pa_rid *rid, bool to_delete)
{
	/* This is a function to update external address assignments */
	struct pa_eaa *eaa = pa_eaa_get(data, addr, rid, !to_delete);
	if (!eaa)
		return;

	if (to_delete)
		pa_aa_todelete(&eaa->aa);

	pa_aa_notify(data, &eaa->aa);
}

hnetd_time_t _remote_rel_to_local_abs(hnetd_time_t base, uint32_t netvalue)
{
  if (netvalue == UINT32_MAX)
    return HNETD_TIME_MAX;
  return base + be32_to_cpu(netvalue);
}

uint32_t _local_abs_to_remote_rel(hnetd_time_t now, hnetd_time_t v)
{
  if (v == HNETD_TIME_MAX)
    return cpu_to_be32(UINT32_MAX);
  if (now > v)
    return 0;
  hnetd_time_t delta = v - now;
  /* Convert to infinite if it would overflow too. */
  if (delta >= UINT32_MAX)
    return cpu_to_be32(UINT32_MAX);
  return cpu_to_be32(delta);
}

static void _pa_dp_delayed_delete(struct uloop_timeout *to)
{
	struct pa_edp *edp = container_of(to, struct pa_edp, timeout);
	pa_dp_todelete(&edp->dp);
	pa_dp_notify(edp->data, &edp->dp);
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

  if (!(dh = hncp_tlv_dp(tlv)))
    return;
  memset(&p, 0, sizeof(p));
  p.plen = dh->prefix_length_bits;
  plen = ROUND_BITS_TO_BYTES(p.plen);
  memcpy(&p, dh->prefix_data, plen);
  if (!add)
    {
      valid = 0;
      preferred = 0;
    }
  else
    {
      valid = _remote_rel_to_local_abs(n->origination_time,
                                       dh->ms_valid_at_origination);
      preferred = _remote_rel_to_local_abs(n->origination_time,
                                           dh->ms_preferred_at_origination);
    }
  unsigned int flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;
  struct tlv_attr *stlv;
  int left;
  void *start;

  /* Account for prefix padding */
  flen = ROUND_BYTES_TO_4BYTES(flen);

  start = tlv_data(tlv) + flen;
  left = tlv_len(tlv) - flen;
  L_DEBUG("considering what is at offset %lu->%u: %s",
          (unsigned long)sizeof(hncp_t_delegated_prefix_header_s) + plen,
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

  struct pa_edp *edp = pa_edp_get(g->pa_data, &p, (struct pa_rid *)&n->node_identifier_hash, !!valid);
  if(!edp)
	  return;

  if(valid) {
	  pa_dp_set_lifetime(&edp->dp, preferred, valid);
	  pa_dp_set_dhcp(&edp->dp, dhcpv6_data, dhcpv6_len);
	  if (edp->timeout.pending)
		  uloop_timeout_cancel(&edp->timeout);
  } else if (!edp->timeout.pending) {
	  edp->timeout.cb = _pa_dp_delayed_delete;
	  edp->data = g->pa_data;
	  uloop_timeout_set(&edp->timeout, HNCP_PA_EDP_DELAYED_DELETE_MS);
  }

  pa_dp_notify(g->pa_data, &edp->dp);
  return;
}

static void _update_a_local_links(hncp_glue g)
{
  hncp o = g->hncp;
  hncp_node n;
  struct tlv_attr *a;
  hncp_t_assigned_prefix_header ah;
  hncp_link l;
  struct prefix p;

  L_DEBUG("_update_a_local_links");
  hncp_for_each_node(o, n)
    {
      hncp_node_for_each_tlv(n, a)
        {
          if (!(ah = hncp_tlv_ap(a)))
            continue;
          memset(&p, 0, sizeof(p));
          p.plen = ah->prefix_length_bits;
          int plen = ROUND_BITS_TO_BYTES(p.plen);
          memcpy(&p, ah->prefix_data, plen);
          l = _find_local_link(n, ah->link_id);
          struct pa_ap *ap = pa_ap_get(g->pa_data, &p, (struct pa_rid *)&n->node_identifier_hash, false);
          if (!ap)
            {
              L_DEBUG(" unable to find AP for %s", PREFIX_REPR(&p));
              continue;
            }
          struct pa_iface *iface = NULL;
          if (l)
            iface = pa_iface_get(g->pa_data, l->ifname, true);
          pa_ap_set_iface(ap, iface);
          L_DEBUG(" updated " PA_AP_L, PA_AP_LA(ap));
          pa_ap_notify(g->pa_data, ap);
        }
    }
}

static void _tlv_cb(hncp_subscriber s,
                    hncp_node n, struct tlv_attr *tlv, bool add)
{
  hncp_glue g = container_of(s, hncp_glue_s, subscriber);

  L_NOTICE("[pa]_tlv_cb %s %s %s",
           add ? "add" : "remove",
           n == g->hncp->own_node ? "local" : HNCP_NODE_REPR(n),
           TLV_REPR(tlv));

  /* Ignore our own TLV changes (otherwise bad things might happen) */
  if (hncp_node_is_self(n))
    {
      return;
    }

  switch (tlv_id(tlv))
    {
    case HNCP_T_EXTERNAL_CONNECTION:
      {
        struct tlv_attr *a;
        int c = 0;
        tlv_for_each_attr(a, tlv)
        {
          if (tlv_id(a) == HNCP_T_DELEGATED_PREFIX)
            _update_d_tlv(g, n, a, add);
          else {
            L_INFO("unsupported external connection tlv:#%d", tlv_id(a));
          }
          c++;
        }
        if (!c)
          L_INFO("empty external connection TLV");

        /* Don't republish here, only updated outgoing dhcp options */
        _refresh_ec(g, false);

      }
      break;
    case HNCP_T_ASSIGNED_PREFIX:
      _update_a_tlv(g, n, tlv, add);
      break;
    case HNCP_T_ROUTER_ADDRESS:
      {
        hncp_t_router_address ra = hncp_tlv_router_address(tlv);
        if (ra)
        {
          _update_pa_eaa(g->pa_data, &ra->address,
                         (struct pa_rid *)&n->node_identifier_hash,
                         !add);
        }
      else
        {
          L_INFO("invalid sized router address tlv:%d bytes", tlv_len(tlv));
        }
      }
      break;
    case HNCP_T_NODE_DATA_NEIGHBOR:
      {
        /* Should do it every now and then even if already busy. So if
         * already queued, ignore this extra change. */
        if (!g->ap_if_update_timeout.pending)
          uloop_timeout_set(&g->ap_if_update_timeout, HNCP_PA_AP_LINK_UPDATE_MS);
      }
      break;
    default:
      return;
    }

}

void hncp_pa_set_dhcpv6_data_in_dirty(hncp_glue g)
{
  hncp o = g->hncp;

  o->tlvs_dirty = true;
  hncp_schedule(o);
}

#define APPEND_BUF(buf, len, ibuf, ilen)        \
do                                              \
  {                                             \
  if (ilen)                                     \
    {                                           \
      buf = realloc(buf, len + ilen);           \
      if (!buf)                                 \
        {                                       \
          L_ERR("oom gathering buf");           \
          goto oom;                             \
        }                                       \
      memcpy(buf + len, ibuf, ilen);            \
      len += ilen;                              \
    }                                           \
 } while(0)


static void _refresh_ec(hncp_glue g, bool publish)
{
  hncp o = g->hncp;
  hnetd_time_t now = hncp_time(o);
  hncp_dp dp, dp2;
  int flen, plen;
  struct tlv_attr *st;
  hncp_t_delegated_prefix_header dph;
  struct tlv_buf tb;
  char *dhcpv6_options = NULL, *dhcp_options = NULL;
  int dhcpv6_options_len = 0, dhcp_options_len = 0;

  if (publish)
    hncp_remove_tlvs_by_type(o, HNCP_T_EXTERNAL_CONNECTION);

  /* This is very brute force. Oh well. (O(N^2) to # of delegated
     prefixes. Most likely it's small enough not to matter.)*/
  vlist_for_each_element(&g->dps, dp2, in_dps)
    {
      bool done = false;
      vlist_for_each_element(&g->dps, dp, in_dps)
        {
          if (dp == dp2)
            break;
          if (strcmp(dp->ifname, dp2->ifname) == 0)
            {
              done = true;
              break;
            }
        }
      if (done)
        continue;
      memset(&tb, 0, sizeof(tb));
      tlv_buf_init(&tb, HNCP_T_EXTERNAL_CONNECTION);
      vlist_for_each_element(&g->dps, dp, in_dps)
        {
          void *cookie;
          /* Different IF -> not interested */
          if (strcmp(dp->ifname, dp2->ifname))
            continue;
          /* Determine how much space we need for TLV. */
          plen = ROUND_BITS_TO_BYTES(dp->prefix.plen);
          flen = sizeof(hncp_t_delegated_prefix_header_s) + plen;
          cookie = tlv_nest_start(&tb, HNCP_T_DELEGATED_PREFIX, flen);

          dph = tlv_data(tb.head);
          dph->ms_valid_at_origination = _local_abs_to_remote_rel(now, dp->valid_until);
          dph->ms_preferred_at_origination = _local_abs_to_remote_rel(now, dp->preferred_until);
          dph->prefix_length_bits = dp->prefix.plen;
          dph++;
          memcpy(dph, &dp->prefix, plen);
          if (dp->dhcpv6_len)
            {
              st = tlv_new(&tb, HNCP_T_DHCPV6_OPTIONS, dp->dhcpv6_len);
              memcpy(tlv_data(st), dp->dhcpv6_data, dp->dhcpv6_len);
            }
          tlv_nest_end(&tb, cookie);
        }
      tlv_sort(tlv_data(tb.head), tlv_len(tb.head));
      struct iface *ifo = iface_get(dp2->ifname);
      if (ifo && ifo->dhcpv6_data_in && ifo->dhcpv6_len_in)
        {
          st = tlv_new(&tb, HNCP_T_DHCPV6_OPTIONS, ifo->dhcpv6_len_in);
          memcpy(tlv_data(st), ifo->dhcpv6_data_in, ifo->dhcpv6_len_in);
          APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
                     tlv_data(st), tlv_len(st));
        }
      if (ifo && ifo->dhcp_data_in && ifo->dhcp_len_in)
        {
          st = tlv_new(&tb, HNCP_T_DHCP_OPTIONS, ifo->dhcp_len_in);
          memcpy(tlv_data(st), ifo->dhcp_data_in, ifo->dhcp_len_in);
          APPEND_BUF(dhcp_options, dhcp_options_len,
                     tlv_data(st), tlv_len(st));
        }
      if (publish)
	hncp_add_tlv(o, tb.head);
      tlv_buf_free(&tb);
    }
  hncp_node n;
  struct tlv_attr *a, *a2;

  /* add the SD domain always to search path (if present) */
  if (o->domain[0])
    {
      /* domain is _ascii_ representation of domain (same as what
       * DHCPv4 expects). DHCPv6 needs ll-escaped string, though. */
      uint8_t ll[DNS_MAX_LL_LEN];
      int len;
      len = escaped2ll(o->domain, ll, sizeof(ll));
      if (len > 0)
        {
          uint16_t fake_header[2];
          uint8_t fake4_header[2];

          fake_header[0] = cpu_to_be16(DHCPV6_OPT_DNS_DOMAIN);
          fake_header[1] = cpu_to_be16(len);
          APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
                     &fake_header[0], 4);
          APPEND_BUF(dhcpv6_options, dhcpv6_options_len, ll, len);

          fake4_header[0] = DHCPV4_OPT_DOMAIN;
          fake4_header[1] = strlen(o->domain);
          APPEND_BUF(dhcp_options, dhcp_options_len, fake4_header, 2);
          APPEND_BUF(dhcp_options, dhcp_options_len, o->domain, fake4_header[1]);
        }
    }

  hncp_for_each_node(o, n)
    {
      hncp_node_for_each_tlv_i(n, a)
        switch (tlv_id(a))
          {
          case HNCP_T_EXTERNAL_CONNECTION:
            if (n != o->own_node)
              {
                tlv_for_each_attr(a2, a)
                  if (tlv_id(a2) == HNCP_T_DHCPV6_OPTIONS)
                    {
                      APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
                                 tlv_data(a2), tlv_len(a2));
                    }
                  else if (tlv_id(a2) == HNCP_T_DHCP_OPTIONS)
                    {
                      APPEND_BUF(dhcp_options, dhcp_options_len,
                                 tlv_data(a2), tlv_len(a2));
                    }
              }
            break;
          case HNCP_T_DNS_DELEGATED_ZONE:
            {
              hncp_t_dns_delegated_zone ddz = tlv_data(a);
              if (ddz->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH)
                {
                  char domainbuf[256];
                  uint16_t fake_header[2];
                  uint8_t fake4_header[2];
                  uint8_t *data = tlv_data(a);
                  int l = tlv_len(a) - sizeof(*ddz);

                  fake_header[0] = cpu_to_be16(DHCPV6_OPT_DNS_DOMAIN);
                  fake_header[1] = cpu_to_be16(l);
                  APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
                             &fake_header[0], 4);
                  APPEND_BUF(dhcpv6_options, dhcpv6_options_len,
                             ddz->ll, l);

                  if (ll2escaped(data, l, domainbuf, sizeof(domainbuf)) >= 0) {
                    fake4_header[0] = DHCPV4_OPT_DOMAIN;
                    fake4_header[1] = strlen(domainbuf);
                    APPEND_BUF(dhcp_options, dhcp_options_len, fake4_header, 2);
                    APPEND_BUF(dhcp_options, dhcp_options_len, domainbuf, fake4_header[1]);
                  }
                }
            }
            break;
          }
    }

  iface_all_set_dhcp_send(dhcpv6_options, dhcpv6_options_len,
                          dhcp_options, dhcp_options_len);

  L_DEBUG("set %d bytes of DHCPv6 options: %s",
          dhcpv6_options_len, HEX_REPR(dhcpv6_options, dhcpv6_options_len));
 oom:
  if (dhcpv6_options)
    free(dhcpv6_options);
  if (dhcp_options)
    free(dhcp_options);
}

static void _republish_cb(hncp_subscriber s)
{
  _refresh_ec(container_of(s, hncp_glue_s, subscriber), true);
}

static void _updated_ldp(hncp_glue g,
                         const struct prefix *prefix,
                         const char *dp_ifname,
                         hnetd_time_t valid_until, hnetd_time_t preferred_until,
                         const void *dhcpv6_data, size_t dhcpv6_len)
{
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
    }
  else
    {
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
    }
  /* Force republish (the actual TLV will be actually refreshed in the
   * subscriber callback) */
  o->tlvs_dirty = true;
  hncp_schedule(o);
}


static void hncp_pa_cps(struct pa_data_user *user, struct pa_cp *cp, uint32_t flags)
{
	hncp_glue g = container_of(user, struct hncp_glue_struct, data_user);
	if((flags & (PADF_CP_ADVERTISE | PADF_CP_TODELETE))) {
		char *ifname = NULL;
		if(cp->type == PA_CPT_L) /* For now, only type cp_la has an interface */
			ifname = _pa_cpl(cp)->iface->ifname;
		hncp_tlv_ap_update(g->hncp, &cp->prefix, ifname,
				cp->authoritative, cp->priority, !(flags & PADF_CP_TODELETE) && cp->advertised);
	}
}

static void hncp_pa_dps(struct pa_data_user *user, struct pa_dp *dp, uint32_t flags)
{
	hncp_glue g = container_of(user, struct hncp_glue_struct, data_user);
	bool todelete = (flags & PADF_DP_TODELETE)?true:false;
	if(dp->local && flags) {
		struct pa_ldp *ldp = container_of(dp, struct pa_ldp, dp);
		_updated_ldp(g, &dp->prefix, ldp->iface?ldp->iface->ifname:NULL, todelete?0:dp->valid_until, todelete?0:dp->preferred_until,
				dp->dhcp_data, dp->dhcp_len);
	}
}

static void hncp_pa_aas(struct pa_data_user *user, struct pa_aa *aa, uint32_t flags)
{
	hncp_glue g = container_of(user, struct hncp_glue_struct, data_user);
	if(aa->local && (flags & (PADF_AA_TODELETE | PADF_AA_CREATED))) {
		struct pa_laa *laa = container_of(aa, struct pa_laa, aa);
		if(!laa->cpl)
			return;
		hncp_link l = hncp_find_link_by_name(g->hncp, laa->cpl->iface->ifname, false);
		if (!l)
			return;
		hncp_t_router_address_s ra;
		ra.link_id = cpu_to_be32(l->iid);
		ra.address = aa->address;
		hncp_update_tlv_raw(g->hncp, HNCP_T_ROUTER_ADDRESS,
				&ra, sizeof(ra),
				(flags & PADF_AA_CREATED));
	}
}

static void _node_change_cb(hncp_subscriber s, hncp_node n, bool add)
{
  hncp_glue g = container_of(s, hncp_glue_s, subscriber);
  hncp o = g->hncp;

  /* We're only interested about own node change. That's same as
   * router ID changing, and notable thing then is that own_node is
   * NULL and operation of interest is add.. */
  if (o->own_node || !add)
    return;
  struct pa_rid *rid = (struct pa_rid *)&n->node_identifier_hash;

  /* Set the rid */
  pa_flood_set_rid(g->pa_data, rid);
  pa_flood_notify(g->pa_data);
}

static void _ap_if_update_timeout_cb(struct uloop_timeout *to)
{
  hncp_glue g = container_of(to, hncp_glue_s, ap_if_update_timeout);

  _update_a_local_links(g);
}

hncp_glue hncp_pa_glue_create(hncp o, struct pa_data *pa_data)
{
  struct pa_rid *rid = (struct pa_rid *)&o->own_node->node_identifier_hash;
  hncp_glue g = calloc(1, sizeof(*g));
  if (!g)
    return false;

  vlist_init(&g->dps, compare_dps, update_dp);
  g->subscriber.tlv_change_callback = _tlv_cb;
  /* g->subscriber.node_change_callback = _node_cb; */
  g->subscriber.republish_callback = _republish_cb;
  g->pa_data = pa_data;
  g->subscriber.node_change_callback = _node_change_cb;
  g->hncp = o;
  memset(&g->data_user, 0, sizeof(g->data_user));
  g->data_user.cps = hncp_pa_cps;
  g->data_user.dps = hncp_pa_dps;
  g->data_user.aas = hncp_pa_aas;
  g->ap_if_update_timeout.cb = _ap_if_update_timeout_cb;

  /* Set the rid */
  pa_flood_set_rid(pa_data, rid);
  pa_flood_set_flooddelays(pa_data, HNCP_DELAY, HNCP_DELAY_LL);

  /* And let the floodgates open. pa SHOULD NOT call anything yet, as
   * it isn't started. hncp, on the other hand, most likely will. */
  pa_data_subscribe(pa_data, &g->data_user);
  hncp_subscribe(o, &g->subscriber);

  return g;
}

void hncp_pa_glue_destroy(hncp_glue g)
{
  uloop_timeout_cancel(&g->ap_if_update_timeout);
  vlist_flush_all(&g->dps);
  free(g);
}
