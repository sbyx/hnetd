/*
 * $Id: hcp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:32:50 2013 mstenber
 * Last modified: Wed Dec  4 13:14:13 2013 mstenber
 * Edit time:     20 min
 *
 */

/* Glue code between hcp and pa. */

/* What does it do:

   - subscribes to HCP and PA events

   - produces / consumes HCP TLVs related to PA

   _Ideally_ this could actually use external hcp API only. In
   practise, though, I can't be bothered. So I don't.

   Structurally, assigned and delegated prefix handling is
   different. Delegated prefixes are maintained locally (or well, at
   least their main key + pointer to TLV is). Assigned prefixes on the
   other hand are assumed to contain sufficient data within callback
   arguments to reconstruct the TLV as needed, and therefore there is
   nothing there here.
*/

#include "hcp_pa.h"
#include "hcp_i.h"

typedef struct {
  /* HCP notification subscriber structure */
  hcp_subscriber_s subscriber;

  /* What are we gluing together anyway? */
  hcp hcp;
  pa_t pa;
} hcp_glue_s, *hcp_glue;


static void _tlv_cb(hcp_subscriber s,
                    hcp_node n, struct tlv_attr *tlv, bool add)
{
  hcp_glue g = container_of(s, hcp_glue_s, subscriber);

}

static void _node_cb(hcp_subscriber s, hcp_node n, bool add)
{
  hcp_glue g = container_of(s, hcp_glue_s, subscriber);

}

static void _updated_lap(const struct prefix *prefix, const char *ifname,
                         int to_delete, void *priv)
{
  hcp_glue g = priv;
}

static void _updated_ldp(const struct prefix *prefix,
                         const struct prefix *excluded, const char *dp_ifname,
                         hnetd_time_t valid_until, hnetd_time_t preferred_until,
                         const void *dhcpv6_data, size_t dhcpv6_len,
                         void *priv)
{
  hcp_glue g = priv;

}


bool hcp_connect_pa(hcp o, pa_t pa)
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

  g->subscriber.tlv_change_callback = _tlv_cb;
  g->subscriber.node_change_callback = _node_cb;
  g->pa = pa;
  g->hcp = o;

  /* Set the rid */
  pa_set_rid(pa, rid);

  /* And let the floodgates open. pa SHOULD NOT call anything yet, as
   * it isn't started. hcp, on the other hand, most likely will. */
  pa_flood_subscribe(pa, &pa_cbs);
  hcp_subscribe(o, &g->subscriber);

  return true;
}
