/*
 * $Id: hcp_notify.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 10:04:30 2013 mstenber
 * Last modified: Thu Dec  5 09:09:41 2013 mstenber
 * Edit time:     35 min
 *
 */

/*
 * This module implements the HCP subscription API.
 */

#include "hcp_i.h"

#define NODE_CHANGE_CALLBACK(s, n, add) \
  if (s->node_change_callback)          \
    s->node_change_callback(s, n, add)

void hcp_subscribe(hcp o, hcp_subscriber s)
{
  hcp_node n;
  struct tlv_attr *a;
  int i;

  list_add(&s->lh, &o->subscribers);
  hcp_for_each_node(o, n)
    {
      NODE_CHANGE_CALLBACK(s, n, true);
      if (s->tlv_change_callback)
        {
          hcp_node_for_each_tlv(n, a, i)
            s->tlv_change_callback(s, n, a, true);
        }
    }
}

void hcp_unsubscribe(hcp o, hcp_subscriber s)
{
  hcp_node n;
  struct tlv_attr *a;
  int i;

  hcp_for_each_node(o, n)
    {
      if (s->tlv_change_callback)
        {
          hcp_node_for_each_tlv(n, a, i)
            s->tlv_change_callback(s, n, a, false);
        }
      NODE_CHANGE_CALLBACK(s, n, false);
    }
  list_del(&s->lh);
}

/* This can be only used in a loop which makes sure that the p stays
 * valid. It ensures that next TLV won't exceed the end, and if it
 * would, p is invalidated and loop aborts. */
#define ENSURE_VALID(p, end)            \
if ((end - TLV_SIZE) < (void *)p)       \
  {                                     \
    p = NULL;                           \
    break;                              \
  }                                     \
if ((end - tlv_pad_len(p)) < (void *)p) \
  {                                     \
    p = NULL;                           \
    break;                              \
  }

void hcp_notify_subscribers_tlvs_changed(hcp_node n,
                                         struct tlv_attr *a_old,
                                         struct tlv_attr *a_new)
{
  hcp_subscriber s;
  void *old_end = (void *)a_old + (a_old ? tlv_pad_len(a_old) : 0);
  void *new_end = (void *)a_new + (a_new ? tlv_pad_len(a_new) : 0);
  int r;

  list_for_each_entry(s, &n->hcp->subscribers, lh)
    {
      struct tlv_attr *op = a_old ? tlv_data(a_old) : NULL;
      struct tlv_attr *np = a_new ? tlv_data(a_new) : NULL;

      /* If subscriber isn't interested, just skip. */
      if (!s->tlv_change_callback)
        continue;

      /* Keep two pointers, one for old, one for new. */

      /* While there's data in both, and it looks valid, we drain each
       * 0-1 at the time. */
      while (op && np)
        {
          ENSURE_VALID(op, old_end);
          ENSURE_VALID(np, new_end);
          /* Ok, op and np both point at valid structs. */
          r = tlv_attr_cmp(op, np);
          /* If they're equal, we can skip both, no sense giving notification */
          if (!r)
            {
              op = tlv_next(op);
              np = tlv_next(np);
              continue;
            }
          if (r < 0)
            {
              /* op < np => op deleted */
              s->tlv_change_callback(s, n, op, false);
              op = tlv_next(op);
            }
          else
            {
              /* op > np => np added */
              s->tlv_change_callback(s, n, np, true);
              np = tlv_next(np);
            }
        }
      /* Anything left in op was deleted. */
      while (op)
        {
          ENSURE_VALID(op, old_end);
          s->tlv_change_callback(s, n, op, false);
          op = tlv_next(op);
        }
      /* Anything left in np was added. */
      while (np)
        {
          ENSURE_VALID(np, new_end);
          s->tlv_change_callback(s, n, np, true);
          np = tlv_next(np);
        }
    }
}

void hcp_notify_subscribers_node_changed(hcp_node n, bool add)
{
  hcp_subscriber s;

  list_for_each_entry(s, &n->hcp->subscribers, lh)
    NODE_CHANGE_CALLBACK(s, n, add);
}


void hcp_notify_subscribers_about_to_republish_tlvs(hcp_node n)
{
  hcp_subscriber s;

  list_for_each_entry(s, &n->hcp->subscribers, lh)
    if (s->republish_callback)
      s->republish_callback(s);
}
