/*
 * $Id: dncp_notify.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 10:04:30 2013 mstenber
 * Last modified: Tue Dec 23 18:57:46 2014 mstenber
 * Edit time:     45 min
 *
 */

/*
 * This module implements the DNCP subscription API.
 */

#include "dncp_i.h"

#define NODE_CHANGE_CALLBACK(s, n, add)         \
  if (s->node_change_callback)                  \
    s->node_change_callback(s, n, add)

void dncp_subscribe(dncp o, dncp_subscriber s)
{
  dncp_node n;
  dncp_tlv t;
  struct tlv_attr *a;

  list_add(&s->lh, &o->subscribers);
  if (s->local_tlv_change_callback)
    {
      vlist_for_each_element(&o->tlvs, t, in_tlvs)
        s->local_tlv_change_callback(s, &t->tlv, true);
    }
  dncp_for_each_node(o, n)
    {
      NODE_CHANGE_CALLBACK(s, n, true);
      if (s->tlv_change_callback)
        {
          dncp_node_for_each_tlv(n, a)
            s->tlv_change_callback(s, n, a, true);
        }
    }
}

void dncp_unsubscribe(dncp o, dncp_subscriber s)
{
  dncp_node n;
  struct tlv_attr *a;
  dncp_tlv t;

  if (s->local_tlv_change_callback)
    {
      vlist_for_each_element(&o->tlvs, t, in_tlvs)
        s->local_tlv_change_callback(s, &t->tlv, false);
    }
  dncp_for_each_node(o, n)
    {
      if (s->tlv_change_callback)
        {
          dncp_node_for_each_tlv(n, a)
            s->tlv_change_callback(s, n, a, false);
        }
      NODE_CHANGE_CALLBACK(s, n, false);
    }
  list_del(&s->lh);
}

/* This can be only used in a loop which makes sure that the p stays
 * valid. It ensures that next TLV won't exceed the end, and if it
 * would, p is invalidated and loop aborts. */
#define ENSURE_VALID(p, end)                    \
  if ((end - TLV_SIZE) < (void *)p)             \
    {                                           \
      p = NULL;                                 \
      break;                                    \
    }                                           \
  if ((end - tlv_pad_len(p)) < (void *)p)       \
    {                                           \
      p = NULL;                                 \
      break;                                    \
    }

void dncp_notify_subscribers_tlvs_changed(dncp_node n,
                                          struct tlv_attr *a_old,
                                          struct tlv_attr *a_new)
{
  dncp_subscriber s;
  void *old_end = (void *)a_old + (a_old ? tlv_pad_len(a_old) : 0);
  void *new_end = (void *)a_new + (a_new ? tlv_pad_len(a_new) : 0);
  int r;

  /* There are two distinct steps here: First we remove missing, and
   * then we add new ones. Otherwise, there may be confusion if we get
   * first new + then remove, and the underlying TLV has same
   * key.. :-p */
  list_for_each_entry(s, &n->dncp->subscribers, lh)
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
            }
          else if (r < 0)
            {
              /* op < np => op deleted */
              s->tlv_change_callback(s, n, op, false);
              op = tlv_next(op);
            }
          else
            {
              /* op > np => np added */
              /* in part 2 */
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
    }
  list_for_each_entry(s, &n->dncp->subscribers, lh)
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
            }
          else if (r < 0)
            {
              /* op < np => op deleted */
              /* we did this in part 1 */
              op = tlv_next(op);
            }
          else
            {
              /* op > np => np added */
              s->tlv_change_callback(s, n, np, true);
              np = tlv_next(np);
            }
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

void dncp_notify_subscribers_local_tlv_changed(dncp o,
                                               struct tlv_attr *a,
                                               bool add)
{
  dncp_subscriber s;

  list_for_each_entry(s, &o->subscribers, lh)
    if (s->local_tlv_change_callback)
      s->local_tlv_change_callback(s, a, add);
}

void dncp_notify_subscribers_node_changed(dncp_node n, bool add)
{
  dncp_subscriber s;

  list_for_each_entry(s, &n->dncp->subscribers, lh)
    NODE_CHANGE_CALLBACK(s, n, add);
}


void dncp_notify_subscribers_about_to_republish_tlvs(dncp_node n)
{
  dncp_subscriber s;

  list_for_each_entry(s, &n->dncp->subscribers, lh)
    if (s->republish_callback)
      s->republish_callback(s);
}


void dncp_notify_subscribers_link_changed(dncp_link l, enum dncp_subscriber_event event)
{
  dncp_subscriber s;

  list_for_each_entry(s, &l->dncp->subscribers, lh)
    if (s->link_change_callback)
      s->link_change_callback(s, l->ifname, event);
}
