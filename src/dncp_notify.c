/*
 * $Id: dncp_notify.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 10:04:30 2013 mstenber
 * Last modified: Mon Jun 15 12:40:19 2015 mstenber
 * Edit time:     61 min
 *
 */

/*
 * This module implements the DNCP subscription API.
 */

#include "dncp_i.h"

#define HANDLE_ENUM_CB(o, s, x)                                 \
  do {                                                          \
    x(o, s, DNCP_CALLBACK_LOCAL_TLV, local_tlv_change_cb);      \
    x(o, s, DNCP_CALLBACK_REPUBLISH, republish_cb);             \
    x(o, s, DNCP_CALLBACK_TLV, tlv_change_cb);                  \
    x(o, s, DNCP_CALLBACK_NODE, node_change_cb);                \
    x(o, s, DNCP_CALLBACK_EP, ep_change_cb);                    \
    x(o, s, DNCP_CALLBACK_SOCKET_MSG, msg_received_cb);         \
  } while(0)

#define HANDLE_ADD(o, s, e, cb)                         \
  if (s->cb) list_add(&s->lhs[e], &o->subscribers[e])

void dncp_subscribe(dncp o, dncp_subscriber s)
{
  dncp_node n;
  dncp_tlv t;
  struct tlv_attr *a;

  HANDLE_ENUM_CB(o, s, HANDLE_ADD);
  if (s->local_tlv_change_cb)
    {
      vlist_for_each_element(&o->tlvs, t, in_tlvs)
        s->local_tlv_change_cb(s, &t->tlv, true);
    }
  dncp_for_each_node(o, n)
    {
      if (s->node_change_cb)
        s->node_change_cb(s, n, true);
      if (s->tlv_change_cb)
        dncp_node_for_each_tlv(n, a)
          s->tlv_change_cb(s, n, a, true);
    }
}

#define HANDLE_DEL(o, s, e, cb)                 \
  if (s->cb) list_del(&s->lhs[e])

void dncp_unsubscribe(dncp o, dncp_subscriber s)
{
  dncp_node n;
  struct tlv_attr *a;
  dncp_tlv t;

  if (s->local_tlv_change_cb)
    {
      vlist_for_each_element(&o->tlvs, t, in_tlvs)
        s->local_tlv_change_cb(s, &t->tlv, false);
    }
  dncp_for_each_node(o, n)
    {
      if (s->tlv_change_cb)
        dncp_node_for_each_tlv(n, a)
          s->tlv_change_cb(s, n, a, false);
      if (s->node_change_cb)
        s->node_change_cb(s, n, false);
    }
  HANDLE_ENUM_CB(o, s, HANDLE_DEL);
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
  list_for_each_entry(s, &n->dncp->subscribers[DNCP_CALLBACK_TLV],
                      lhs[DNCP_CALLBACK_TLV])
    {
      struct tlv_attr *op = a_old ? tlv_data(a_old) : NULL;
      struct tlv_attr *np = a_new ? tlv_data(a_new) : NULL;

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
              s->tlv_change_cb(s, n, op, false);
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
          s->tlv_change_cb(s, n, op, false);
          op = tlv_next(op);
        }
    }
  list_for_each_entry(s, &n->dncp->subscribers[DNCP_CALLBACK_TLV],
                      lhs[DNCP_CALLBACK_TLV])
    {
      struct tlv_attr *op = a_old ? tlv_data(a_old) : NULL;
      struct tlv_attr *np = a_new ? tlv_data(a_new) : NULL;

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
              s->tlv_change_cb(s, n, np, true);
              np = tlv_next(np);
            }
        }
      /* Anything left in np was added. */
      while (np)
        {
          ENSURE_VALID(np, new_end);
          s->tlv_change_cb(s, n, np, true);
          np = tlv_next(np);
        }
    }
}

void dncp_notify_subscribers_local_tlv_changed(dncp o,
                                               struct tlv_attr *a,
                                               bool add)
{
  dncp_subscriber s;

  list_for_each_entry(s, &o->subscribers[DNCP_CALLBACK_LOCAL_TLV],
                      lhs[DNCP_CALLBACK_LOCAL_TLV])
    s->local_tlv_change_cb(s, a, add);
}

void dncp_notify_subscribers_node_changed(dncp_node n, bool add)
{
  dncp_subscriber s;

  list_for_each_entry(s, &n->dncp->subscribers[DNCP_CALLBACK_NODE],
                      lhs[DNCP_CALLBACK_NODE])
    s->node_change_cb(s, n, add);
}


void dncp_notify_subscribers_about_to_republish_tlvs(dncp_node n)
{
  dncp_subscriber s;

  list_for_each_entry(s, &n->dncp->subscribers[DNCP_CALLBACK_REPUBLISH],
                      lhs[DNCP_CALLBACK_REPUBLISH])
    s->republish_cb(s);
}


void dncp_notify_subscribers_ep_changed(dncp_ep ep,
                                        enum dncp_subscriber_event event)
{
  dncp_subscriber s;
  dncp_ep_i l = container_of(ep, dncp_ep_i_s, conf);

  list_for_each_entry(s, &l->dncp->subscribers[DNCP_CALLBACK_EP],
                      lhs[DNCP_CALLBACK_EP])
    s->ep_change_cb(s, &l->conf, event);
}
