/*
 * $Id: dncp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Thu Apr 30 11:49:55 2015 mstenber
 * Edit time:     877 min
 *
 */

#include "dncp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in <profile>_io.
 */

/***************************************************** Low-level TLV pushing */

static bool _push_node_state_tlv(struct tlv_buf *tb, dncp_node n,
                                 bool incl_data)
{
  hnetd_time_t now = dncp_time(n->dncp);
  dncp_t_node_state s;
  int l = incl_data && n->tlv_container ? tlv_len(n->tlv_container) : 0;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NODE_STATE, sizeof(*s) + l);

  if (!a)
    return false;
  s = tlv_data(a);
  s->node_identifier = n->node_identifier;
  s->update_number = cpu_to_be32(n->update_number);
  s->ms_since_origination = cpu_to_be32(now - n->origination_time);
  s->node_data_hash = n->node_data_hash;
  if (l)
    memcpy((void *)s + sizeof(*s), tlv_data(n->tlv_container), l);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, dncp o)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NET_STATE, DNCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  dncp_calculate_network_hash(o);
  memcpy(c, &o->network_hash, DNCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, dncp_link l)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_ENDPOINT_ID, sizeof(dncp_t_link_id_s));
  dncp_t_link_id lid;

  if (!a)
    return false;
  lid = tlv_data(a);
  lid->node_identifier = l->dncp->own_node->node_identifier;
  lid->link_id = l->iid;
  return true;
}

static bool _push_keepalive_interval_tlv(struct tlv_buf *tb,
                                         uint32_t link_id,
                                         uint32_t value)
{
  dncp_t_keepalive_interval ki;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_KEEPALIVE_INTERVAL, sizeof(*ki));

  if (!a)
    return false;
  ki = tlv_data(a);
  ki->link_id = link_id;
  ki->interval_in_ms = cpu_to_be32(value);
  return true;
}

/****************************************** Actual payload sending utilities */

void dncp_link_send_network_state(dncp_link l,
                                  struct sockaddr_in6 *dst,
                                  size_t maximum_size)
{
  struct tlv_buf tb;
  dncp o = l->dncp;
  dncp_node n;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (!_push_link_id_tlv(&tb, l))
    goto done;
  if (!_push_network_state_tlv(&tb, o))
    goto done;

  /* We multicast only 'stable' state. Unicast, we give everything we have. */
  if (!o->graph_dirty || !maximum_size)
    {
      int nn = 0;

      if (maximum_size)
        dncp_for_each_node(o, n)
          nn++;
      if (!maximum_size
          || maximum_size >= (tlv_len(tb.head)
                              + (4 + sizeof(dncp_t_keepalive_interval_s))
                              + nn * (4 + sizeof(dncp_t_node_state_s))))
        {
          dncp_for_each_node(o, n)
            {
              if (!_push_node_state_tlv(&tb, n, false))
                goto done;
            }
        }
    }
  if (l->conf->keepalive_interval != DNCP_KEEPALIVE_INTERVAL)
    if (!_push_keepalive_interval_tlv(&tb, l->iid, l->conf->keepalive_interval))
      goto done;
  if (maximum_size && tlv_len(tb.head) > maximum_size)
    {
      L_ERR("dncp_link_send_network_state failed: %d > %d",
            (int)tlv_len(tb.head), (int)maximum_size);
      goto done;
    }
  L_DEBUG("dncp_link_send_network_state -> " SA6_F "%%" DNCP_LINK_F,
          SA6_D(dst), DNCP_LINK_D(l));
  dncp_io_sendto(o, tlv_data(tb.head), tlv_len(tb.head), dst, NULL);
 done:
  tlv_buf_free(&tb);
}

void dncp_link_send_node_state(dncp_link l,
                               struct sockaddr_in6 *dst,
                               dncp_node n)
{
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_node_state_tlv(&tb, n, true))
    {
      L_DEBUG("dncp_link_send_node_data %s -> " SA6_F " %%" DNCP_LINK_F,
              DNCP_NODE_REPR(n), SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst, NULL);
    }
  tlv_buf_free(&tb);
}

void dncp_link_send_req_network_state(dncp_link l,
                                      struct sockaddr_in6 *dst)
{
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_network_state_tlv(&tb, l->dncp) /* SHOULD include local */
      && tlv_new(&tb, DNCP_T_REQ_NET_STATE, 0))
    {
      L_DEBUG("dncp_link_send_req_network_state -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst, NULL);
    }
  tlv_buf_free(&tb);
}

void dncp_link_send_req_node_data(dncp_link l,
                                  struct sockaddr_in6 *dst,
                                  dncp_t_node_state ns)
{
  struct tlv_buf tb;
  struct tlv_attr *a;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && (a = tlv_new(&tb, DNCP_T_REQ_NODE_STATE, DNCP_HASH_LEN)))
    {
      L_DEBUG("dncp_link_send_req_node_data -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      memcpy(tlv_data(a), &ns->node_identifier, DNCP_NI_LEN);
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst, NULL);
    }
  tlv_buf_free(&tb);
}

/************************************************************ Input handling */

static dncp_tlv
_heard(dncp_link l, dncp_t_link_id lid, struct sockaddr_in6 *src,
       bool multicast)
{
  dncp_t_neighbor_s np = {
    .neighbor_node_identifier = lid->node_identifier,
    .neighbor_link_id = lid->link_id,
    .link_id = l->iid
  };
  dncp_neighbor n;
  dncp_tlv t = dncp_find_tlv(l->dncp, DNCP_T_NEIGHBOR,
                             &np, sizeof(np));
  if (!t)
    {
      /* Doing add based on multicast is relatively insecure. */
      if (multicast)
        return NULL;
      t =
        dncp_add_tlv(l->dncp, DNCP_T_NEIGHBOR, &np, sizeof(np),
                     sizeof(*n));
      if (!t)
        return NULL;
      n = dncp_tlv_get_extra(t);
      n->last_contact = dncp_time(l->dncp);
      L_DEBUG("Neighbor %s added on " DNCP_LINK_F,
              DNCP_STRUCT_REPR(lid->node_identifier), DNCP_LINK_D(l));
    }
  else
    n = dncp_tlv_get_extra(t);

  if (!multicast)
    {
      n->last_sa6 = *src;
    }
  return t;
}

/* Handle a single received message. */
static void
handle_message(dncp_link l,
               struct sockaddr_in6 *src,
               struct in6_addr *dst,
               struct tlv_attr *msg)
{
  dncp o = l->dncp;
  struct tlv_attr *a;
  dncp_node n;
  dncp_t_link_id lid = NULL;
  dncp_tlv tne = NULL;
  dncp_neighbor ne = NULL;
  struct tlv_buf tb;
  uint32_t new_update_number;
  bool should_request_network_state = false;
  bool updated_or_requested_state = false;
  bool got_tlv = false;
  bool multicast = IN6_IS_ADDR_MULTICAST(dst);

  /* Make sure source is IPv6 link-local (for now..) */
  if (!IN6_IS_ADDR_LINKLOCAL(&src->sin6_addr))
    return;

  /* Non-multicast destination has to be too. */
  if (!multicast && !IN6_IS_ADDR_LINKLOCAL(dst))
    return;

  /* Validate that link id exists (if this were TCP, we would keep
   * track of the remote link id on per-stream basis). */
  tlv_for_each_attr(a, msg)
    if (tlv_id(a) == DNCP_T_ENDPOINT_ID)
      {
        /* Error to have multiple top level link id's. */
        if (lid)
          {
            L_INFO("got multiple link ids - ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(*lid))
          {
            L_INFO("got invalid sized link id - ignoring");
            return;
          }
        lid = tlv_data(a);
      }

  bool is_local = memcmp(&lid->node_identifier, &o->own_node->node_identifier,
                         DNCP_NI_LEN) == 0;
  if (!is_local && lid)
    {
      tne = _heard(l, lid, src, multicast);
      if (!tne)
        {
          if (!multicast)
            return; /* OOM */
          should_request_network_state = true;
        }
      ne = tne ? dncp_tlv_get_extra(tne) : NULL;
    }

  tlv_for_each_attr(a, msg)
    {
      got_tlv = true;
      switch (tlv_id(a))
        {
        case DNCP_T_REQ_NET_STATE:
          /* Ignore if in multicast. */
          if (multicast)
            L_INFO("ignoring req-net-hash in multicast");
          else
            dncp_link_send_network_state(l, src, 0);
          break;

        case DNCP_T_REQ_NODE_STATE:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-node-data in multicast");
              break;
            }
          void *p = tlv_data(a);
          if (tlv_len(a) != DNCP_HASH_LEN)
            break;
          n = dncp_find_node_by_node_identifier(o, p, false);
          if (!n)
            break;
          if (n != o->own_node)
            {
              if (o->graph_dirty)
                {
                  L_DEBUG("prune pending, ignoring node data request");
                  break;
                }

              if (n->last_reachable_prune != o->last_prune)
                {
                  L_DEBUG("not reachable request, ignoring");
                  break;
                }
            }
          dncp_link_send_node_state(l, src, n);
          break;

        case DNCP_T_NET_STATE:
          if (tlv_len(a) != DNCP_HASH_LEN)
            {
              L_DEBUG("got invalid network hash length: %d", tlv_len(a));
              break;
            }
          unsigned char *nethash = tlv_data(a);
          bool consistent = memcmp(nethash, &o->network_hash,
                                   DNCP_HASH_LEN) == 0;
          L_DEBUG("received network state which is %sconsistent (%s)",
                  consistent ? "" : "in",
                  is_local ? "local" : ne ? "remote" : "unknown remote");

          if (consistent)
            {
              /* Increment Trickle count + last in sync time.*/
              if (ne)
                {
                  l->trickle_c++;
                  ne->last_contact = dncp_time(l->dncp);
                }
              else
                {
                  /* Send an unicast request, to potentially set up the
                   * peer structure. */
                  should_request_network_state = true;
                }
            }
          else
            {
              /* MUST: rate limit check */
              if ((dncp_time(o) - l->last_req_network_state) < l->conf->trickle_imin)
                break;
              l->last_req_network_state = dncp_time(o);

              should_request_network_state = true;
            }
          break;

        case DNCP_T_NODE_STATE:
          if (tlv_len(a) < sizeof(dncp_t_node_state_s))
            {
              L_INFO("invalid length node state TLV received - ignoring");
              break;
            }
          dncp_t_node_state ns = tlv_data(a);
          n = dncp_find_node_by_node_identifier(o, &ns->node_identifier,
                                                false);
          new_update_number = be32_to_cpu(ns->update_number);
          bool interesting = !n
            || (dncp_update_number_gt(n->update_number, new_update_number)
                || (new_update_number == n->update_number
                    && memcmp(&n->node_data_hash,
                              &ns->node_data_hash,
                              sizeof(n->node_data_hash)) != 0));
          L_DEBUG("saw %s %s for %s/%p (update number %d)",
                  interesting ? "new" : "old",
                  tlv_len(a) == sizeof(*ns) ? "state" : "state+data",
                  DNCP_NODE_REPR(ns), n, new_update_number);
          if (!interesting)
            break;
          bool found_data = false;
          int nd_len = tlv_len(a) - sizeof(*ns);
#ifdef DTLS
          /* We don't accept node data via multicast in secure mode. */
          if (multicast && o->profile_data.d)
            nd_len = 0;
#endif /* DTLS */
          if (nd_len > 0)
            {
              unsigned char *nd_data = (unsigned char *)ns + sizeof(*ns);

              n = n ? n: dncp_find_node_by_node_identifier(o, &ns->node_identifier, true);
              if (!n)
                return; /* OOM */
              if (dncp_node_is_self(n))
                {
                  L_DEBUG("received %d update number from network, own %d",
                          new_update_number, n->update_number);
                  if (o->collided)
                    {
                      if (dncp_profile_handle_collision(o))
                        return;
                    }
                  else
                    {
                      o->collided = true;
                      n->update_number = new_update_number + 1000 - 1;
                      /* republish increments the count too */
                    }
                  o->republish_tlvs = true;
                  dncp_schedule(o);
                  return;
                }
              /* Ok. nd contains more recent TLV data than what we have
               * already. Woot. */
              memset(&tb, 0, sizeof(tb));
              tlv_buf_init(&tb, 0); /* not passed anywhere */
              if (tlv_put_raw(&tb, nd_data, nd_len))
                {
                  dncp_node_set(n, new_update_number,
                                dncp_time(o) - be32_to_cpu(ns->ms_since_origination),
                                tb.head);
                }
              else
                {
                  L_DEBUG("tlv_put_raw failed");
                  tlv_buf_free(&tb);
                }
              found_data = true;
            }
          if (!found_data)
            {
              L_DEBUG("node data %s for %s",
                      multicast ? "not supplied" : "missing",
                      DNCP_NODE_REPR(ns));
              dncp_link_send_req_node_data(l, src, ns);
            }
          updated_or_requested_state = true;
          break;

        default:
          /* Unknown TLV - MUST ignore. */
          continue;
        }

    }

  /* Shared got unicast from the other party handling. */
  if (!multicast && got_tlv && ne)
    ne->last_contact = dncp_time(l->dncp);

  if (should_request_network_state && !updated_or_requested_state && !is_local)
    dncp_link_send_req_network_state(l, src);
}


void dncp_poll(dncp o)
{
  unsigned char buf[DNCP_MAXIMUM_PAYLOAD_SIZE+sizeof(struct tlv_attr)];
  struct tlv_attr *msg = (struct tlv_attr *)buf;
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct sockaddr_in6 src;
  struct in6_addr dst;
  dncp_link l;
  dncp_subscriber s;

  while ((read = dncp_io_recvfrom(o, msg->data, DNCP_MAXIMUM_PAYLOAD_SIZE,
                                  srcif, &src, &dst)) > 0)
    {
      tlv_init(msg, 0, read + sizeof(struct tlv_attr));

      /* First off. If it's off some link we aren't supposed to use, ignore. */
      l = dncp_find_link_by_name(o, srcif, false);
      if (l)
    	  handle_message(l, &src, &dst, msg);

      list_for_each_entry(s, &o->subscribers[DNCP_CALLBACK_SOCKET_MSG],
                          lhs[DNCP_CALLBACK_SOCKET_MSG])
        s->msg_received_callback(s, srcif, &src, &dst, msg);
    }
}
