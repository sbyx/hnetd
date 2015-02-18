/*
 * $Id: dncp_proto.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 08:34:59 2013 mstenber
 * Last modified: Wed Feb 18 13:43:58 2015 mstenber
 * Edit time:     742 min
 *
 */

#include "dncp_i.h"

/*
 * This module contains the logic to handle receiving and sending of
 * traffic from single- or multicast sources. The actual low-level IO
 * is performed in <profile>_io.
 */

/***************************************************** Low-level TLV pushing */

static bool _push_node_state_tlv(struct tlv_buf *tb, dncp_node n)
{
  hnetd_time_t now = dncp_time(n->dncp);
  dncp_t_node_state s;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NODE_STATE, sizeof(*s));

  if (!a)
    return false;
  s = tlv_data(a);
  s->node_identifier = n->node_identifier;
  s->update_number = cpu_to_be32(n->update_number);
  s->ms_since_origination = cpu_to_be32(now - n->origination_time);
  s->node_data_hash = n->node_data_hash;
  return true;
}

static bool _push_node_data_tlv(struct tlv_buf *tb, dncp_node n)
{
  int s = n->tlv_container ? tlv_len(n->tlv_container) : 0;
  dncp_t_node_data_header h;
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NODE_DATA, sizeof(*h) + s);

  if (!a)
    return false;
  h = tlv_data(a);
  h->node_identifier = n->node_identifier;
  h->update_number = cpu_to_be32(n->update_number);
  memcpy((void *)h + sizeof(*h), tlv_data(n->tlv_container), s);
  return true;
}

static bool _push_network_state_tlv(struct tlv_buf *tb, dncp o)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_NETWORK_HASH, DNCP_HASH_LEN);
  unsigned char *c;

  if (!a)
    return false;
  c = tlv_data(a);
  memcpy(c, &o->network_hash, DNCP_HASH_LEN);
  return true;
}

static bool _push_link_id_tlv(struct tlv_buf *tb, dncp_link l)
{
  struct tlv_attr *a = tlv_new(tb, DNCP_T_LINK_ID, sizeof(dncp_t_link_id_s));
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
  dncp_calculate_network_hash(o);
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
              if (!_push_node_state_tlv(&tb, n))
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
  dncp_io_sendto(o, tlv_data(tb.head), tlv_len(tb.head), dst);
 done:
  tlv_buf_free(&tb);
}

void dncp_link_send_node_data(dncp_link l,
                              struct sockaddr_in6 *dst,
                              dncp_node n)
{
  /* Send two things:
     - node state tlv
     - node data tlv
  */
  struct tlv_buf tb;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0); /* not passed anywhere */
  if (_push_link_id_tlv(&tb, l)
      && _push_node_state_tlv(&tb, n)
      && _push_node_data_tlv(&tb, n))
    {
      L_DEBUG("dncp_link_send_node_state %s -> " SA6_F " %%" DNCP_LINK_F,
              DNCP_NODE_REPR(n), SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
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
      && tlv_new(&tb, DNCP_T_REQ_NET_HASH, 0))
    {
      L_DEBUG("dncp_link_send_req_network_state -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
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
      && (a = tlv_new(&tb, DNCP_T_REQ_NODE_DATA, DNCP_HASH_LEN)))
    {
      L_DEBUG("dncp_link_send_req_node_state -> " SA6_F "%%" DNCP_LINK_F,
              SA6_D(dst), DNCP_LINK_D(l));
      memcpy(tlv_data(a), &ns->node_identifier, DNCP_NI_LEN);
      dncp_io_sendto(l->dncp, tlv_data(tb.head), tlv_len(tb.head), dst);
    }
  tlv_buf_free(&tb);
}

/************************************************************ Input handling */

static dncp_tlv
_heard(dncp_link l, dncp_t_link_id lid, struct sockaddr_in6 *src,
       bool multicast)
{
  dncp_t_node_data_neighbor_s np = {
    .neighbor_node_identifier = lid->node_identifier,
    .neighbor_link_id = lid->link_id,
    .link_id = l->iid
  };
  dncp_neighbor n;
  dncp_tlv t = dncp_find_tlv(l->dncp, DNCP_T_NODE_DATA_NEIGHBOR,
                             &np, sizeof(np));
  if (!t)
    {
      /* Doing add based on multicast is relatively insecure. */
      if (multicast)
        return NULL;
      t =
        dncp_add_tlv(l->dncp, DNCP_T_NODE_DATA_NEIGHBOR, &np, sizeof(np),
                     sizeof(*n));
      if (!t)
        return NULL;
      n = dncp_tlv_get_extra(t);
      n->last_sync = dncp_time(l->dncp);
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
               unsigned char *data, ssize_t len,
               bool multicast)
{
  dncp o = l->dncp;
  struct tlv_attr *a;
  dncp_node n;
  dncp_t_link_id lid = NULL;
  unsigned char *nethash = NULL;
  int nodestates = 0;
  dncp_tlv tne = NULL;
  dncp_neighbor ne = NULL;
  dncp_t_node_state ns;
  dncp_t_node_data_header nd;
  unsigned char *nd_data = NULL;
  int nd_len = 0;
  struct tlv_buf tb;
  uint32_t new_update_number;

  /* Validate that link id exists. */
  tlv_for_each_in_buf(a, data, len)
    if (tlv_id(a) == DNCP_T_LINK_ID)
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

  if (!lid)
    {
      L_INFO("did not get link ids - ignoring");
      return;
    }

  bool is_local = memcmp(&lid->node_identifier, &o->own_node->node_identifier,
                         DNCP_NI_LEN) == 0;
  if (!is_local)
    {
      tne = _heard(l, lid, src, multicast);
      if (!tne && !multicast)
        return;
      ne = tne ? dncp_tlv_get_extra(tne) : NULL;
    }

  /* Estimates what's in the payload + handles the few
   * request messages we support. */
  tlv_for_each_in_buf(a, data, len)
    {
      switch (tlv_id(a))
        {
        case DNCP_T_NETWORK_HASH:
          if (tlv_len(a) != DNCP_HASH_LEN)
            {
              L_DEBUG("got invalid network hash length: %d", tlv_len(a));
              return;
            }
          if (nethash)
            {
              L_DEBUG("ignoring message with multiple network hashes");
              return;
            }
          nethash = tlv_data(a);
          break;
        case DNCP_T_NODE_STATE:
          nodestates++;
          break;
        case DNCP_T_REQ_NET_HASH:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in multicast");
              return;
            }
          dncp_link_send_network_state(l, src, 0);
          return;
        case DNCP_T_REQ_NODE_DATA:
          /* Ignore if in multicast. */
          if (multicast)
            {
              L_INFO("ignoring req-net-hash in unicast");
              return;
            }
          tlv_for_each_in_buf(a, data, len)
            {
              if (tlv_id(a) == DNCP_T_REQ_NODE_DATA)
                {
                  void *p = tlv_data(a);
                  int len = tlv_len(a);
                  if (!len || tlv_len(a) != DNCP_HASH_LEN)
                    continue;
                  n = dncp_find_node_by_node_identifier(o, p, false);
                  if (!n)
                    continue;
                  if (n != o->own_node)
                    {
                      if (o->graph_dirty)
                        {
                          L_DEBUG("prune pending, ignoring node data request");
                          continue;
                        }

                      if (n->last_reachable_prune != o->last_prune)
                        {
                          L_DEBUG("not reachable request, ignoring");
                          continue;
                        }
                    }
                  dncp_link_send_node_data(l, src, n);
                }
            }
          return;
        }
    }

  /* Requests were handled above. So what's left is response
   * processing here. If it was unicast, it was probably solicited
   * response, so we can mark the node as having been in touch with us
   * recently. */
  if (!multicast)
    {
      L_DEBUG("unicast received from %s %s on " DNCP_LINK_F,
              is_local ? "local" : ne ? "remote" : "unknown remote",
              DNCP_NODE_REPR(lid), DNCP_LINK_D(l));
      if (ne)
        ne->last_sync = dncp_time(l->dncp);
    }

  /* Three different cases to be handled for solicited/unsolicited responses:
     - raw network hash
     - network hash + node states
     - node state + node data
  */
  if (nethash)
    {
      /* We don't care, if network hash state IS same. */
      if (memcmp(nethash, &o->network_hash, DNCP_HASH_LEN) == 0)
        {
          L_DEBUG("received network state which is consistent (%s)",
                  is_local ? "local" : ne ? "remote" : "unknown remote");

          /* Increment Trickle count + last in sync time.*/
          if (ne)
            {
              l->trickle_c++;
              ne->last_sync = dncp_time(l->dncp);
            }
          else if (!is_local)
            {
              /* Send an unicast request, to potentially set up the
               * peer structure. */
              dncp_link_send_req_network_state(l, src);
            }
          return;
        }

      bool should_unicast = multicast;
      if (multicast)
        {
          /* No need to reset Trickle anymore, but log the fact */
          L_DEBUG("received inconsistent multicast network state %s != %s %s",
                  HEX_REPR(nethash, DNCP_HASH_LEN),
                  HEX_REPR(&o->network_hash, DNCP_HASH_LEN),
                  ne ? "" : "(from unknown)");
        }

      /* Short form (raw network hash) */
      if (!nodestates)
        {
          if (multicast)
            dncp_link_send_req_network_state(l, src);
          else
            L_INFO("unicast short form network status received - ignoring");
          return;
        }

      /* TBD: The section below is essentially an attack vector. We
       * should definitely add some sort of rate limiting here, as now
       * this provides nice amplification attack (send packet with src
       * = your enemy, with alleged set of new data.. current
       * req-per-node code below sends N packets. oops). */

      /* Long form (has node states). */
      /* The exercise becomes just to ask for any node state that
       * differs from local and is more recent. */
      tlv_for_each_in_buf(a, data, len)
        if (tlv_id(a) == DNCP_T_NODE_STATE)
          {
            if (tlv_len(a) != sizeof(dncp_t_node_state_s))
              {
                L_INFO("invalid length node state TLV received - ignoring");
                return;
              }
            ns = tlv_data(a);
            n = dncp_find_node_by_node_identifier(o, &ns->node_identifier,
                                                  false);
            new_update_number = be32_to_cpu(ns->update_number);
            bool interesting = !n
              || (dncp_update_number_gt(n->update_number, new_update_number)
                  || (new_update_number == n->update_number
                      && memcmp(&n->node_data_hash,
                                &ns->node_data_hash,
                                sizeof(n->node_data_hash)) != 0));
            if (interesting)
              {
                L_DEBUG("saw something new for %s/%p (update number %d)",
                        DNCP_NODE_REPR(ns), n, new_update_number);
                dncp_link_send_req_node_data(l, src, ns);
                should_unicast = false;
              }
            else
              {
                L_DEBUG("saw something old for %s/%p (update number %d)",
                        DNCP_NODE_REPR(ns), n, new_update_number);
              }
          }

      if (should_unicast && ne)
        {
          /* They did not have anything newer than what we did -> by
           * implication, we probably have something they are lacking.
           */
          dncp_link_send_network_state(l, src, 0);

          /* This is needed to keep keepalive ticking */
          if (dncp_neighbor_interval(o, &tne->tlv))
            dncp_link_send_req_network_state(l, src);
        }
      return;
    }
  /* We don't accept node data via multicast. */
  if (multicast)
    {
      L_INFO("received node data via multicast, ignoring");
      return;
    }

  /* Look for node state + node data. */
  ns = NULL;
  nd = NULL;
  tlv_for_each_in_buf(a, data, len)
    switch(tlv_id(a))
      {
      case DNCP_T_NODE_STATE:
        if (ns)
          {
            L_INFO("received multiple node state TLVs, ignoring");
            return;
          }
        if (tlv_len(a) != sizeof(dncp_t_node_state_s))
          {
            L_INFO("received invalid node state TLVs, ignoring");
            return;
          }
        ns = tlv_data(a);
        break;
      case DNCP_T_NODE_DATA:
        if (nd)
          {
            L_INFO("received multiple node data TLVs, ignoring");
            return;
          }
        nd_len = tlv_len(a) - sizeof(dncp_t_node_data_header_s);
        if (nd_len < 0)
          {
            L_INFO("received invalid node data TLV, ignoring");
            return;
          }
        nd = tlv_data(a);
        nd_data = (unsigned char *)nd + sizeof(dncp_t_node_data_header_s);
        break;
      }
  if (!ns || !nd)
    {
      L_INFO("node data or node state TLV missing, ignoring");
      return;
    }
  /* If they're for different nodes, not interested. */
  if (memcmp(&ns->node_identifier, &nd->node_identifier, DNCP_NI_LEN))
    {
      L_INFO("node data and state identifier mismatch, ignoring");
      return;
    }
  /* Is it actually valid? Should be same update #. */
  if (ns->update_number != nd->update_number)
    {
      L_INFO("node data and state update number mismatch, ignoring");
      return;
    }
  /* Let's see if it's more recent. */
  n = dncp_find_node_by_node_identifier(o, &ns->node_identifier, true);
  if (!n)
    return;
  new_update_number = be32_to_cpu(ns->update_number);
  if (dncp_update_number_gt(new_update_number, n->update_number)
      || (n->update_number == new_update_number
          && !memcmp(&n->node_data_hash,
                     &ns->node_data_hash,
                     sizeof(n->node_data_hash))))
    {
      L_DEBUG("received update number %d, but already have %d",
              new_update_number, n->update_number);
      return;
    }
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
        o->collided = true;
      n->update_number = new_update_number;
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
}


void dncp_poll(dncp o)
{
  unsigned char buf[DNCP_MAXIMUM_PAYLOAD_SIZE];
  ssize_t read;
  char srcif[IFNAMSIZ];
  struct sockaddr_in6 src;
  struct in6_addr dst;
  dncp_link l;

  while ((read = dncp_io_recvfrom(o, buf, sizeof(buf), srcif, &src, &dst)) > 0)
    {
      /* First off. If it's off some link we aren't supposed to use, ignore. */
      l = dncp_find_link_by_name(o, srcif, false);
      if (!l)
        continue;
      /* If it's multicast, it's valid if and only if it's aimed at
       * the multicast address. */
      if (IN6_IS_ADDR_MULTICAST(&dst))
        {
#if 0
          /* XXX - should we care about this? if so, should hook it up
           * somewhere profile specific. */
          if (memcmp(&dst, &o->multicast_address, sizeof(dst)) != 0)
            continue;
#endif /* 0 */

          /* XXX - should we care about source address too? */
          handle_message(l, &src, buf, read, true);
          continue;
        }
      /* If it's not aimed _a_ linklocal address, we don't care. */
      if (!IN6_IS_ADDR_LINKLOCAL(&dst))
        continue;
      handle_message(l, &src, buf, read, false);
    }
}
