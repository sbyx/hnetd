/*
 * $Id: test_hncp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Fri Dec  6 18:15:44 2013 mstenber
 * Last modified: Wed Feb 12 23:14:26 2014 mstenber
 * Edit time:     142 min
 *
 */

/*
 * This is unit module that makes sure that hncp data structures are
 * correctly reported to the pa, and vice versa.
 */

/* Basically, what we need to ensure is that:

   - lap is propagated directly to HNCP (and removed as needed)

   - ldp is propagated to HNCP, and whenver time passes (and it's
   refreshed), the lifetimes should be valid still and updated
   accordingly. Obviously removal has to work also.

   - eap is propagated to PA; and when the associated node moves to
   different interface, eap is propagated again. Disappearance
   should work too.

   - edp is propagated as-is to PA. Disappearance should work too.

   Main approach for testing is to create two instances of hncp; one is
   used to generate the TLV (for itself), which then just magically shows
   up in the other one. Then, peering/not peering relationship of the two
   is manually played with.
*/

/* 1 is always built-in. */
#define L_LEVEL7
#define MAXIMUM_PROPAGATION_DELAY 0

#include "net_sim.h"

typedef struct {
  struct list_head lh;
  struct prefix p;
} rp_s, *rp;

typedef struct {
  rp_s rp;
  struct pa_rid rid;
  char ifname[IFNAMSIZ];
  hnetd_time_t updated;
} eap_s, *eap;

typedef struct {
  rp_s rp;
  struct pa_rid rid;
  hnetd_time_t valid;
  hnetd_time_t preferred;
  void *dhcpv6_data;
  size_t dhcpv6_len;
  hnetd_time_t updated;
} edp_s, *edp;

struct list_head eaps;
struct list_head edps;

void *_find_rp(const struct prefix *prefix, struct list_head *lh,
               size_t create_size)
{
  rp rp;

  list_for_each_entry(rp, lh, lh)
    {
      if (memcmp(prefix, &rp->p, sizeof(*prefix)) == 0)
        return rp;
    }
  if (!create_size)
    return NULL;
  rp = calloc(1, create_size);
  rp->p = *prefix;
  list_add_tail(&rp->lh, lh);
  return rp;
}

void _zap_rp(void *e)
{
  rp rp = e;
  list_del(&rp->lh);
  free(e);
}
/*
int pa_update_eap(pa_t pa, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  const char *ifname, bool to_delete)
{
  net_node node = container_of(pa, net_node_s, pa);
  eap e;

  node->updated_eap++;
  L_NOTICE("pa_update_eap #%d %s %s / %s@%s at %lld",
           node->updated_eap,
           to_delete ? "delete" : "upsert",
           HEX_REPR(rid, HNCP_HASH_LEN),
           PREFIX_REPR(prefix),
           ifname ? ifname : "?",
           (long long)node->s->now);
  sput_fail_unless(prefix, "prefix set");
  sput_fail_unless(rid, "rid set");

  e = _find_rp(prefix, &eaps, to_delete ? 0 : sizeof(*e));
  if (!e)
    return 0;
  if (to_delete)
    {
      _zap_rp(e);
      return 0;
    }
  if (ifname)
    strcpy(e->ifname, ifname);
  else
    *e->ifname = 0;
  e->updated = node->s->now;
  return 0;
}

int pa_update_edp(pa_t pa, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  const struct prefix *excluded,
                  hnetd_time_t valid_until, hnetd_time_t preferred_until,
                  const void *dhcpv6_data, size_t dhcpv6_len)
{
  net_node node = container_of(pa, net_node_s, pa);
  edp e;

  node->updated_edp++;
  L_NOTICE("pa_update_edp #%d %s / %s v%lld p%lld (+ %d dhcpv6) at %lld",
           node->updated_edp,
           HEX_REPR(rid, HNCP_HASH_LEN),
           PREFIX_REPR(prefix),
           (long long)valid_until, (long long)preferred_until,
           (int)dhcpv6_len,
           (long long)node->s->now);
  sput_fail_unless(prefix, "prefix set");
  sput_fail_unless(rid, "rid set");
  sput_fail_unless(!excluded, "excluded not set");
  e = _find_rp(prefix, &edps, valid_until == 0? 0 : sizeof(*e));
  if (!e)
    return 0;
  if (valid_until == 0)
    {
      free(e->dhcpv6_data);
      _zap_rp(e);
      return 0;
    }
  if (rid)
    e->rid = *rid;
  e->valid = valid_until;
  e->preferred = preferred_until;
  if (e->dhcpv6_data)
    {
      free(e->dhcpv6_data);
      e->dhcpv6_data = NULL;
    }
  e->dhcpv6_len = dhcpv6_len;
  if (dhcpv6_data)
    {
      sput_fail_unless(dhcpv6_len > 0, "has to have len if data");
      e->dhcpv6_data = malloc(dhcpv6_len);
      memcpy(e->dhcpv6_data, dhcpv6_data, dhcpv6_len);
    }
  else
    {
      sput_fail_unless(dhcpv6_len == 0, "NULL data means zero length");
    }
  e->updated = node->s->now;
  return 0;
}*/

struct prefix p1 = {
  .prefix = { .s6_addr = {
      0x20, 0x01, 0x00, 0x01}},
  .plen = 40 };

struct prefix p2 = {
  .prefix = { .s6_addr = {
      0x20, 0x02, 0x00, 0x01}},
  .plen = 48 };


struct prefix p3 = {
  .prefix = { .s6_addr = {
      0x20, 0x03, 0x00, 0x01}},
  .plen = 54 };


struct prefix p4 = {
  .prefix = { .s6_addr = {
      0x20, 0x04, 0x00, 0x01}},
  .plen = 58 };


void hncp_pa_two(void)
{
  net_sim_s s;
  hncp n1;
  hncp n2;
  hncp_link l1;
  hncp_link l2, l22;
  net_node node1, node2;
  eap ea;
  edp ed;

  INIT_LIST_HEAD(&eaps);
  INIT_LIST_HEAD(&edps);

  net_sim_init(&s);
  n1 = net_sim_find_hncp(&s, "n1");
  n2 = net_sim_find_hncp(&s, "n2");
  l1 = net_sim_hncp_find_link_by_name(n1, "eth0");
  l2 = net_sim_hncp_find_link_by_name(n2, "eth1");
  l22 = net_sim_hncp_find_link_by_name(n2, "eth2");
  sput_fail_unless(avl_is_empty(&l1->neighbors.avl), "no l1 neighbors");
  sput_fail_unless(avl_is_empty(&l2->neighbors.avl), "no l2 neighbors");

  /* connect l1+l2 -> should converge at some point */
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);

  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));

  L_DEBUG("converged, feeding in ldp");

  sput_fail_unless(n1->nodes.avl.count == 2, "n1 nodes == 2");
  sput_fail_unless(n2->nodes.avl.count == 2, "n2 nodes == 2");


  /* Play with the prefix API. Feed in stuff! */
  node1 = container_of(n1, net_node_s, n);
  node2 = container_of(n2, net_node_s, n);


  /* First, fake delegated prefixes */
  hnetd_time_t p1_valid = s.start;
  hnetd_time_t p1_preferred = s.start + 4200;
  pa_update_ldp(&node1->pa_data, &p1,
                            "eth0", p1_valid, p1_preferred,
                            NULL, 0);

  hnetd_time_t p2_valid = s.start + 12345;
  hnetd_time_t p2_preferred = s.start;
  pa_update_ldp(&node1->pa_data, &p2,
                            NULL, p2_valid, p2_preferred,
                            "foo", 4);

  hnetd_time_t p3_valid = s.start + 123456;
  hnetd_time_t p3_preferred = s.start + 1200;
  pa_update_ldp(&node1->pa_data, &p3,
                            NULL, p3_valid, p3_preferred,
                            "bar", 4);

  hnetd_time_t p4_valid = HNETD_TIME_MAX;
  hnetd_time_t p4_preferred = HNETD_TIME_MAX;
  pa_update_ldp(&node1->pa_data, &p4,
                            NULL, p4_valid, p4_preferred,
                            "baz", 4);

  SIM_WHILE(&s, 1000, node2->updated_edp != 4);
  node2->updated_edp = 0;

  /* First element */
  sput_fail_unless(edps.next != &edps, "edps not empty");
  ed = list_entry(edps.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p1) == 0, "p1 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p1_preferred + 1, "p1 preferred ok");
  sput_fail_unless(ed->valid, "p1 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 0, "dhcpv6_len == 0");


  /* Second element */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 2");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p2) == 0, "p2 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred, "p2 preferred ok");
  sput_fail_unless(ed->valid == p2_valid + 1, "p2 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "foo")==0, "foo");

  /* Third element */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 3");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p3) == 0, "p3 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p3_preferred + 1, "p3 preferred ok");
  sput_fail_unless(ed->valid == p3_valid + 1, "p3 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "bar")==0, "bar");

  /* Fourth element (infinite lifetime) */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 4");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p4) == 0, "p4 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == HNETD_TIME_MAX, "p4 preferred ok");
  sput_fail_unless(ed->valid == HNETD_TIME_MAX, "p4 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "baz")==0, "baz");

  /* The end */
  sput_fail_unless(ed->rp.lh.next == &edps, "edps had 4");


  /* Insert some dummy TLV at node 1 which should cause fresh edp
   * reception; timestamps should not change, though. */

  L_DEBUG("inserting fake TLV (empty)");

  struct tlv_attr tmp;
  tlv_init(&tmp, 67, TLV_SIZE);
  hncp_add_tlv(&node1->n, &tmp);
  SIM_WHILE(&s, 1000, node2->updated_edp != (2 * 4));
  node2->updated_edp = 0;

  /* First element */
  sput_fail_unless(edps.next != &edps, "edps not empty");
  ed = list_entry(edps.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p1) == 0, "p1 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p1_preferred + 1, "p1 preferred ok");
  sput_fail_unless(ed->valid, "p1 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 0, "dhcpv6_len == 0");


  /* Second element */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 2");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p2) == 0, "p2 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred, "p2 preferred ok");
  sput_fail_unless(ed->valid == p2_valid + 1, "p2 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "foo")==0, "foo");

  /* Third element */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 3");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p3) == 0, "p3 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p3_preferred + 1, "p3 preferred ok");
  sput_fail_unless(ed->valid == p3_valid + 1, "p3 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "bar")==0, "bar");

  /* Fourth element (infinite lifetime) */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 4");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p4) == 0, "p4 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HNCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == HNETD_TIME_MAX, "p4 preferred ok");
  sput_fail_unless(ed->valid == HNETD_TIME_MAX, "p4 valid ok");
  sput_fail_unless(ed->dhcpv6_len == 4, "dhcpv6_len == 4");
  sput_fail_unless(ed->dhcpv6_data && strcmp(ed->dhcpv6_data, "baz")==0, "baz");

  /* The end */
  sput_fail_unless(ed->rp.lh.next == &edps, "edps had 4");

  /* Make sure delete works too */
  pa_update_ldp(&node1->pa_data, &p2,
                            NULL, 0, 0,
                            NULL, 0);

  pa_update_ldp(&node1->pa_data, &p4,
                            NULL, 0, 0,
                            NULL, 0);

  L_DEBUG("waiting for delete effects");
  /* should get 2 updates + 2 deletes */
  SIM_WHILE(&s, 1000, node2->updated_edp != (4 + 2));

  /* Make sure p2 is gone */
  ed = list_entry(edps.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p1) == 0, "p1 same");
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 2");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p3) == 0, "p3 same");

  /* The end */
  sput_fail_unless(ed->rp.lh.next == &edps, "edps had 2");

  /* Then fake prefix assignment */
  p1.plen = 64;
  p2.plen = 64;
  pa_update_lap(&node1->pa_data, &p1, NULL, false);
  pa_update_lap(&node1->pa_data, &p2, "eth0", false);
  SIM_WHILE(&s, 1000,
            node2->updated_eap != 2);

  /* First element */
  ea = list_entry(eaps.next, eap_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ea->rp.p, &p1) == 0, "p1 same");
  sput_fail_unless(ea->updated == s.now, "updated now");


  /* Second element */
  sput_fail_unless(ea->rp.lh.next != &eaps, "eaps has >= 2");
  ea = list_entry(ea->rp.lh.next, eap_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ea->rp.p, &p2) == 0, "p2 same");
  sput_fail_unless(ea->updated == s.now, "updated now");
  sput_fail_unless(strcmp(ea->ifname, "eth1") == 0, "eth1");

  /* The end */
  sput_fail_unless(ea->rp.lh.next == &eaps, "eaps had 2");

  /* switch from l2 to l22 to connect n2's side; eventually the ifname
   * on p2 prefix in eaps should reflect that. */
  net_sim_set_connected(l1, l2, false);
  net_sim_set_connected(l2, l1, false);
  net_sim_set_connected(l1, l22, true);
  net_sim_set_connected(l22, l1, true);

  SIM_WHILE(&s, 1000,
            (!(ea=_find_rp(&p2, &eaps, 0))
             || strcmp(ea->ifname, "eth2")!=0));

  net_sim_uninit(&s);
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp_pa", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hncp_pa"); /* optional */
  sput_run_test(hncp_pa_two);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
