/*
 * $Id: test_hcp_pa.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Fri Dec  6 18:15:44 2013 mstenber
 * Last modified: Fri Dec  6 20:20:52 2013 mstenber
 * Edit time:     49 min
 *
 */

/*
 * This is unit module that makes sure that hcp data structures are
 * correctly reported to the pa, and vice versa.
 */

/* Basically, what we need to ensure is that:

   - lap is propagated directly to HCP (and removed as needed)

   - ldp is propagated to HCP, and whenver time passes (and it's
     refreshed), the lifetimes should be valid still and updated
     accordingly. Obviously removal has to work also.

   - eap is propagated to PA; and when the associated node moves to
     different interface, eap is propagated again. Disappearance
     should work too.

   - edp is propagated as-is to PA. Disappearance should work too.

   Main approach for testing is to create two instances of hcp; one is
   used to generate the TLV (for itself), which then just magically shows
   up in the other one. Then, peering/not peering relationship of the two
   is manually played with.
*/

/* 1 is always built-in. */
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
} eap_s, *eap;

typedef struct {
  rp_s rp;
  struct pa_rid rid;
  hnetd_time_t valid;
  hnetd_time_t preferred;
  void *dhcpv6_data;
  size_t dhcpv6_len;
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

int pa_update_eap(pa_t pa, const struct prefix *prefix,
                  const struct pa_rid *rid,
                  const char *ifname, bool to_delete)
{
  net_node node = container_of(pa, net_node_s, pa);
  eap e;

  sput_fail_unless(prefix, "prefix set");
  sput_fail_unless(rid, "rid set");
  node->updated_eap++;

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

  sput_fail_unless(prefix, "prefix set");
  sput_fail_unless(rid, "rid set");
  sput_fail_unless(!excluded, "excluded not set");
  node->updated_edp++;

  e = _find_rp(prefix, &edps, valid_until == 0? 0 : sizeof(*e));
  if (!e)
    return 0;
  if (valid_until == 0)
    {
      free(e->dhcpv6_data);
      _zap_rp(e);
      return 0;
    }
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
  return 0;
}

struct prefix p1 = {
  .prefix = { .s6_addr = {
      0x20, 0x01, 0x00, 0x01}},
  .plen = 54 };

struct prefix p2 = {
  .prefix = { .s6_addr = {
      0x20, 0x02, 0x00, 0x01}},
  .plen = 54 };


void hcp_pa_two(void)
{
  net_sim_s s;
  hcp n1;
  hcp n2;
  hcp_link l1;
  hcp_link l2;
  net_node node1, node2;
  eap ea;
  edp ed;

  INIT_LIST_HEAD(&eaps);
  INIT_LIST_HEAD(&edps);

  net_sim_init(&s);
  n1 = net_sim_find_hcp(&s, "n1");
  n2 = net_sim_find_hcp(&s, "n2");
  l1 = net_sim_hcp_find_link_by_name(n1, "eth0");
  l2 = net_sim_hcp_find_link_by_name(n2, "eth1");
  sput_fail_unless(avl_is_empty(&l1->neighbors.avl), "no l1 neighbors");
  sput_fail_unless(avl_is_empty(&l2->neighbors.avl), "no l2 neighbors");

  /* connect l1+l2 -> should converge at some point */
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);
  SIM_WHILE(&s, 100, !net_sim_is_converged(&s));

  sput_fail_unless(n1->nodes.avl.count == 2, "n1 nodes == 2");
  sput_fail_unless(n2->nodes.avl.count == 2, "n2 nodes == 2");


  /* Play with the prefix API. Feed in stuff! */
  node1 = container_of(n1, net_node_s, n);
  node2 = container_of(n2, net_node_s, n);

  /* First, fake delegated prefixes */
  hnetd_time_t p1_valid = s.now + 123;
  hnetd_time_t p1_preferred = s.now + 1;
  node1->pa.cbs.updated_ldp(&p1, NULL,
                            "eth0", p1_valid, p1_preferred,
                            NULL, 0, node1->g);
  hnetd_time_t p2_valid = s.now + 42;
  hnetd_time_t p2_preferred = s.now + 5;
  node1->pa.cbs.updated_ldp(&p2, NULL,
                            NULL, p2_valid, p2_preferred,
                            "foo", 3, node1->g);

  SIM_WHILE(&s, 1000,
            node2->updated_edp != 2);

  /* Make sure we have exactly two entries. And by lucky coindidence,
   * as stuff should stay ordered, we should be able just to iterate
   * through them. */
  sput_fail_unless(edps.next != &edps, "edps not empty");

  /* First element */
  ed = list_entry(edps.next, edp_s, rp.lh);
  L_NOTICE("first entry: %s", PREFIX_REPR(&ed->rp.p));
  /* p1 has explicit link, which is first key => p2 is first we
   * receive as it has link id of zeros. */
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p2) == 0, "p2 same");
  /* weirdly enough, while the interface _is_ broadcast, it is never
   * received by PA API. XXX: Ask Pierre to remove it also from the
   * send case.. */
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p2_preferred, "p2 preferred ok");
  sput_fail_unless(ed->valid == p2_valid, "p2 valid ok");


  /* Second element */
  sput_fail_unless(ed->rp.lh.next != &edps, "edps has >= 2");
  ed = list_entry(ed->rp.lh.next, edp_s, rp.lh);
  sput_fail_unless(prefix_cmp(&ed->rp.p, &p1) == 0, "p1 same");
  sput_fail_unless(memcmp(&ed->rid, &node1->n.own_node->node_identifier_hash,
                          HCP_HASH_LEN) == 0, "rid ok");
  sput_fail_unless(ed->preferred == p1_preferred, "p1 preferred ok");
  sput_fail_unless(ed->valid == p1_valid, "p1 valid ok");

  /* The end */
  sput_fail_unless(ed->rp.lh.next == &edps, "edps had 2");


  /* Then fake prefix assignment */
  p1.plen = 64;
  p2.plen = 64;
  node1->pa.cbs.updated_lap(&p1, "eth0", false, node1->g);
  node1->pa.cbs.updated_lap(&p2, NULL, false, node1->g);
  SIM_WHILE(&s, 1000,
            node2->updated_eap != 2);

  net_sim_uninit(&s);
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hcp_pa", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hcp_pa"); /* optional */
  sput_run_test(hcp_pa_two);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
