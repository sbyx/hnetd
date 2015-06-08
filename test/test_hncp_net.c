/*
 * $Id: test_hncp_net.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 10:41:56 2013 mstenber
 * Last modified: Mon Jun  8 09:53:53 2015 mstenber
 * Edit time:     642 min
 *
 */

/*
 * This is N-node version of the testsuite which leverages net_sim.h.
 */

#include <unistd.h>

/* Test utilities */
#include "net_sim.h"
#include "sput.h"

/**************************************************************** Test cases */

struct prefix p1 = {
  .prefix = { .s6_addr = {
      0x20, 0x01, 0x00, 0x01}},
  .plen = 54 };

struct prefix p2 = {
  .prefix = { .s6_addr = {
      0x20, 0x02, 0x00, 0x01}},
  .plen = 54 };

bool link_has_neighbors(dncp_ep_i l)
{
  dncp_tlv t;

  dncp_for_each_local_tlv(l->dncp, t)
    {
      if (tlv_id(&t->tlv) == DNCP_T_NEIGHBOR)
        {
          dncp_t_neighbor ne = tlv_data(&t->tlv);
          if (ne->link_id == l->iid)
            return true;
        }
    }
  return false;
}

void hncp_two(void)
{
  net_sim_s s;
  dncp n1;
  dncp n2;
  dncp_ep_i l1;
  dncp_ep_i l2;
  net_node node1;
  //net_node node2;

  net_sim_init(&s);
  n1 = net_sim_find_dncp(&s, "n1");
  n1->own_node->update_number = 0xFFFFFFFE;
  dncp_ep lc = dncp_ep_find_by_name(n1, "eth0");
  lc->keepalive_interval = 1000;
  n2 = net_sim_find_dncp(&s, "n2");
  l1 = net_sim_dncp_find_link_by_name(n1, "eth0");
  l2 = net_sim_dncp_find_link_by_name(n2, "eth1");
  sput_fail_unless(!link_has_neighbors(l1), "no l1 neighbors");
  sput_fail_unless(!link_has_neighbors(l2), "no l2 neighbors");

  /* connect l1+l2 -> should converge at some point */
  net_sim_set_connected(l1, l2, true);
  net_sim_set_connected(l2, l1, true);
  SIM_WHILE(&s, 1000, !net_sim_is_converged(&s));

  sput_fail_unless(n1->nodes.avl.count == 2, "n1 nodes == 2");
  sput_fail_unless(n2->nodes.avl.count == 2, "n2 nodes == 2");


  /* Play with the prefix API. Feed in stuff! */
  node1 = net_sim_node_from_dncp(n1);
  //node2 = container_of(n2, net_node_s, n);

  /* First, give delegated prefixes */
  net_sim_node_iface_callback(node1,
                              cb_prefix,
                              "eth1",
                              &p1,
                              NULL,
                              hnetd_time() + 123, hnetd_time() + 1,
                              NULL, 0);
  net_sim_node_iface_callback(node1,
                              cb_prefix,
                              "eth1",
                              &p2,
                              NULL,
                              hnetd_time() + 123, hnetd_time() + 1,
                              NULL, 0);
  if (net_sim_dncp_tlv_type_count(n2, HNCP_T_EXTERNAL_CONNECTION) != 1)
    SIM_WHILE(&s, 1000,
              !net_sim_is_converged(&s) ||
              net_sim_dncp_tlv_type_count(n2, HNCP_T_EXTERNAL_CONNECTION) != 1);

#define dncp_ifname_has_highest_id(o, ifname) \
  dncp_ep_has_highest_id(dncp_ep_find_by_name(o, ifname))

    /* Prefix assignment should just happen. Magic(?). */
  /* Wait for prefixes to be assigned too */
  if (net_sim_dncp_tlv_type_count(n2, HNCP_T_ASSIGNED_PREFIX) != 2)
    SIM_WHILE(&s, 10000,
              !net_sim_is_converged(&s) ||
              net_sim_dncp_tlv_type_count(n2, HNCP_T_ASSIGNED_PREFIX) != 2);

  sput_fail_unless(dncp_ifname_has_highest_id(n1, "eth0") !=
                   dncp_ifname_has_highest_id(n2, "eth1"),
                   "someone is highest");

  /* disconnect on one side (=> unidirectional traffic) => should at
   * some point disappear. */
  hnetd_time_t time_ok = hnetd_time();
  L_DEBUG("disconnecting one side (the more active sender)");
  net_sim_set_connected(l1, l2, false);
  SIM_WHILE(&s, 10000,
            link_has_neighbors(l2));
  hnetd_time_t time_gone = hnetd_time();
  sput_fail_unless((time_gone - time_ok) < lc->keepalive_interval * 5,
                   "realized relatively fast neighbor gone");


  /* n1 will keep getting stuff from n2, so it's sometimes alive,
   * sometimes not.. However, network hashes should be again
   * different. */
  sput_fail_unless(memcmp(&n1->network_hash, &n2->network_hash, HNCP_HASH_LEN),
                   "hashes different");

  /* Should also have done the necessary purging of nodes due to lack
   * of reachability (eventually; this may take some more time due to
   * grace period).. */
  SIM_WHILE(&s, 10000, n2->nodes.avl.count != 1);

  sput_fail_unless(dncp_ifname_has_highest_id(n1, "eth0") &&
                   dncp_ifname_has_highest_id(n2, "eth1"),
                   "both highest");

  sput_fail_unless(dncp_ifname_has_highest_id(n1, "nonexistent"),
                   "nonexistent highest too");

  net_sim_uninit(&s);
}

/* 11 nodes represented, wired according to how they are wired in the
 * test topology. */
char *nodenames[] = {"cpe", "b1", "b2", "b3", "b4", "b5", "b6",
                     "b7", "b8", "b9", "b10", NULL};
typedef struct {
  int src;
  char *srclink;
  int dst;
  char *dstlink;
} nodeconnection_s;

nodeconnection_s nodeconnections[] = {
  {0, "eth1", 1, "eth0"},
  {0, "eth1", 2, "eth0"},
  {1, "eth1", 5, "eth0"},
  {1, "eth2", 2, "eth1"},
  {1, "eth3", 9, "eth0"},
  {2, "eth2", 3, "eth0"},
  {3, "eth1", 4, "eth0"},
  {4, "eth1", 8, "eth0"},
  {4, "eth1", 9, "eth1"},
  {5, "eth1", 6, "eth0"},
  {6, "eth1", 9, "eth2"},
  {6, "eth2", 7, "eth0"},
  {7, "eth1", 10, "eth0"},
  {8, "eth1", 10, "eth1"},
  {9, "eth3", 10, "eth2"},
};

static void handle_connections(net_sim s,
                               nodeconnection_s *c,
                               int n_conns)
{
  int i;

  L_DEBUG("handle_connections %d", n_conns);
  for (i = 0 ; i < n_conns ; i++)
    {
      dncp n1 = net_sim_find_dncp(s, nodenames[c->src]);
      dncp_ep_i l1 = net_sim_dncp_find_link_by_name(n1, c->srclink);
      dncp n2 = net_sim_find_dncp(s, nodenames[c->dst]);
      dncp_ep_i l2 = net_sim_dncp_find_link_by_name(n2, c->dstlink);

      net_sim_set_connected(l1, l2, true);
      net_sim_set_connected(l2, l1, true);
      c++;
    }
}

static void raw_bird14(net_sim s)
{
  int num_connections = sizeof(nodeconnections) / sizeof(nodeconnections[0]);

  /* Both of these seem to do things that make the stable
   * no-change-at-all check fail. */
  s->disable_pa = true;
  s->disable_multicast = true;

  handle_connections(s, &nodeconnections[0], num_connections);

  SIM_WHILE(s, 10000, !net_sim_is_converged(s));

  sput_fail_unless(net_sim_find_dncp(s, "b10")->nodes.avl.count == 11,
                   "b10 enough nodes");

  sput_fail_unless(hnetd_time() - s->start < 10 * HNETD_TIME_PER_SECOND,
                   "should converge in 10 seconds");

  sput_fail_unless(s->sent_multicast < 1000, "with 'few' multicast");

  sput_fail_unless(s->sent_unicast < 5000, "with 'few' unicast");

  /* Then, simulate network for a while, keeping eye on how often it's
   * NOT converged. */
  int converged_count = s->converged_count;
  int not_converged_count = s->not_converged_count;
#if L_LEVEL >= LOG_NOTICE
  int sent_unicast = s->sent_unicast;
#endif /* L_LEVEL >= LOG_NOTICE */
  hnetd_time_t convergence_time = hnetd_time();

  s->add_neighbor_is_error = true;
  s->del_neighbor_is_error = true;
  L_DEBUG("assume stable topology");
  SIM_WHILE(s, 100000, !net_sim_is_converged(s) ||
            (hnetd_time() - convergence_time) < (HNCP_KEEPALIVE_INTERVAL*
                                                 HNCP_KEEPALIVE_MULTIPLIER));
  L_NOTICE("unicasts sent:%d after convergence, last %lld ms after convergence",
           s->sent_unicast - sent_unicast, (long long)(s->last_unicast_sent - convergence_time));
#if 0
  /* As we do reachability checking, this isn't valid.. unfortunately. */
  sput_fail_unless((s->sent_unicast - sent_unicast) < 50,
                   "did not send (many) unicasts");
#endif /* 0 */
  sput_fail_unless(s->not_converged_count == not_converged_count,
                   "should stay converged");
  sput_fail_unless(s->converged_count > converged_count,
                   "converged count rising");

  L_DEBUG("assume unstable topology");
  s->add_neighbor_is_error = false;
  s->del_neighbor_is_error = false;

  /* Make sure it will converge after remove + re-add in reasonable
   * timeframe too. */
  net_sim_remove_node_by_name(s, nodenames[0]);

  /* Re-add the node */
  (void)net_sim_find_dncp(s, nodenames[0]);

  handle_connections(s, &nodeconnections[0], 2); /* Two first ones are needed */

  /* As the original node and the new node will wind up with exactly same
   * update #, but potentially wildly different timestamp on other nodes,
   * accept time errors in this case.
   * (Shouldn't accept in general case, however.)
   */

  s->accept_time_errors = true;

  SIM_WHILE(s, 10000, !net_sim_is_converged(s));

  net_sim_uninit(s);
}

void hncp_bird14()
{
  net_sim_s s;

  net_sim_init(&s);
  raw_bird14(&s);
}

void hncp_bird14_u()
{
  net_sim_s s;

  net_sim_init(&s);
  s.fake_unicast = true;
  raw_bird14(&s);
}

void hncp_bird14_us()
{
  net_sim_s s;

  net_sim_init(&s);
  s.fake_unicast_is_reliable_stream = true;
  raw_bird14(&s);
}

void hncp_bird14_u_us()
{
  net_sim_s s;

  net_sim_init(&s);
  s.fake_unicast = true;
  s.fake_unicast_is_reliable_stream = true;
  raw_bird14(&s);
}

void hncp_bird14_unique()
{
  net_sim_s s;

  net_sim_init(&s);
  s.use_global_iids = true;
  raw_bird14(&s);
}

static void raw_hncp_tube(net_sim s, unsigned int num_nodes, bool no_conflicts)
{
  /* A LOT of routers connected in a tube (R1 R2 R3 .. RN). */
  unsigned int i;
  dncp_node_identifier_s h1, h2;

  memset(&h1, 0, sizeof(h1));
  memset(&h2, 1, sizeof(h2));

  s->disable_sd = true;
  s->disable_multicast = true;
  s->disable_pa = true; /* TBD we SHOULD care about pa but it does not work :p */
  if (no_conflicts)
    s->del_neighbor_is_error = true;

  for (i = 0 ; i < num_nodes-1 ; i++)
    {
      char buf[128];

      sprintf(buf, "node%d", i);
      dncp n1 = net_sim_find_dncp(s, buf);
      /* Add intentional router ID collisions at nodes 0, 1,3 and 2 and 4 */
      if (!no_conflicts)
        {
          if (i == 0 || i == 1 || i == 3)
            dncp_set_own_node_identifier(n1, &h1);
          else if (i == 2 || i == 4)
            dncp_set_own_node_identifier(n1, &h2);
        }

      sprintf(buf, "node%d", i+1);
      dncp n2 = net_sim_find_dncp(s, buf);

      dncp_ep_i l1 = net_sim_dncp_find_link_by_name(n1, "down");
      dncp_ep_i l2 = net_sim_dncp_find_link_by_name(n2, "up");
      /* Asymmetric keepalive setup; l2 sends them 'normally', and l1
       * very aggressively. */
      l1->conf.keepalive_interval = HNCP_KEEPALIVE_INTERVAL / 20;
      net_sim_set_connected(l1, l2, true);
      net_sim_set_connected(l2, l1, true);
    }
  SIM_WHILE(s, 100000, !net_sim_is_converged(s));

  sput_fail_unless(net_sim_find_dncp(s, "node0")->nodes.avl.count >= num_nodes,
                   "enough nodes");
  for (i = 0 ; i < num_nodes ; i++)
    {
      char buf[128];

      sprintf(buf, "node%d", i);
      dncp n = net_sim_find_dncp(s, buf);
      /* <= 5 may have up to 2 drops; >5 0. */
      if (i <= 5)
        sput_fail_unless(n->num_neighbor_dropped <= 2, "few drops (start)");
      else
        sput_fail_unless(!n->num_neighbor_dropped, "no drops (end)");


    }

  net_sim_uninit(s);
  L_NOTICE("finished in %lld ms", (long long)hnetd_time() - s->start);
}

#define NS_LENGTH (sizeof(dncp_t_node_state_s) + HNCP_HASH_LEN + HNCP_NI_LEN)

void hncp_tube_small(void)
{
  net_sim_s s;

  net_sim_init(&s);
  raw_hncp_tube(&s, 6, false);

  /* This is arbitrary result based on test runs. Raise it if you have
   * _a good reason_ to think the value is too low. */
  sput_fail_unless((hnetd_time() - s.start) < 10 * HNETD_TIME_PER_SECOND,
                   "fastish convergence");
}


/* Intentionally pick a number that is close to IPv6 MTU / node state
 * (network state hash etc left as rounding errors) */
#define MEDIUM_TUBE_LENGTH 1000 / NS_LENGTH

void hncp_tube_medium(void)
{
  net_sim_s s;

  net_sim_init(&s);
  raw_hncp_tube(&s, MEDIUM_TUBE_LENGTH, false);

  /* This is arbitrary result based on test runs. Raise it if you have
   * _a good reason_ to think the value is too low. */

  /* With conflicts, it may take 48 seconds for the system to even
   * realize something is wrong due to (potentially) long keepalive
   * interval times multiplier. */
  sput_fail_unless((hnetd_time() - s.start) < 70 * HNETD_TIME_PER_SECOND,
                   "fastish convergence");

}

void hncp_tube_medium_nc(void)
{
  net_sim_s s;

  net_sim_init(&s);
  raw_hncp_tube(&s, MEDIUM_TUBE_LENGTH, true);


  /* This is arbitrary result based on test runs. Raise it if you have
   * _a good reason_ to think the value is too low. */

  /* Without conflicts, this should finish faster. */
  sput_fail_unless((hnetd_time() - s.start) < 30 * HNETD_TIME_PER_SECOND,
                   "fastish convergence");
}

  /* Intentionally pick a number that is >> IPv6 MTU / node state
   * (network state hash etc left as rounding errors) */
#define BIG_TUBE_LENGTH 3000 / NS_LENGTH

void hncp_tube_beyond_multicast_nc(void)
{
  net_sim_s s;

  net_sim_init(&s);
  raw_hncp_tube(&s, BIG_TUBE_LENGTH, true);
}

void hncp_tube_beyond_multicast_unique(void)
{
  net_sim_s s;

  net_sim_init(&s);
  s.use_global_iids = true;
  raw_hncp_tube(&s, BIG_TUBE_LENGTH, false);
}

/* Note: As we play with bitmasks,
   NUM_MONKEY_ROUTERS * NUM_MONKEY_PORTS^2 <= 31
*/
#define NUM_MONKEY_ROUTERS 7
#define NUM_MONKEY_PORTS 2
#define NUM_MONKEY_ITERATIONS 1000

dncp net_sim_find_dncp_n(net_sim s, int i)
{
  char n[3];
  sprintf(n, "n%d", i);
  return net_sim_find_dncp(s, n);
}

dncp_ep_i net_sim_dncp_find_link_n(dncp o, int i)
{
  char n[3];
  sprintf(n, "l%d", i);
  return net_sim_dncp_find_link_by_name(o, n);
}

#define MONKEY_MASK(p1,r2,p2) \
  (1 << (r2 + (p1 + p2 * NUM_MONKEY_PORTS) * NUM_MONKEY_ROUTERS))

#define MONKEY_CONNECTED(ma,r1,p1,r2,p2)        \
  (ma[r1] & MONKEY_MASK(p1, r2, p2))

#define MONKEY_SET_CONNECTED(ma,r1,p1,r2,p2)    \
  ma[r1] |= MONKEY_MASK(p1, r2, p2)

#define MONKEY_CLEAR_CONNECTED(ma,r1,p1,r2,p2)  \
  ma[r1] &= ~MONKEY_MASK(p1, r2, p2)


dncp_t_neighbor monkey_neighbor(dncp n1, dncp_ep_i l1,
                                          dncp n2, dncp_ep_i l2)
{
  dncp_t_neighbor nh;
  struct tlv_attr *a;

  dncp_node_for_each_tlv_with_type(n1->own_node, a,
                                   DNCP_T_NEIGHBOR)
    if ((nh = dncp_tlv_neighbor(n1, a)))
      {
        if (nh->link_id != l1->iid)
          continue;
        if (nh->neighbor_link_id != l2->iid)
          continue;
        if (memcmp(dncp_tlv_get_node_identifier(n1, nh),
                   &n2->own_node->node_identifier,
                   HNCP_NI_LEN))
          continue;
        return nh;
      }
  return NULL;
}

bool monkey_ok(int *ma,
               dncp n1, dncp_ep_i l1, dncp n2, dncp_ep_i l2,
               int i, int p1, int j, int p2)
{
  bool should_be_connected =
    MONKEY_CONNECTED(ma, i, p1, j, p2) &&
    MONKEY_CONNECTED(ma, j, p2, i, p1) && i != j;

  /* Look at the _published_ state only. */
  dncp_t_neighbor nh1 = monkey_neighbor(n1, l1, n2, l2);
  bool found1 = nh1 && dncp_node_find_neigh_bidir(n1->own_node, nh1);
  dncp_t_neighbor nh2 = monkey_neighbor(n2, l2, n1, l1);
  bool found2 = nh2 && dncp_node_find_neigh_bidir(n2->own_node, nh2);

  if (found1 != found2)
    {
      L_DEBUG("monkey_converged %d/%d <> %d/%d mismatch (%s <=> %s)",
              i, p1, j, p2,
              found1 ? "bidir" : nh1 ? "unidir" : "-",
              found2 ? "bidir" : nh2 ? "unidir" : "-");
      return false;
    }

  bool found = found1 && found2;
  if (!found != !should_be_connected)
    {
      L_DEBUG("monkey_converged %d/%d <=> %d/%d %sconnected?!?",
              i, p1, j, p2,
              should_be_connected ? "dis" : "");
      return false;
    }
  return true;
}

bool monkey_converged(net_sim s, int *ma, int *broken)
{
  int i, j, p1, p2;
  net_node n;

  /* First off, cheap checks. */
  list_for_each_entry(n, &s->nodes, lh)
    {
      if (n->d->network_hash_dirty)
        return false;
    }

  if (broken[0] >= 0)
    {
      i = broken[0];
      p1 = broken[1];
      j = broken[2];
      p2 = broken[3];
      dncp n1 = net_sim_find_dncp_n(s, i);
      dncp n2 = net_sim_find_dncp_n(s, j);
      dncp_ep_i l1 = net_sim_dncp_find_link_n(n1, p1);
      dncp_ep_i l2 = net_sim_dncp_find_link_n(n2, p2);
      if (!monkey_ok(ma, n1, l1, n2, l2, i, p1, j, p2))
        return false;
    }
  for (i = 0 ; i < NUM_MONKEY_ROUTERS ; i++)
    {
      dncp n1 = net_sim_find_dncp_n(s, i);
      for (j = 0 ; j < NUM_MONKEY_ROUTERS ; j++)
        {
          dncp n2 = net_sim_find_dncp_n(s, j);

          for (p1 = 0 ; p1 < NUM_MONKEY_PORTS ; p1++)
            {
              dncp_ep_i l1 = net_sim_dncp_find_link_n(n1, p1);

              for (p2 = 0 ; p2 < NUM_MONKEY_PORTS ; p2++)
                {
                  dncp_ep_i l2 = net_sim_dncp_find_link_n(n2, p2);
                  if (!monkey_ok(ma, n1, l1, n2, l2, i, p1, j, p2))
                    {
                      broken[0] = i;
                      broken[1] = p1;
                      broken[2] = j;
                      broken[3] = p2;
                      return false;
                    }
                }
            }
        }
    }
  broken[0] = -1;
  return true;
}

#if L_LEVEL >= 7
void monkey_debug_print(net_sim s, int *ma)
{
  int r1, r2, p1, p2;
  for (r1 = 0 ; r1 < NUM_MONKEY_ROUTERS ; r1++)
    {
      dncp n1 = net_sim_find_dncp_n(s, r1);
      for (p1 = 0 ; p1 < NUM_MONKEY_PORTS ; p1++)
        {
          dncp_ep_i l1 = net_sim_dncp_find_link_n(n1, p1);
          int tot = l1->trickle.num_skipped + l1->trickle.num_sent;

          if (tot)
            L_DEBUG("%d/%d - trickle %d/%d (%.2f%%)",
                    r1, p1, l1->trickle.num_sent, tot,
                    100.0 * l1->trickle.num_sent / tot);
        }
    }
  for (r1 = 0 ; r1 < NUM_MONKEY_ROUTERS ; r1++)
    {
      dncp n1 = net_sim_find_dncp_n(s, r1);
      for (p1 = 0 ; p1 < NUM_MONKEY_PORTS ; p1++)
        {
          dncp_ep_i l1 = net_sim_dncp_find_link_n(n1, p1);
          for (r2 = r1+1 ; r2 < NUM_MONKEY_ROUTERS ; r2++)
            {
              dncp n2 = net_sim_find_dncp_n(s, r2);
              for (p2 = 0 ; p2 < NUM_MONKEY_PORTS ; p2++)
                {
                  dncp_ep_i l2 = net_sim_dncp_find_link_n(n2, p2);
                  L_DEBUG("%d/%d %s%s-%s%s %d/%d",
                          r1, p1,
                          MONKEY_CONNECTED(ma, r2, p2, r1, p1) ? "<" : " ",
                          monkey_neighbor(n2, l2, n1, l1) ? "(" : " ",
                          monkey_neighbor(n1, l1, n2, l2) ? ")" : " ",
                          MONKEY_CONNECTED(ma, r1, p1, r2, p2) ? ">" : " ",
                          r2, p2);
                }
            }
        }
    }
}
#else
#define monkey_debug_print(s,ma)
#endif /* L_LEVEL >= L_DEBUG */

void hncp_random_monkey(void)
{
  /* This is a sanity checker for the neighbor graph of HNCP.
   * Notably, it involves bunch of monkeys that do random connections.
   *
   * Eventually, the state should always converge in something sane. */
  net_sim_s s;
  int ma[NUM_MONKEY_ROUTERS];
  int broken[4] = {-1, 0, 0, 0};
  int i;

  memset(ma, 0, sizeof(ma));
  net_sim_init(&s);
  s.disable_multicast = true;
  s.disable_sd = true; /* we don't care about sd */
  s.disable_pa = true; /* TBD we SHOULD care about pa but it does not work :p */
  /* Ensure that the routers + their links have consistent ordering. */
  /* This way, debug and non debug builds have same output even
   * with the monkey_debug_print occuring every round.. */
  int r1, p1;
  for (r1 = 0 ; r1 < NUM_MONKEY_ROUTERS ; r1++)
    {
      dncp n1 = net_sim_find_dncp_n(&s, r1);
      for (p1 = 0 ; p1 < NUM_MONKEY_PORTS ; p1++)
        net_sim_dncp_find_link_n(n1, p1);
    }

  /* s.use_global_iids = true; */
  for (i = 0 ; i < NUM_MONKEY_ITERATIONS ; i++)
    {
      /* Do random connect/disconnect */
      int r1 = random() % NUM_MONKEY_ROUTERS;
      dncp n1 = net_sim_find_dncp_n(&s, r1);
      int p1 = random() % NUM_MONKEY_PORTS;
      dncp_ep_i l1 = net_sim_dncp_find_link_n(n1, p1);

      int r2 = random() % NUM_MONKEY_ROUTERS;
      dncp n2 = net_sim_find_dncp_n(&s, r2);
      int p2 = random() % NUM_MONKEY_PORTS;
      dncp_ep_i l2 = net_sim_dncp_find_link_n(n2, p2);
      bool is_connect = random() % 2;

      if (is_connect)
          MONKEY_SET_CONNECTED(ma, r1, p1, r2, p2);
      else
          MONKEY_CLEAR_CONNECTED(ma, r1, p1, r2, p2);
      net_sim_set_connected(l1, l2, is_connect);

      monkey_debug_print(&s, ma);
      L_DEBUG("hncp_random_monkey iteration #%d: %d/%d->%d/%d %s",
              i, r1, p1, r2, p2, is_connect ? "connected" : "disconnected");
      hnetd_time_t t = hnetd_time();

      /* Wait a second between topology changes. */
      SIM_WHILE(&s, 1000, hnetd_time() < (t + 1000));

      if (!monkey_converged(&s, ma, broken))
        {
          SIM_WHILE(&s, 100000, !monkey_converged(&s, ma, broken));
          if (!monkey_converged(&s, ma, broken))
            {
              /* Print out the connections */
              monkey_debug_print(&s, ma);
              break;
            }
        }
    }
  net_sim_uninit(&s);

}

#define test_setup() srandom(seed)
#define maybe_run_test(fun) sput_maybe_run_test(fun, test_setup())

int main(__unused int argc, __unused char **argv)
{
#ifdef hnetd_time
#undef hnetd_time
#endif /* hnetd_time */
  int seed = (int)hnetd_time();
  int c;

  while ((c = getopt(argc, argv, "r:")) > 0)
    {
      switch (c)
        {
        case 'r':
          seed = atoi(optarg);
          break;
        }
    }
  argc -= optind;
  argv += optind;

  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp_net", LOG_CONS | LOG_PERROR, LOG_DAEMON);

  fprintf(stderr, "Starting with random seed %d\n", seed);
  sput_start_testing();
  sput_enter_suite("hncp_net"); /* optional */
  maybe_run_test(hncp_two);
  maybe_run_test(hncp_bird14);
  maybe_run_test(hncp_bird14_u);
  maybe_run_test(hncp_bird14_us);
  maybe_run_test(hncp_bird14_u_us);
  maybe_run_test(hncp_bird14_unique);
  maybe_run_test(hncp_tube_small);
  maybe_run_test(hncp_tube_medium);
  maybe_run_test(hncp_tube_medium_nc);
  maybe_run_test(hncp_tube_beyond_multicast_nc);
  maybe_run_test(hncp_tube_beyond_multicast_unique);
  maybe_run_test(hncp_random_monkey);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
