#include "hncp_trust.h"
#include "sput.h"

#include "local_trust.h"

/* Fake structures to keep pa's default config happy. */
void *iface_register_user;
void *iface_unregister_user;

struct iface* iface_get( __unused const char *ifname )
{
  return NULL;
}

void iface_all_set_dhcp_send(__unused const void *dhcpv6_data, __unused size_t dhcpv6_len,
                             __unused const void *dhcp_data, __unused size_t dhcp_len)
{
}


#include <libubox/md5.h>
hncp_hash create_hash(const uint8_t c){
  md5_ctx_t ctx;
  hncp_hash h = malloc(sizeof(hncp_hash_s));
  md5_begin(&ctx);
  md5_hash(&c, 1, &ctx);
  md5_end(h, &ctx);
  return h;
}

void trust_graph(void){
  hncp o = hncp_create();
  hncp_hash h = &(o->own_node->node_identifier_hash);

  hncp_trust_init(o);
  hncp_trust_graph g = o->trust->my_graph;
  sput_fail_unless(trust_graph_is_trusted(g, h), "I trust myself");

  hncp_hash h1 = create_hash(1);
  hncp_hash h2 = create_hash(2);

  hncp_trust_graph g1 = trust_graph_create(h1);
  sput_fail_if(trust_graph_is_trusted(g, h2) || trust_graph_is_trusted(g1, h), "No trust link yet.");

  hncp_trust_graph g2 = trust_graph_create(h2);
  trust_graph_add_trust_link(g, g1);
  trust_graph_add_trust_link(g1, g2);
  /* here : g => g1 => g2 */
  sput_fail_unless(trust_graph_is_trusted(g, h1), "Direct trust ok");
  sput_fail_unless(trust_graph_is_trusted(g, h2), "Transitive trust ok");
  sput_fail_if(g->marked || g1->marked || g2->marked, "Clean graph after search");

  trust_graph_add_trust_link(g2,g);
  hncp_hash h3 = create_hash(3);
  hncp_trust_graph g3 = trust_graph_create(h3);
  /* here : g => g1 => g2 => g */
  sput_fail_if(trust_graph_is_trusted(g2,h3), "No infinite loop search");
  sput_fail_unless(trust_graph_is_trusted(g2, h), "I'm trusted");
  trust_graph_add_trust_link(g,g3);
  trust_graph_add_trust_link(g3, g1);
  /* here g => g3 => g1 => g2 => g
   *      g => g1 */
  sput_fail_unless(trust_graph_remove_trust_link(g, g3), "Link deletion ok");
  sput_fail_if(trust_graph_remove_trust_link(g, g3), "No deletion for non-existent link");
  /* here g => g1 => g2 => g
   *      g3 => g1 */
  hncp_trust_graph list[2] = {g, g2};
  trust_graph_add_trust_array(g3, list, 2);
  trust_graph_remove_trust_link(g3, g1);
  trust_graph_remove_trust_link(g, g1);
  trust_graph_remove_trust_link(g2, g);
  /* here g1 => g2, g3 => g, g3 => g2 */
  sput_fail_unless(trust_graph_is_trusted(g3, h) && trust_graph_is_trusted(g3, h2) && !trust_graph_is_trusted(g3, h1), "Link replacement ok");;
  trust_graph_add_trust_link(g, g1);
  /* here g=> g1 => g2
   * g3 => g, g3 => g2 */
  sput_fail_unless(trust_graph_is_trusted(g, h2) && trust_graph_is_trusted(g3, h) \
                  && !trust_graph_is_trusted(g, h3), "Graph seems to stay consistent");
  sput_fail_if(g->marked || g1->marked || g2->marked || g3->marked, "Clean graph after search");

  hncp_trust_destroy(o);
  hncp_destroy(o);
  trust_graph_destroy(g1);
  trust_graph_destroy(g2);
  trust_graph_destroy(g3);
  free(h1);
  free(h2);
  free(h3);
}

void hncp_trust_test(void){
  hncp o = hncp_create();
  hncp_hash h = &(o->own_node->node_identifier_hash);
  hncp_trust_init(o);
  //hncp_trust_graph g = o->trust->my_graph;
  sput_fail_unless(hncp_trust_node_trusted(o, h), "I trust myself");

  hncp_hash h1 = create_hash(1);
  hncp_hash h2 = create_hash(2);
  sput_fail_if(hncp_trust_node_trusted(o, h1) || hncp_trust_node_trusts_me(o, h2), "I'm alone");
  hncp_trust_update_graph(o, h1, NULL, 0);
  hncp_hash_s list[2] = {*h, *h1};
  hncp_trust_update_graph(o, h2, list, 2);
  list[0] = *h2;
  hncp_trust_update_graph(o, h1, list, 1);

  hncp_trust_graph g1 = hncp_trust_get_graph_or_create_it(o, h1);
  hncp_trust_graph g2 = hncp_trust_get_graph_or_create_it(o, h2);
  /* here : g1 <=> g2 => g */
  sput_fail_if(g1->trusted || g2->trusted || list_first_entry(&g1->arrows, struct _trusted_list, list)->node != g2, "Consistency check");
  sput_fail_if(hncp_trust_node_trusted(o, h1) || !hncp_trust_node_trusts_me(o, h1), "Distant link insertion ok");

  local_trust_add_trusted_array(o, list, 2);
  hncp_hash h3 = create_hash(3);
  hncp_trust_update_graph(o, h3, h1, 1);
  sput_fail_unless(!hncp_trust_node_trusted(o, h3) && hncp_trust_node_trusts_me(o, h3), "Local insertion ok");
  /* here : g3 => g1 <=> g2 <=> g => g1 */
  sput_fail_unless(local_trust_remove_trusted_hash(o, h2), "Local removal ok");
  sput_fail_if(local_trust_remove_trusted_hash(o, h2), "Removal, bis");
  local_trust_purge_trusted_array(o);
  sput_fail_if(hncp_trust_node_trusted(o, h1) || hncp_trust_node_trusted(o, h2), "Local complete deletion ok");
  local_trust_add_trusted_hash(o, h2);
  /* here : g3 => g1 <=> g2 <=> g */
  sput_fail_unless(hncp_trust_node_trusts_me(o, h3) && !hncp_trust_node_trusted(o, h3), "Inserting again ok");
  hncp_trust_destroy(o);
  hncp_destroy(o);
  free(h1);
  free(h2);
  free(h3);
}


int main(__unused int argc, __unused char **argv)
{
  openlog("test_hncp_trust", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("trust_graph"); /* graph structure & links */
  sput_run_test(trust_graph);
  sput_leave_suite(); /* optional */
  sput_enter_suite("hncp_trust"); /* TLV, local links */
  sput_run_test(hncp_trust_test);
  sput_finish_testing();
  return sput_get_return_value();
}
