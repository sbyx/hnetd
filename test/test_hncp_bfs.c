#ifdef L_LEVEL
#undef L_LEVEL
#endif

#define L_LEVEL 7

#include "../src/hncp_routing.c"
#include "../src/iface.c"
#include "../src/hncp_proto.c"

#include "sput.h"
#include "smock.h"


void pa_data_subscribe(__unused struct pa_data *d, __unused struct pa_data_user *u){}
void platform_set_owner(__unused struct iface *c, __unused bool enable) {}
int platform_init(__unused struct pa_data *data, __unused const char *pd_socket) { return 0; }
void platform_set_address(__unused struct iface *c, __unused struct iface_addr *addr, __unused bool enable) {}
void platform_set_route(__unused struct iface *c, __unused struct iface_route *addr, __unused bool enable) {}
void platform_iface_free(__unused struct iface *c) {}
void platform_set_internal(__unused struct iface *c, __unused bool internal) {}
void platform_filter_prefix(__unused struct iface *c, __unused const struct prefix *p, __unused bool enable) {}
void platform_iface_new(__unused struct iface *c, __unused const char *handle) { c->platform = (void*)1; }
void platform_set_dhcpv6_send(__unused struct iface *c, __unused const void *dhcpv6_data, __unused size_t len,
		__unused const void *dhcp_data, __unused size_t len4) {}
void platform_set_prefix_route(__unused const struct prefix *p, __unused bool enable) {}

void hncp_bfs_one(void)
{
	hncp hncp = hncp_create();

	/* Get rid of version, as synthesizing versions for other
	 * routers is a bore */
	(void)hncp_remove_tlvs_by_type(hncp, HNCP_T_VERSION);

	hncp_bfs bfs = hncp_routing_create(hncp, NULL);

	hncp_hash_s h = {{0}};
	hncp_node n0 = hncp->own_node;
	h.buf[0] = 1;
	hncp_node n1 = hncp_find_node_by_hash(hncp, &h, true);
	h.buf[0] = 2;
	hncp_node n2 = hncp_find_node_by_hash(hncp, &h, true);
	h.buf[0] = 3;
	hncp_node n3 = hncp_find_node_by_hash(hncp, &h, true);
	h.buf[0] = 4;
	hncp_node n4 = hncp_find_node_by_hash(hncp, &h, true);

	// Create a network topology with us + 4 routers:
	// US -- N1 -- N2 |- N4
	//    \      /
	//       N3
	// with uni-directional neighbor N2 - N4 and PDs on N2 and N3

	hncp_link l1 = hncp_find_link_by_name(hncp, "l1", true);
	hncp_link l3 = hncp_find_link_by_name(hncp, "l3", true);
	struct iface *i1 = iface_create("l1", "l1", 0);
	struct iface *i3 = iface_create("l3", "l3", 0);

	hncp_t_link_id_s lid1 = {n1->node_identifier_hash, 0};
	_heard(l1, &lid1, (struct in6_addr*)n1->node_identifier_hash.buf);

	hncp_t_link_id_s lid3 = {n3->node_identifier_hash, 0};
	_heard(l3, &lid3, (struct in6_addr*)n3->node_identifier_hash.buf);

	// TLV foo
	struct tlv_buf b = {NULL, NULL, 0, NULL};
	hncp_t_node_data_neighbor_s n;
	struct __attribute__((__packed__)) {
		hncp_t_delegated_prefix_header_s hdr;
		struct in6_addr prefix;
	} dp = {
		.prefix = {{{0x20, 0x01, 0xdb, 0x8}}}
	};

	struct __attribute__((__packed__)) {
		hncp_t_assigned_prefix_header_s hdr;
		struct in6_addr prefix;
	} ap = {
		.prefix = {{{0x20, 0x01, 0xdb, 0x8}}}
	};


	tlv_buf_init(&b, 0);

	// N0 link 0
	n.link_id = htonl(l1->iid);
	n.neighbor_link_id = htonl(0);
	n.neighbor_node_identifier_hash = n1->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = htonl(l1->iid);
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 0;
	ap.prefix.s6_addr[7] = 0;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	// N0 link 1
	n.link_id = htonl(l3->iid);
	n.neighbor_link_id = htonl(0);
	n.neighbor_node_identifier_hash = n3->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = 0;
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 0;
	ap.prefix.s6_addr[7] = 1;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	n0->tlv_container = tlv_memdup(b.head);


	tlv_buf_init(&b, 0);

	// N1 link 0
	n.link_id = htonl(0);
	n.neighbor_link_id = htonl(l1->iid);
	n.neighbor_node_identifier_hash = n0->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N1 link 1
	n.link_id = htonl(1);
	n.neighbor_link_id =htonl(0);
	n.neighbor_node_identifier_hash = n2->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = htonl(0);
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 1;
	ap.prefix.s6_addr[7] = 1;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	n1->tlv_container = tlv_memdup(b.head);


	tlv_buf_init(&b, 0);

	// N2 link 0
	n.link_id = htonl(0);
	n.neighbor_link_id = htonl(1);
	n.neighbor_node_identifier_hash = n1->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N2 link 1
	n.link_id = htonl(1);
	n.neighbor_link_id = htonl(1);
	n.neighbor_node_identifier_hash = n3->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N2 link 2
	n.link_id = htonl(2);
	n.neighbor_link_id = htonl(0);
	n.neighbor_node_identifier_hash = n4->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = htonl(2);
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 2;
	ap.prefix.s6_addr[7] = 2;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	void *cookie = tlv_nest_start(&b, HNCP_T_EXTERNAL_CONNECTION, 0);
	dp.hdr.ms_preferred_at_origination = 7200000;
	dp.hdr.ms_valid_at_origination = 7200000;
	dp.hdr.prefix_length_bits = 48;
	tlv_put(&b, HNCP_T_DELEGATED_PREFIX, &dp, sizeof(dp));
	tlv_nest_end(&b, cookie);

	n2->tlv_container = tlv_memdup(b.head);


	tlv_buf_init(&b, 0);

	// N3 link 0
	n.link_id = htonl(0);
	n.neighbor_link_id = htonl(l3->iid);
	n.neighbor_node_identifier_hash = n0->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N3 link 1
	n.link_id = htonl(1);
	n.neighbor_link_id = htonl(1);
	n.neighbor_node_identifier_hash = n2->node_identifier_hash;
	tlv_put(&b, HNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = htonl(1);
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 3;
	ap.prefix.s6_addr[7] = 1;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	dp.hdr.ms_preferred_at_origination = 7200000;
	dp.hdr.ms_valid_at_origination = 7200000;
	dp.hdr.prefix_length_bits = 48;
	dp.prefix.s6_addr[5] = 1;
	cookie = tlv_nest_start(&b, HNCP_T_EXTERNAL_CONNECTION, 0);
	tlv_put(&b, HNCP_T_DELEGATED_PREFIX, &dp, sizeof(dp));
	tlv_nest_end(&b, cookie);

	n3->tlv_container = tlv_memdup(b.head);

	tlv_buf_init(&b, 0);
	n4->tlv_container = tlv_memdup(b.head);


	hncp_routing_run(&bfs->t);

	struct iface_route up31 = {.from = {.prefix = dp.prefix, .plen = 48}, .via = *((struct in6_addr*)n3->node_identifier_hash.buf), .metric = 10000 + 1};
	sput_fail_unless(!!vlist_find(&i3->routes, &up31, &up31, node), "uplink 3 #1");

	struct iface_route up32 = {.from = {.plen = 128}, .via = *((struct in6_addr*)n3->node_identifier_hash.buf), .metric = 10000 + 1};
	sput_fail_unless(!!vlist_find(&i3->routes, &up32, &up32, node), "uplink 3 #2");

	dp.prefix.s6_addr[5] = 0;
	struct iface_route up11 = {.from = {.prefix = dp.prefix, .plen = 48}, .via = *((struct in6_addr*)n1->node_identifier_hash.buf), .metric = 10000 + 2};
	sput_fail_unless(!!vlist_find(&i1->routes, &up11, &up11, node), "uplink 1 #1");

	struct iface_route up12 = {.from = {.plen = 128}, .via = *((struct in6_addr*)n1->node_identifier_hash.buf), .metric = 10000 + 2};
	sput_fail_unless(!!vlist_find(&i1->routes, &up12, &up12, node), "uplink 1 #2");
}


int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp_pa", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hncp_bfs"); /* optional */
  sput_run_test(hncp_bfs_one);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();

}
