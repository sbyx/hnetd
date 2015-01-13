#ifdef L_LEVEL
#undef L_LEVEL
#endif

#define L_LEVEL 7

#include "../src/hncp_routing.c"
#include "../src/iface.c"
#include "../src/dncp_proto.c"
#include "../src/hncp_link.c"

#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;


void pa_data_subscribe(__unused struct pa_data *d, __unused struct pa_data_user *u){}
struct pa_iface* pa_iface_get(__unused struct pa_data *d, __unused const char *ifname, __unused bool goc){ return NULL; }
void pa_core_static_prefix_init(__unused struct pa_static_prefix_rule *rule, __unused const char *ifname,
		__unused const struct prefix* p, __unused bool hard) {};
void pa_core_link_id_init(__unused struct pa_link_id_rule *lrule, __unused const char *ifname,
		__unused uint32_t link_id, __unused uint8_t link_id_len, __unused bool hard) {};
void pa_core_rule_add(__unused struct pa_core *core, __unused struct pa_rule *rule) {};
void pa_core_rule_del(__unused struct pa_core *core, __unused struct pa_rule *rule) {};
void pa_core_iface_addr_init(__unused struct pa_iface_addr *addr, __unused const char *ifname,
		__unused struct in6_addr *address, __unused uint8_t mask, __unused struct prefix *filter) {}
void pa_core_iface_addr_add(__unused struct pa_core *core, __unused struct pa_iface_addr *addr) {}
void pa_core_iface_addr_del(__unused struct pa_core *core, __unused struct pa_iface_addr *addr) {}
void platform_set_owner(__unused struct iface *c, __unused bool enable) {}
int platform_init(__unused dncp hncp, __unused struct pa_data *data, __unused const char *pd_socket) { return 0; }
void platform_set_address(__unused struct iface *c, __unused struct iface_addr *addr, __unused bool enable) {}
void platform_set_route(__unused struct iface *c, __unused struct iface_route *addr, __unused bool enable) {}
void platform_iface_free(__unused struct iface *c) {}
void platform_set_internal(__unused struct iface *c, __unused bool internal) {}
void platform_filter_prefix(__unused struct iface *c, __unused const struct prefix *p, __unused bool enable) {}
void platform_iface_new(__unused struct iface *c, __unused const char *handle) { c->platform = (void*)1; }
void platform_set_dhcpv6_send(__unused struct iface *c, __unused const void *dhcpv6_data, __unused size_t len,
		__unused const void *dhcp_data, __unused size_t len4) {}
void platform_set_prefix_route(__unused const struct prefix *p, __unused bool enable) {}
void platform_restart_dhcpv4(__unused struct iface *c) {}
void platform_set_snat(__unused struct iface *c, __unused const struct prefix *p) {}
void hncp_sd_dump_link_fqdn(__unused hncp_sd sd, __unused dncp_link l, __unused char *buf, __unused size_t buf_len) {}

void hncp_bfs_one(void)
{
	dncp hncp = hncp_create();

	/* Get rid of version, as synthesizing versions for other
	 * routers is a bore */
	(void)dncp_remove_tlvs_by_type(hncp, HNCP_T_VERSION);

	hncp_bfs bfs = hncp_routing_create(hncp, NULL);

	dncp_node_identifier_s h = {{0}};
	dncp_node n0 = hncp->own_node;
	h.buf[0] = 1;
	dncp_node n1 = dncp_find_node_by_node_identifier(hncp, &h, true);
	h.buf[0] = 2;
	dncp_node n2 = dncp_find_node_by_node_identifier(hncp, &h, true);
	h.buf[0] = 3;
	dncp_node n3 = dncp_find_node_by_node_identifier(hncp, &h, true);
	h.buf[0] = 4;
	dncp_node n4 = dncp_find_node_by_node_identifier(hncp, &h, true);

	// Create a network topology with us + 4 routers:
	// US -- N1 -- N2 |- N4
	//    \      /
	//       N3
	// with uni-directional neighbor N2 - N4 and PDs on N2 and N3

	dncp_link l1 = dncp_find_link_by_name(hncp, "l1", true);
	dncp_link l3 = dncp_find_link_by_name(hncp, "l3", true);
	struct iface *i1 = iface_create("l1", "l1", 0);
	struct iface *i3 = iface_create("l3", "l3", 0);

	struct sockaddr_in6 dummy1 = {.sin6_family = AF_INET6};
	memset(&dummy1.sin6_addr, 1, sizeof(dummy1.sin6_addr));
	struct sockaddr_in6 dummy3 = {.sin6_family = AF_INET6};
	memset(&dummy3.sin6_addr, 3, sizeof(dummy3.sin6_addr));
	dncp_t_link_id_s lid1 = {n1->node_identifier, 0};
	_heard(l1, &lid1, &dummy1, false);

	dncp_t_link_id_s lid3 = {n3->node_identifier, 0};
	_heard(l3, &lid3, &dummy3, false);

	// TLV foo
	struct tlv_buf b = {NULL, NULL, 0, NULL};
	dncp_t_node_data_neighbor_s n;
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

	hncp_t_routing_protocol_s rp = { 0, 0 };

	tlv_buf_init(&b, 0);

	// N0 link 0
	n.link_id = l1->iid;
	n.neighbor_link_id = 0;
	n.neighbor_node_identifier = n1->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = l1->iid;
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 0;
	ap.prefix.s6_addr[7] = 0;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	// N0 link 1
	n.link_id = l3->iid;
	n.neighbor_link_id = 0;
	n.neighbor_node_identifier = n3->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = 0;
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 0;
	ap.prefix.s6_addr[7] = 1;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	tlv_put(&b, HNCP_T_ROUTING_PROTOCOL, &rp, sizeof(rp));
	dncp_node_set(n0, 0, 0, tlv_memdup(b.head));


	tlv_buf_init(&b, 0);

	// N1 link 0
	n.link_id = 0;
	n.neighbor_link_id = l1->iid;
	n.neighbor_node_identifier = n0->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N1 link 1
	n.link_id = 1;
	n.neighbor_link_id =0;
	n.neighbor_node_identifier = n2->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = 0;
	ap.hdr.prefix_length_bits = 64;
	ap.prefix.s6_addr[6] = 1;
	ap.prefix.s6_addr[7] = 1;
	tlv_put(&b, HNCP_T_ASSIGNED_PREFIX, &ap, sizeof(ap));

	tlv_put(&b, HNCP_T_ROUTING_PROTOCOL, &rp, sizeof(rp));
	dncp_node_set(n1, 0, 0, tlv_memdup(b.head));


	tlv_buf_init(&b, 0);

	// N2 link 0
	n.link_id = 0;
	n.neighbor_link_id = 1;
	n.neighbor_node_identifier = n1->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N2 link 1
	n.link_id = 1;
	n.neighbor_link_id = 1;
	n.neighbor_node_identifier = n3->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N2 link 2
	n.link_id = 2;
	n.neighbor_link_id = 0;
	n.neighbor_node_identifier = n4->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = 2;
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

	tlv_put(&b, HNCP_T_ROUTING_PROTOCOL, &rp, sizeof(rp));
	dncp_node_set(n2, 0, 0, tlv_memdup(b.head));


	tlv_buf_init(&b, 0);

	// N3 link 0
	n.link_id = 0;
	n.neighbor_link_id = l3->iid;
	n.neighbor_node_identifier = n0->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	// N3 link 1
	n.link_id = 1;
	n.neighbor_link_id = 1;
	n.neighbor_node_identifier = n2->node_identifier;
	tlv_put(&b, DNCP_T_NODE_DATA_NEIGHBOR, &n, sizeof(n));

	ap.hdr.link_id = 1;
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

	tlv_put(&b, HNCP_T_ROUTING_PROTOCOL, &rp, sizeof(rp));
	dncp_node_set(n3, 0, 0, tlv_memdup(b.head));

	tlv_buf_init(&b, 0);
	tlv_put(&b, HNCP_T_ROUTING_PROTOCOL, &rp, sizeof(rp));
	dncp_node_set(n4, 0, 0, tlv_memdup(b.head));


	hncp_routing_run(&bfs->t);

	struct iface_route up31 = {.from = {.prefix = dp.prefix, .plen = 48}, .via = dummy3.sin6_addr, .metric = 10000 + 1};
	sput_fail_unless(!!vlist_find(&i3->routes, &up31, &up31, node), "uplink 3 #1");

	struct iface_route up32 = {.from = {.plen = 128}, .via = dummy3.sin6_addr, .metric = 10000 + 1};
	sput_fail_unless(!!vlist_find(&i3->routes, &up32, &up32, node), "uplink 3 #2");

	dp.prefix.s6_addr[5] = 0;
	struct iface_route up11 = {.from = {.prefix = dp.prefix, .plen = 48}, .via = dummy1.sin6_addr, .metric = 10000 + 2};
	sput_fail_unless(!!vlist_find(&i1->routes, &up11, &up11, node), "uplink 1 #1");

	struct iface_route up12 = {.from = {.plen = 128}, .via = dummy1.sin6_addr, .metric = 10000 + 2};
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
