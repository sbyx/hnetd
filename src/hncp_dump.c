#include "hncp_dump.h"

#include "hncp_routing.h"
#include "hncp_i.h"
#include <libubox/blobmsg_json.h>

#define hd_a(test, err) do{if(!(test)) {err;}}while(0)

static char __hexhash[DNCP_HASH_LEN*2 + 1];
#define hd_hash_to_hex(hash) hexlify(__hexhash, (hash)->buf, DNCP_HASH_LEN)
#define hd_ni_to_hex(hash) hexlify(__hexhash, (hash)->buf, DNCP_NI_LEN)

static hnetd_time_t hd_now; //time hncp_dump is called

#define hd_do_in_nested(buf, type, name, action, err) do { \
		void *__k; \
		if(!(__k =  blobmsg_open_ ## type (buf, name)) || (action)) { \
			if(__k) \
				blobmsg_close_ ## type (buf, __k);\
			do{err;}while(0);\
		}\
		blobmsg_close_ ## type (buf, __k);\
} while(0)

#define hd_do_in_array(buf, name, action, err) hd_do_in_nested(buf, array, name, action, err)
#define hd_do_in_table(buf, name, action, err) hd_do_in_nested(buf, table, name, action, err)

#define blobmsg_add_named_blob(buf, name, attr) blobmsg_add_field(buf, blobmsg_type(attr), name, \
													blobmsg_data(attr), blobmsg_data_len(attr))

static int hd_push_dn(struct blob_buf *b, const char *name, uint8_t *ll, size_t ll_len)
{
	char zone[DNS_MAX_ESCAPED_LEN];
	hd_a(ll2escaped(ll, ll_len, zone, sizeof(zone)) >= 0, return -1);
	hd_a(!blobmsg_add_string(b, name, zone), return -1);
	return 0;
}

static int hd_push_string(struct blob_buf *b, const char *name, void *data, size_t data_len)
{
	char *options;
	hd_a(options = malloc(data_len + 1), return -1);
	memcpy(options, data, data_len);
	options[data_len] = '\0';
	hd_a(!blobmsg_add_string(b, name, options), free(options); return -1;);
	free(options);
	return 0;
}

static int hd_push_hex(struct blob_buf *b, const char *name, void *data, size_t data_len)
{
	char *options;
	hd_a(options = malloc(data_len*2 + 1), return -1);
	hexlify(options, data, data_len);
	options[data_len*2] = '\0';
	hd_a(!blobmsg_add_string(b, name, options), free(options); return -1;);
	free(options);
	return 0;
}

static int hd_node_routing(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_routing_protocol rp = (hncp_t_routing_protocol) tlv_data(tlv);
	if(tlv_len(tlv) != sizeof(hncp_t_routing_protocol_s))
		return -1;

	hd_a(!blobmsg_add_u16(b, "protocol", rp->protocol), return -1);
	hd_a(!blobmsg_add_string(b, "name", hncp_routing_namebyid(rp->protocol)), return -1);
	hd_a(!blobmsg_add_u16(b, "preference", rp->preference), return -1);
	return 0;
}

static int hd_node_zone(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_dns_delegated_zone zo = (hncp_t_dns_delegated_zone) tlv_data(tlv);

	if(tlv_len(tlv) < sizeof(hncp_t_dns_delegated_zone_s))
		return -1;

	hd_a(!blobmsg_add_string(b, "address", ADDR_REPR((struct in6_addr *)&zo->address)), return -1);
	hd_a(!blobmsg_add_u8(b, "search", !!(zo->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_SEARCH)), return -1);
	hd_a(!blobmsg_add_u8(b, "browse", !!(zo->flags & HNCP_T_DNS_DELEGATED_ZONE_FLAG_BROWSE)), return -1);

	if(tlv_len(tlv) == sizeof(hncp_t_dns_delegated_zone_s))
		return 0;

	hd_a(!hd_push_dn(b, "domain", zo->ll, tlv_len(tlv) - sizeof(hncp_t_dns_delegated_zone_s)), return -1);
	return 0;
}

static int hd_node_address(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_router_address ra = (hncp_t_router_address) tlv_data(tlv);
	if(tlv_len(tlv) != 20)
		return -1;
	hd_a(!blobmsg_add_string(b, "address", ADDR_REPR(&ra->address)), return -1);
	hd_a(!blobmsg_add_u32(b, "link-id", ntohl(ra->link_id)), return -1);
	return 0;
}

static int hd_node_externals_dp(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_delegated_prefix_header dh;
	int plen;
	struct prefix p;
	if (!(dh = dncp_tlv_dp(tlv)))
		return -1;
	memset(&p, 0, sizeof(p));
	p.plen = dh->prefix_length_bits;
	plen = ROUND_BITS_TO_BYTES(p.plen);
	memcpy(&p, dh->prefix_data, plen);
	hd_a(!blobmsg_add_string(b, "prefix", PREFIX_REPR(&p)), return -1);
	hd_a(!blobmsg_add_u64(b, "valid", ntohl(dh->ms_valid_at_origination)), return -1);
	hd_a(!blobmsg_add_u64(b, "preferred", ntohl(dh->ms_preferred_at_origination)), return -1);
	return 0;
}

static int hd_node_external(struct tlv_attr *tlv, struct blob_buf *b)
{
	struct tlv_attr *a;
	struct blob_buf dps = {NULL, NULL, 0, NULL};
	int ret = -1;

	hd_a(!blob_buf_init(&dps, BLOBMSG_TYPE_ARRAY), return -1);
	tlv_for_each_attr(a, tlv)
	{
		switch (tlv_id(a)) {
			case HNCP_T_DELEGATED_PREFIX:
				hd_do_in_table(&dps, NULL, hd_node_externals_dp(a, &dps), goto err);
				break;
			case HNCP_T_DHCPV6_OPTIONS:
				hd_a(tlv_len(a) > 0, goto err);
				hd_a(!hd_push_hex(b, "dhcpv6", tlv_data(a), tlv_len(a)), goto err);
				break;
			case HNCP_T_DHCP_OPTIONS:
				hd_a(tlv_len(a) > 0, goto err);
				hd_a(!hd_push_hex(b, "dhcpv4", tlv_data(a), tlv_len(a)), goto err);
				break;
			default:
				break;
		}
	}

	hd_a(!blobmsg_add_named_blob(b, "delegated", dps.head), goto err);
	ret = 0;
err:
	blob_buf_free(&dps);
	return ret;
}

static int hd_node_neighbor(struct tlv_attr *tlv, struct blob_buf *b)
{
	dncp_t_node_data_neighbor nh;

	if (!(nh = dncp_tlv_neighbor(tlv)))
		return -1;
	hd_a(!blobmsg_add_string(b, "node-id", hd_ni_to_hex(&nh->neighbor_node_identifier)), return -1);
	hd_a(!blobmsg_add_u32(b, "local-link", ntohl(nh->link_id)), return -1);
	hd_a(!blobmsg_add_u32(b, "neighbor-link", ntohl(nh->neighbor_link_id)), return -1);
	return 0;
}

static int hd_node_prefix(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_assigned_prefix_header ah;
	int plen;
	struct prefix p;

	if (!(ah = dncp_tlv_ap(tlv)))
		return -1;
	memset(&p, 0, sizeof(p));
	p.plen = ah->prefix_length_bits;
	plen = ROUND_BITS_TO_BYTES(p.plen);
	memcpy(&p, ah->prefix_data, plen);
	hd_a(!blobmsg_add_string(b, "prefix", PREFIX_REPR(&p)), return -1);
	//hd_a(!blobmsg_add_u8(b, "authoritative", !!(ah->flags & HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE)), return -1);
	hd_a(!blobmsg_add_u8(b, "authoritative", 0), return -1); //todo: authoritative should be removed
	//hd_a(!blobmsg_add_u16(b, "priority", HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(ah->flags)), return -1);
	hd_a(!blobmsg_add_u16(b, "priority", HNCP_T_ASSIGNED_PREFIX_FLAG_PRIORITY(ah->flags)), return -1);
	hd_a(!blobmsg_add_u32(b, "link", ntohl(ah->link_id)), return -1);
	return 0;
}

static int hd_node(dncp o, dncp_node n, struct blob_buf *b)
{
	struct tlv_attr *tlv;
	hncp_t_version v;
	struct blob_buf prefixes = {NULL, NULL, 0, NULL},
			neighbors = {NULL, NULL, 0, NULL},
			externals = {NULL, NULL, 0, NULL},
			addresses = {NULL, NULL, 0, NULL},
			zones = {NULL, NULL, 0, NULL},
			routing = {NULL, NULL, 0, NULL};
	int ret = -1;

	hd_a(!blobmsg_add_u32(b, "update", n->update_number), return -1);
	hd_a(!blobmsg_add_u64(b, "age", hd_now - n->origination_time), return -1);
	if(n == o->own_node)
			hd_a(!blobmsg_add_u8(b, "self", 1), return -1);

	hd_a(!blob_buf_init(&prefixes, BLOBMSG_TYPE_ARRAY), goto px);
	hd_a(!blob_buf_init(&neighbors, BLOBMSG_TYPE_ARRAY), goto nh);
	hd_a(!blob_buf_init(&externals, BLOBMSG_TYPE_ARRAY), goto el);
	hd_a(!blob_buf_init(&addresses, BLOBMSG_TYPE_ARRAY), goto ad);
	hd_a(!blob_buf_init(&zones, BLOBMSG_TYPE_ARRAY), goto zo);
	hd_a(!blob_buf_init(&routing, BLOBMSG_TYPE_ARRAY), goto ro);

	dncp_node_for_each_tlv(n, tlv) {
		switch (tlv_id(tlv)) {
			case HNCP_T_ASSIGNED_PREFIX:
				hd_do_in_table(&prefixes, NULL, hd_node_prefix(tlv, &prefixes), goto err);
				break;
			case DNCP_T_NODE_DATA_NEIGHBOR:
				hd_do_in_table(&neighbors, NULL, hd_node_neighbor(tlv, &neighbors), goto err);
				break;
			case HNCP_T_EXTERNAL_CONNECTION:
				hd_do_in_table(&externals, NULL, hd_node_external(tlv, &externals), goto err);
				break;
			case HNCP_T_ROUTER_ADDRESS:
				hd_do_in_table(&addresses, NULL, hd_node_address(tlv, &addresses), goto err);
				break;
			case HNCP_T_VERSION:
				v = (hncp_t_version)tlv_data(tlv);
				if(tlv_len(tlv) > sizeof(hncp_t_version_s)) {
					hd_a(!blobmsg_add_u32(b, "version", v->version), goto err);
					hd_a(!blobmsg_add_u32(b, "cap_m", v->cap_mdnsproxy), goto err);
					hd_a(!blobmsg_add_u32(b, "cap_p", v->cap_prefixdel), goto err);
					hd_a(!blobmsg_add_u32(b, "cap_h", v->cap_hostnames), goto err);
					hd_a(!blobmsg_add_u32(b, "cap_l", v->cap_legacy), goto err);
				}

				if(tlv_len(tlv) > sizeof(hncp_t_version_s))
					hd_a(!hd_push_string(b, "user-agent", v->user_agent, tlv_len(tlv) - sizeof(hncp_t_version_s)), goto err);
				break;
			case HNCP_T_DNS_DELEGATED_ZONE:
				hd_do_in_table(&zones, NULL, hd_node_zone(tlv, &zones), goto err);
				break;
			case HNCP_T_DNS_ROUTER_NAME:
				hd_a(!hd_push_string(b, "router-name", tlv_data(tlv), tlv_len(tlv)), goto err);
				break;
			case HNCP_T_DNS_DOMAIN_NAME:
				hd_a(!hd_push_dn(b, "domain", tlv_data(tlv), tlv_len(tlv)), goto err);
				break;
			case HNCP_T_ROUTING_PROTOCOL:
				hd_do_in_table(&routing, NULL, hd_node_routing(tlv, &routing), goto err);
				break;
			default:
				break;
		}
	}

	hd_a(!blobmsg_add_named_blob(b, "neighbors", neighbors.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "prefixes", prefixes.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "uplinks", externals.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "addresses", addresses.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "zones", zones.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "routing", routing.head), goto err);
	ret = 0;
err:
	blob_buf_free(&routing);
ro:
	blob_buf_free(&zones);
zo:
	blob_buf_free(&addresses);
ad:
	blob_buf_free(&externals);
el:
	blob_buf_free(&neighbors);
nh:
	blob_buf_free(&prefixes);
px:
	return ret;
}

static int hd_nodes(dncp o, struct blob_buf *b)
{
	dncp_node node;
	dncp_for_each_node(o, node)
		hd_do_in_table(b, hd_ni_to_hex(&node->node_identifier), hd_node(o, node,b), return -1);
	return 0;
}

static int hd_links(dncp o, struct blob_buf *b)
{
	dncp_link link;
	vlist_for_each_element(&o->links, link, in_links)
		hd_a(!blobmsg_add_u32(b, link->ifname, link->iid), return -1);
	return 0;
}

static int hd_info(dncp o, struct blob_buf *b)
{
	hd_a(!blobmsg_add_u64(b, "time", hd_now), return -1);
	hd_a(!blobmsg_add_string(b, "node-id", hd_ni_to_hex(&o->own_node->node_identifier)), return -1);
	return 0;
}


int hncp_dump(struct blob_buf *b, dncp o)
{
	hd_now = hnetd_time();
	hd_a(!hd_info(o, b), return -1);
	hd_do_in_table(b, "links", hd_links(o,b), return -1);
	hd_do_in_table(b, "nodes", hd_nodes(o,b), return -1);
	return 0;
}


