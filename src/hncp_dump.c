/*
 * Copyright (c) 2015 Cisco Systems, Inc.
 */

/* TBD: This whole module is full of potential for nastiness, given it
 * does not do any input validation (length of TLVs) => it is a DoS
 * vector. Should fix (and probably unify TLV validation code in
 * general). -MSt */
#include "hncp_dump.h"

#include "dncp_i.h"
#include "hncp_i.h"
#include "platform.h"

#include <libubox/blobmsg_json.h>

#define hd_a(test, err) do{if(!(test)) {err;}}while(0)

static char __hexhash[HNCP_HASH_LEN*2 + 1];
#define hd_hash_to_hex(hash) hexlify(__hexhash, (hash)->buf, HNCP_HASH_LEN)
#define hd_ni_to_hex(hash) hexlify(__hexhash, (hash)->buf, HNCP_NI_LEN)

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
	hncp_t_node_address ra = (hncp_t_node_address) tlv_data(tlv);
	if(tlv_len(tlv) != 20)
		return -1;
	hd_a(!blobmsg_add_string(b, "address", ADDR_REPR(&ra->address)), return -1);
	hd_a(!blobmsg_add_u32(b, "link-id", ntohl(ra->ep_id)), return -1);
	return 0;
}

static int hd_node_externals_dp(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_delegated_prefix_header dh;
	unsigned int plen;
	struct prefix p;
	struct tlv_attr *a;
	unsigned int flen;
	int ret = -1;
	struct blob_buf dps = {NULL, NULL, 0, NULL};

	if (!(dh = hncp_tlv_dp(tlv)))
		return -1;
	memset(&p, 0, sizeof(p));
	p.plen = dh->prefix_length_bits;
	plen = ROUND_BITS_TO_BYTES(p.plen);
	memcpy(&p, dh->prefix_data, plen);
	hd_a(!blobmsg_add_string(b, "prefix", PREFIX_REPR(&p)), return -1);
	hd_a(!blobmsg_add_u64(b, "valid", ntohl(dh->ms_valid_at_origination)), return -1);
	hd_a(!blobmsg_add_u64(b, "preferred", ntohl(dh->ms_preferred_at_origination)), return -1);

	flen = ROUND_BYTES_TO_4BYTES(sizeof(*dh) +
			ROUND_BITS_TO_BYTES(dh->prefix_length_bits));

	hd_a(!blob_buf_init(&dps, BLOBMSG_TYPE_ARRAY), return -1);
	if (tlv_len(tlv) > flen) {
		tlv_for_each_in_buf(a, tlv_data(tlv) + flen, tlv_len(tlv) - flen) {
			hncp_t_prefix_policy d = tlv_data(a);
			if (tlv_id(a) != HNCP_T_PREFIX_POLICY || tlv_len(a) < 1)
				continue;

			plen = ROUND_BITS_TO_BYTES(d->type);
			if (d->type <= 128 && tlv_len(a) >= 1 + plen) {
				p.plen = d->type;
				memcpy(&p.prefix, d->id, plen);
				memset(&p.prefix.s6_addr[plen], 0, sizeof(p.prefix) - plen);
				hd_a(!blobmsg_add_string(&dps, NULL, PREFIX_REPR(&p)), return -1);
			} else if (d->type == 129 && tlv_len(a) >= 2 && d->id[tlv_len(a) - 2] == 0) {
				hd_a(!blobmsg_add_string(&dps, NULL, (const char*)d->id), return -1);
			}
		}
	}
	hd_a(!blobmsg_add_named_blob(b, "domains", dps.head), goto err);
	ret = 0;
err:
	blob_buf_free(&dps);
	return ret;
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
	dncp_t_neighbor nh;

	if (!(nh = dncp_tlv_neighbor2(tlv, HNCP_NI_LEN)))
		return -1;
	hd_a(!blobmsg_add_string(b, "node-id", hd_ni_to_hex(dncp_tlv_get_node_id2(nh, HNCP_NI_LEN))), return -1);
	hd_a(!blobmsg_add_u32(b, "local-link", ntohl(nh->ep_id)), return -1);
	hd_a(!blobmsg_add_u32(b, "neighbor-link", ntohl(nh->neighbor_ep_id)), return -1);
	return 0;
}

static int hd_node_prefix(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_assigned_prefix_header ah;
	int plen;
	struct prefix p;

	if (!(ah = hncp_tlv_ap(tlv)))
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
	hd_a(!blobmsg_add_u32(b, "link", ntohl(ah->ep_id)), return -1);
	return 0;
}

static int hd_node_pim_bp(struct tlv_attr *tlv, struct blob_buf *b)
{
	hncp_t_pim_border_proxy bp = (hncp_t_pim_border_proxy)tlv_data(tlv);
	if(tlv_len(tlv) != 18)
		return -1;

	hd_a(!blobmsg_add_string(b, "address", ADDR_REPR(&bp->addr)), return -1);
	hd_a(!blobmsg_add_u16(b, "port", bp->port), return -1);
	return 0;
}

static int hd_node_ssid(struct tlv_attr *tlv, struct blob_buf *b)
{
	if(tlv_len(tlv) != sizeof(hncp_t_wifi_ssid_s))
		goto inv;

	hncp_t_wifi_ssid ssid = (hncp_t_wifi_ssid) tlv->data;
	if(ssid->password[HNCP_WIFI_PASSWORD_LEN] != 0 ||
			ssid->ssid[HNCP_WIFI_SSID_LEN] != 0)
		goto inv;

	hd_a(!blobmsg_add_string(b, "ssid", (char *)ssid->ssid), return -1);
	hd_a(!blobmsg_add_string(b, "password", (char *)ssid->password), return -1);
	return 0;
inv:
	hd_a(!blobmsg_add_u32(b, "invalid", 1), return -1);
	return 0;
}


static int hd_node(dncp o, dncp_node n, struct blob_buf *b)
{
	struct tlv_attr *tlv;
	hncp_t_version v;
	hncp_t_node_name na;
	struct blob_buf prefixes = {NULL, NULL, 0, NULL},
			neighbors = {NULL, NULL, 0, NULL},
			externals = {NULL, NULL, 0, NULL},
			addresses = {NULL, NULL, 0, NULL},
			zones = {NULL, NULL, 0, NULL},
			pim_bps = {NULL, NULL, 0, NULL},
			hncp_wifi = {NULL, NULL, 0, NULL};
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
	hd_a(!blob_buf_init(&pim_bps, BLOBMSG_TYPE_ARRAY), goto bp);
	hd_a(!blob_buf_init(&hncp_wifi, BLOBMSG_TYPE_ARRAY), goto aw);

	dncp_node_for_each_tlv(n, tlv) {
		switch (tlv_id(tlv)) {
			case HNCP_T_ASSIGNED_PREFIX:
				hd_do_in_table(&prefixes, NULL, hd_node_prefix(tlv, &prefixes), goto err);
				break;
			case DNCP_T_NEIGHBOR:
				hd_do_in_table(&neighbors, NULL, hd_node_neighbor(tlv, &neighbors), goto err);
				break;
			case HNCP_T_EXTERNAL_CONNECTION:
				hd_do_in_table(&externals, NULL, hd_node_external(tlv, &externals), goto err);
				break;
			case HNCP_T_NODE_ADDRESS:
				hd_do_in_table(&addresses, NULL, hd_node_address(tlv, &addresses), goto err);
				break;
			case HNCP_T_VERSION:
				v = (hncp_t_version)tlv_data(tlv);
				if(tlv_len(tlv) > sizeof(hncp_t_version_s)) {
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
			case HNCP_T_NODE_NAME:
				na = tlv_data(tlv);
				hd_a(!hd_push_string(b, "router-name", na->name, na->name_length), goto err);
				break;
			case HNCP_T_DOMAIN_NAME:
				hd_a(!hd_push_dn(b, "domain", tlv_data(tlv), tlv_len(tlv)), goto err);
				break;
			case HNCP_T_PIM_RPA_CANDIDATE:
				hd_a(!blobmsg_add_string(b, "rpa_candidate", ADDR_REPR((struct in6_addr *)tlv_data(tlv))), goto err);
				break;
			case HNCP_T_PIM_BORDER_PROXY:
				hd_do_in_table(&pim_bps, NULL, hd_node_pim_bp(tlv, &pim_bps), goto err);
				break;
			case HNCP_T_SSID:
				hd_do_in_table(&hncp_wifi, NULL, hd_node_ssid(tlv, &hncp_wifi), goto err);
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
	hd_a(!blobmsg_add_named_blob(b, "pim_proxies", pim_bps.head), goto err);
	hd_a(!blobmsg_add_named_blob(b, "ssids", hncp_wifi.head), goto err);
	ret = 0;
err:
	blob_buf_free(&hncp_wifi);
aw:
	blob_buf_free(&pim_bps);
bp:
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
		hd_do_in_table(b, hd_ni_to_hex(&node->node_id), hd_node(o, node,b), return -1);
	return 0;
}

static int hd_links(dncp o, struct blob_buf *b)
{
	dncp_ep ep;
	dncp_for_each_ep(o, ep)
		hd_a(!blobmsg_add_u32(b, ep->ifname, dncp_ep_get_id(ep)), return -1);
	return 0;
}

static int hd_info(dncp o, struct blob_buf *b)
{
	hd_a(!blobmsg_add_u64(b, "time", hd_now), return -1);
	hd_a(!blobmsg_add_string(b, "node-id", hd_ni_to_hex(&o->own_node->node_id)), return -1);
	return 0;
}

platform_rpc_cb hd_cb;
platform_rpc_main hd_main;

static struct hd_rpc_method {
	struct platform_rpc_method m;
	dncp dncp;
} hncp_rpc_dump = {
	{.name = "dump", .cb = hd_cb, .main = hd_main},
	NULL,
};

int hd_main(struct platform_rpc_method *method, __unused int argc, __unused char* const argv[])
{
	return platform_rpc_cli(method->name, NULL);
}

int hd_cb(struct platform_rpc_method *method, __unused const struct blob_attr *in, struct blob_buf *b)
{
	struct hd_rpc_method *m = container_of(method, struct hd_rpc_method, m);
	hd_now = hnetd_time();
	hd_a(!hd_info(m->dncp, b), return -1);
	hd_do_in_table(b, "links", hd_links(m->dncp, b), return -1);
	hd_do_in_table(b, "nodes", hd_nodes(m->dncp, b), return -1);
	return 1;
}

void hd_register_rpc(void)
{
	platform_rpc_register(&hncp_rpc_dump.m);
}

void hd_init(dncp dncp)
{
	hncp_rpc_dump.dncp = dncp;
}
