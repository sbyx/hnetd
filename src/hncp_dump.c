#include "hncp_dump.h"

#include "hncp_i.h"
#include <libubox/blobmsg_json.h>

#define hd_a(test, err) do{if(!(test)) {err;}}while(0)

static char __hexhash[HNCP_HASH_LEN*2 + 1];
#define hd_hash_to_hex(hash) hexlify(__hexhash, (hash)->buf, HNCP_HASH_LEN)

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
	printf("\n%x\n", ah->flags);
	hd_a(!blobmsg_add_u16(b, "authoritative", !!(ah->flags & HNCP_T_ASSIGNED_PREFIX_FLAG_AUTHORITATIVE)), return -1);
	hd_a(!blobmsg_add_u16(b, "priority", HNCP_T_ASSIGNED_PREFIX_FLAG_PREFERENCE(ah->flags)), return -1);
	hd_a(!blobmsg_add_u32(b, "link", ntohl(ah->link_id)), return -1);
	printf("\n%d\n\n", ah->link_id);
	return 0;
}

static int hd_node_prefixes(hncp_node n, struct blob_buf *b)
{
	struct tlv_attr *tlv;
	hncp_node_for_each_tlv(n, tlv) {
		if (tlv_id(tlv) == HNCP_T_ASSIGNED_PREFIX)
			hd_do_in_table(b, NULL, hd_node_prefix(tlv, b), return -1);
	}
	return 0;
}

static int hd_node(hncp o, hncp_node n, struct blob_buf *b)
{
	hd_a(!blobmsg_add_u32(b, "version", n->version), return -1);
	hd_a(!blobmsg_add_u32(b, "update", n->update_number), return -1);
	hd_a(!blobmsg_add_u64(b, "origination", n->origination_time), return -1);
	if(n == o->own_node)
		hd_a(!blobmsg_add_u8(b, "self", 1), return -1);
	hd_do_in_array(b, "prefixes", hd_node_prefixes(n,b), return -1);
	return 0;
}

static int hd_nodes(hncp o, struct blob_buf *b)
{
	hncp_node node;
	vlist_for_each_element(&o->nodes, node, in_nodes)
		hd_do_in_table(b, hd_hash_to_hex(&node->node_identifier_hash), hd_node(o, node,b), return -1);
	return 0;
}

static int hd_links(hncp o, struct blob_buf *b)
{
	hncp_link link;
	vlist_for_each_element(&o->links, link, in_links)
		hd_a(!blobmsg_add_u32(b, link->ifname, link->iid), return -1);
	return 0;
}

static int hd_info(hncp o, struct blob_buf *b)
{
	hd_a(!blobmsg_add_u64(b, "time", hnetd_time()), return -1);
	hd_a(!blobmsg_add_string(b, "node-id", hd_hash_to_hex(&o->own_node->node_identifier_hash)), return -1);
	return 0;
}


struct blob_buf *hncp_dump(hncp o)
{
	struct blob_buf *b;
	hd_a(b = calloc(1, sizeof(*b)), goto alloc);
	hd_a(!blob_buf_init(b, 0), goto init);
	hd_a(!hd_info(o, b), goto fill);
	hd_do_in_table(b, "links", hd_links(o,b), goto fill);
	hd_do_in_table(b, "nodes", hd_nodes(o,b), goto fill);
	return b;
fill:
	blob_buf_free(b);
init:
	free(b);
alloc:
	return NULL;
}


