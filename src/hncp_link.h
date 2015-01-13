#ifndef SRC_HNCP_LINK_H_
#define SRC_HNCP_LINK_H_

#include "dncp.h"
#include "dncp_proto.h"
#include "hncp_proto.h"

struct hncp_link;

enum hncp_link_elected {
	HNCP_LINK_NONE		= 0,
	HNCP_LINK_LEGACY	= 1 << 0,
	HNCP_LINK_HOSTNAMES	= 1 << 1,
	HNCP_LINK_PREFIXDEL	= 1 << 2,
	HNCP_LINK_MDNSPROXY	= 1 << 3,
	HNCP_LINK_ALL		= HNCP_LINK_LEGACY | HNCP_LINK_HOSTNAMES |
							HNCP_LINK_PREFIXDEL | HNCP_LINK_MDNSPROXY,
};

struct hncp_link_config {
	int version;
	int cap_mdnsproxy;
	int cap_prefixdel;
	int cap_hostnames;
	int cap_legacy;
	char agent[32];
};

struct hncp_link_user {
	struct list_head head;
	void (*cb_link)(struct hncp_link_user*, const char *ifname,
			dncp_t_link_id peers, size_t peercnt);
	void (*cb_elected)(struct hncp_link_user*, const char *ifname,
			enum hncp_link_elected elected);
};

struct hncp_link* hncp_link_create(dncp dncp, const struct hncp_link_config *conf);
void hncp_link_destroy(struct hncp_link *l);

void hncp_link_register(struct hncp_link *l, struct hncp_link_user *user);
void hncp_link_unregister(struct hncp_link_user *user);

#endif /* SRC_HNCP_LINK_H_ */
