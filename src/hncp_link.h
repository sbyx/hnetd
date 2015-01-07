#ifndef SRC_HNCP_LINK_H_
#define SRC_HNCP_LINK_H_

#include "dncp.h"
#include "dncp_proto.h"

struct hncp_link;

struct hncp_link_user {
	struct list_head head;
	void (*cb_link)(struct hncp_link_user*, const char *ifname,
			dncp_t_link_id peers, size_t peercnt);
};

struct hncp_link* hncp_link_new(dncp dncp);

#endif /* SRC_HNCP_LINK_H_ */
