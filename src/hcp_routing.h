#ifndef HCP_ROUTING_H_
#define HCP_ROUTING_H_

#include "hcp.h"

struct hcp_routing_struct;
typedef struct hcp_routing_struct hcp_bfs_s, *hcp_bfs;

hcp_bfs hcp_routing_create(hcp hcp, const char *script);
void hcp_routing_destroy(hcp_bfs bfs);

enum hcp_routing_protocol {
	HCP_ROUTING_NONE,
	HCP_ROUTING_BABEL,
	HCP_ROUTING_OSPF,
	HCP_ROUTING_ISIS,
	HCP_ROUTING_RIP,
	HCP_ROUTING_MAX
};

#endif /* HCP_ROUTING_H_ */
