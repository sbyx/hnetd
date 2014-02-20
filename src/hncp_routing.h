/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#ifndef HNCP_ROUTING_H_
#define HNCP_ROUTING_H_

#include "hncp.h"

struct hncp_routing_struct;
typedef struct hncp_routing_struct hncp_bfs_s, *hncp_bfs;

hncp_bfs hncp_routing_create(hncp hncp, const char *script);
void hncp_routing_destroy(hncp_bfs bfs);

enum hncp_routing_protocol {
	HNCP_ROUTING_NONE,
	HNCP_ROUTING_BABEL,
	HNCP_ROUTING_OSPF,
	HNCP_ROUTING_ISIS,
	HNCP_ROUTING_RIP,
	HNCP_ROUTING_MAX
};

#endif /* HNCP_ROUTING_H_ */
