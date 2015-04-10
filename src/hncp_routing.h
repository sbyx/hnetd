/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once

#include "hncp.h"

struct hncp_routing_struct;
typedef struct hncp_routing_struct hncp_bfs_s, *hncp_bfs;

hncp_bfs hncp_routing_create(dncp hncp, const char *script, bool incremental);
void hncp_routing_destroy(hncp_bfs bfs);
