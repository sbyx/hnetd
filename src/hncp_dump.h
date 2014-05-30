/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * HNCP database dump tool.
 *
 */
#ifndef HNCP_DUMP_H_
#define HNCP_DUMP_H_

//#include <libubox/blob.h>
#include <libubox/blobmsg.h>

#include "hncp.h"

/* Returns a blob buffer containing hncp data or NULL in case of error.
 * Dump format is the following (Will be updated as new elements are added).
 * {
 *   ifaces : {
 *     "ifname1" : iface_id (int32),
 *     ...
 *   }
 * }
 *
 */
struct blob_buf *hncp_dump(hncp o);

/* Frees any blob buffer returned by hncp_dump functions */
#define hncp_dump_free(dump) blob_buf_free(dump)

#endif /* HNCP_DUMP_H_ */
