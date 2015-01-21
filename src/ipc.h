/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include "hnetd.h"
#include "dncp.h"
#include "dncp_trust.h"

// IPC init
int ipc_init();

// IPC CLI client
int ipc_client(const char *buffer);

// IPC ifup/ifdown client
int ipc_ifupdown(int argc, char *argv[]);

// IPC dump client
int ipc_dump(void);

// IPC trust client (to deal with dncp_trust)
int ipc_trust(int argc, char *argv[]);

void ipc_conf(dncp hncp, dncp_trust trust);
