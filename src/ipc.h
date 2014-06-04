/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include "hnetd.h"
#include "hncp.h"

// IPC init
int ipc_init();

// IPC CLI client
int ipc_client(const char *buffer);

// IPC ifup/ifdown client
int ipc_ifupdown(int argc, char *argv[]);

// IPC dump client
int ipc_dump(void);

void ipc_conf(hncp hncp);
