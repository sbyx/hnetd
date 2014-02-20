/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include "hnetd.h"

// IPC init
int ipc_init(void);

// IPC CLI client
int ipc_client(const char *buffer);

// IPC ifup/ifdown client
int ipc_ifupdown(const char *action, const char *ifname, const char *external);
