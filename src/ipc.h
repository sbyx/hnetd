#pragma once
#include "hnetd.h"

// IPC init
int ipc_init(void);

// IPC CLI client
int ipc_client(const char *buffer);
