#pragma once
#include "hnetd.h"

#include <libubox/uloop.h>

#include "iface.h"

// Initialize ELSA handler
int elsa_init(void);

// Handle ELSA IPC message
void elsa_handle(struct uloop_fd *fd, unsigned int events);

// Notify ELSA of a delegated prefix
void elsa_notify_prefix(const struct iface_addr *prefix, const char *device);
