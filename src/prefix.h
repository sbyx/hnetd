#pragma once
#include "libubox/uloop.h"

#include "hnetd.h"
#include "iface.h"

// Initialize ELSA handler
int prefix_init(void);

// Notify ELSA of a delegated prefix
void prefix_notify(const struct iface_addr *prefix, const char *device);
