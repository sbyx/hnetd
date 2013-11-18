#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>

#include "iface.h"

// Platform specific initialization
int platform_init(void);

// Handle IPC message
void platform_handle(struct uloop_fd *fd, unsigned int events);

// Handle domain change
void platform_apply_domain(struct iface *iface);

// Handle internal change
void platform_apply_zone(struct iface *iface);

// Set / unset a route
void platform_apply_route(struct iface_route *route, bool enable);

// Set / unset an address
void platform_apply_address(struct iface_addr *addr, bool enable);

// Apply changes all changes (if necessary)
void platform_commit(struct iface *iface);
