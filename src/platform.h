#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>

#include "iface.h"


// Platform specific initialization
int platform_init(void);



// Handle internal change
void platform_set_internal(struct iface *c, bool internal);

// Set / unset an address
void platform_set_address(struct iface *c, struct iface_addr *addr, bool enable);

// Set owner status
void platform_set_owner(struct iface *c, bool enable);

// Set DHCPv6 data
void platform_set_dhcpv6_send(struct iface *c, const void *dhcpv6_data, size_t len);

// Create local interface
void platform_iface_new(struct iface *c, const char *handle);

// Delete local interface
void platform_iface_free(struct iface *c);
