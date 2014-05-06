/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>

#include "iface.h"


// Platform specific initialization
int platform_init(struct pa_data *pa_data, const char *pd_socket);



// Handle internal change
void platform_set_internal(struct iface *c, bool internal);

// Set / unset an address
void platform_set_address(struct iface *c, struct iface_addr *addr, bool enable);

// Set / unset a route
void platform_set_route(struct iface *c, struct iface_route *route, bool enable);

// Set owner status
void platform_set_owner(struct iface *c, bool enable);

// Restart dhcpv4 client
void platform_restart_dhcpv4(struct iface *c);

// Set DHCPv6 data
void platform_set_dhcpv6_send(struct iface *c, const void *dhcpv6_data, size_t len, const void *dhcp_data, size_t len4);

// Create local interface
void platform_iface_new(struct iface *c, const char *handle);

// Delete local interface
void platform_iface_free(struct iface *c);

// Set prefix route
void platform_set_prefix_route(const struct prefix *p, bool enable);

// Filter / unfilter prefix
void platform_filter_prefix(struct iface *c, const struct prefix *p, bool enable);
