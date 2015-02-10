/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include <libubox/blobmsg.h>
#include <libubox/uloop.h>
#include <netinet/in.h>

#include "iface.h"


// Platform specific initialization
int platform_init(dncp hncp, hncp_pa hncp_pa, const char *pd_socket);

// Handle internal change
void platform_set_internal(struct iface *c, bool internal);

// Set / unset an address
void platform_set_address(struct iface *c, struct iface_addr *addr, bool enable);

// Set / unset a route
void platform_set_route(struct iface *c, struct iface_route *route, bool enable);

// Set owner status
void platform_set_dhcp(struct iface *c, enum hncp_link_elected elected);

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

// Enable / disable NAT
void platform_set_snat(struct iface *c, const struct prefix *p);

// Register an RPC function
struct platform_rpc_method;
typedef int(platform_rpc_cb)(struct platform_rpc_method *method, const struct blob_attr *in, struct blob_buf *out);
typedef int(platform_rpc_main)(struct platform_rpc_method *method, int argc, char* const argv[]);

struct platform_rpc_method {
	const char *name;
	platform_rpc_cb *cb;
	platform_rpc_main *main;
	struct blobmsg_policy *policy;
	size_t policy_cnt;
};
int platform_rpc_register(struct platform_rpc_method *method);

// Call RPC function from your own program
int platform_rpc_cli(const char *name, struct blob_attr *in);

// Multicall RPC dispatcher
int platform_rpc_multicall(int argc, char *const argv[]);



#define PLATFORM_RPC_MAX 32
