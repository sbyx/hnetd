/*
 * $Id: hncp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:30:01 2014 mstenber
 * Last modified: Wed Apr 29 16:37:31 2015 mstenber
 * Edit time:     5 min
 *
 */

#pragma once

#include "dncp.h"
#include "dncp_profile.h"

/****************************************** Other implementation definitions */

/* Current (binary) data schema version
 *
 * Note that adding new TLVs does not require change of version; only
 * change of contents of existing TLVs (used by others) does.
 */
#define HNCP_VERSION 1

/* 0 = reserved link id. note it somewhere. */

#define HNCP_SD_DEFAULT_DOMAIN "home."

/*********************************************************************** API */

/**
 * Set IPv6 address for given interface.
 */
void dncp_ep_set_ipv6_address(dncp o,
                              const char *ifname, const struct in6_addr *a);

#ifdef DTLS

/**
 * Set the dtls instance to be used for securing HNCP traffic.
 */
void hncp_set_dtls(dncp o, dtls d);
#endif /* DTLS */

/**
 * Fork+run an utility script, and return the PID.
 */
pid_t hncp_run(char *argv[]);

/**
 * Create HNCP instance
 */
dncp hncp_create(void);


bool hncp_init(dncp o, const void *node_identifier, int len);
void hncp_uninit(dncp o);

