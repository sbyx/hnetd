/*
 * $Id: hncp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:30:01 2014 mstenber
 * Last modified: Tue Dec 23 18:09:09 2014 mstenber
 * Edit time:     4 min
 *
 */

#ifndef HNCP_H
#define HNCP_H

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
void hncp_if_set_ipv6_address(hncp o,
                              const char *ifname, const struct in6_addr *a);

#ifdef DTLS

/**
 * Set the dtls instance to be used for securing HNCP traffic.
 */
void hncp_set_dtls(hncp o, dtls d);
#endif /* DTLS */

/**
 * Create HNCP instance
 */
hncp hncp_create(void);

bool hncp_init(hncp o, const void *node_identifier, int len);

#endif /* HNCP_H */
