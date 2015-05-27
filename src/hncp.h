/*
 * $Id: hncp.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:30:01 2014 mstenber
 * Last modified: Wed May 27 09:45:15 2015 mstenber
 * Edit time:     20 min
 *
 */

#pragma once

#include "hnetd.h"

/* in6_addr */
#include <netinet/in.h>

/******************************** DNCP 'profile' values we stick in dncp_ext */

/* Intentionally renamed DNCP -> HNCP so that DNCP* ones can be used
 * in DNCP code. */

/* Minimum interval trickle starts at. The first potential time it may
 * send something is actually this divided by two. */
#define HNCP_TRICKLE_IMIN (HNETD_TIME_PER_SECOND / 5)

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define HNCP_TRICKLE_IMAX (40 * HNETD_TIME_PER_SECOND)

/* Redundancy constant. */
#define HNCP_TRICKLE_K 1

/* Size of the node identifier */
#define HNCP_NI_LEN 4

/* Default keep-alive interval to be used; overridable by user config */
#define HNCP_KEEPALIVE_INTERVAL 24 * HNETD_TIME_PER_SECOND

/* How many keep-alive periods can be missed until peer is declared M.I.A. */
/* (Note: This CANNOT be configured) */
#define HNCP_KEEPALIVE_MULTIPLIER 21/10

/* Let's assume we use 64-bit version of MD5 for the time being.. */
#define HNCP_HASH_LEN 8

/* How recently the node has to be reachable before prune kills it for real. */
#define HNCP_PRUNE_GRACE_PERIOD (60 * HNETD_TIME_PER_SECOND)

/* Don't do node pruning more often than this. This should be less
 * than minimum Trickle interval, as currently non-valid state will
 * not be used to respond to node data requests about anyone except
 * self. */
#define HNCP_MINIMUM_PRUNE_INTERVAL (HNETD_TIME_PER_SECOND / 50)


/****************************************** Other implementation definitions */

/* Current (binary) data schema version
 *
 * Note that adding new TLVs does not require change of version; only
 * change of contents of existing TLVs (used by others) does.
 */
#define HNCP_VERSION 1

/* 0 = reserved link id. note it somewhere. */

#define HNCP_SD_DEFAULT_DOMAIN "home."

/* How often we retry multicast joins? Once per second seems sane
 * enough. */
#define HNCP_REJOIN_INTERVAL (1 * HNETD_TIME_PER_SECOND)

/*********************************************************************** API */

typedef struct hncp_struct hncp_s, *hncp;

/**
 * Set IPv6 address for given interface.
 */
void hncp_set_ipv6_address(hncp o, const char *ifname,
                           const struct in6_addr *a);

/**
 * Set HNCP enabled on an interface.
 */
void hncp_set_enabled(hncp o, const char *ifname, bool enabled);

/**
 * Get the IPv6 address for the given interface (if ifname is set) or any.
 */
struct in6_addr *hncp_get_ipv6_address(hncp o, const char *ifname);


#ifdef DTLS

#include "dtls.h"

/**
 * Set the dtls instance to be used for securing HNCP traffic.
 */
void hncp_set_dtls(hncp o, dtls d);
#endif /* DTLS */

/**
 * Fork+run an utility script, and return the PID.
 */
pid_t hncp_run(char *argv[]);

/**
 * Create HNCP instance
 */
hncp hncp_create(void);


/**
 * Destroy HNCP instances
 */
void hncp_destroy(hncp o);


/* Intentionally include this only here, so that there are no
 * references to DNCP before. */
#include "dncp.h"

/**
 * Get the DNCP instance pointer.
 */
dncp hncp_get_dncp(hncp o);
