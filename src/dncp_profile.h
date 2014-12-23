/*
 * $Id: dncp_profile.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 12:50:58 2014 mstenber
 * Last modified: Tue Dec 23 15:31:51 2014 mstenber
 * Edit time:     19 min
 *
 */

#pragma once

#ifdef DTLS
#include "dtls.h"
#endif /* DTLS */

#include "hncp.h"

/* Profile API refers to links; however, try to avoid importing
 * definition of _i.h unless it is really needed. */
typedef struct hncp_link_struct hncp_link_s, *hncp_link;

/* These are the DNCP profile specific definitions. The values used
 * here are for HNCP (and obviously if doing some other protocol, feel
 * free to replace with something more appropriate). */

/* The embedded struct within main dncp object that is profile specific. */
typedef struct dncp_profile_data_struct *dncp_profile_data, dncp_profile_data_s;

/* Per-node data. */
typedef struct dncp_profile_node_data_struct *dncp_profile_node_data, dncp_profile_node_data_s;

/* TBD sync with HNCP-03 values */

/* Minimum interval trickle starts at. The first potential time it may
 * send something is actually this divided by two. */
#define DNCP_TRICKLE_IMIN (HNETD_TIME_PER_SECOND / 5)

/* Note: This is concrete value, NOT exponent # as noted in RFC. I
 * don't know why RFC does that.. We don't want to ever need do
 * exponentiation in any case in code. 64 seconds for the time being.. */
#define DNCP_TRICKLE_IMAX (40 * HNETD_TIME_PER_SECOND)

/* Redundancy constant. */
#define DNCP_TRICKLE_K 1

/* Size of the node identifier */
#define DNCP_NI_LEN 4

/* Default keep-alive interval to be used; overridable by user config */
#define DNCP_KEEPALIVE_INTERVAL 24 * HNETD_TIME_PER_SECOND

/* How many keep-alive periods can be missed until peer is declared M.I.A. */
/* (Note: This CANNOT be configured) */
#define DNCP_KEEPALIVE_MULTIPLIER 5/2

/* Let's assume we use 64-bit version of MD5 for the time being.. */
#define DNCP_HASH_LEN 8

/* However, in security stuff, we use sha256 */
#define DNCP_SHA256_LEN 32

/* How recently the node has to be reachable before prune kills it for real. */
#define DNCP_PRUNE_GRACE_PERIOD (60 * HNETD_TIME_PER_SECOND)

/* Don't do node pruning more often than this. This should be less
 * than minimum Trickle interval, as currently non-valid state will
 * not be used to respond to node data requests about anyone except
 * self. */
#define DNCP_MINIMUM_PRUNE_INTERVAL (HNETD_TIME_PER_SECOND / 50)


/* This is the extra data embedded _within_ dncp object for
 * per-profile use. */
struct dncp_profile_data_struct
{
  /* Multicast address */
  struct in6_addr multicast_address;

#ifdef DTLS
  /* DTLS 'socket' abstraction, which actually hides two UDP sockets
   * (client and server) and N OpenSSL contexts tied to each of
   * them. */
  dtls d;

  /* Trust consensus model of authz for DTLS is _not_ here; see
   * hncp_trust.[ch]. */
#endif /* DTLS */
};

struct dncp_profile_node_data_struct
{
  uint32_t version;
};

/* Profile-specific validation that the data is valid.*/
struct tlv_attr *dncp_profile_node_validate_data(hncp_node n,
                                                 struct tlv_attr *a);

/* Profile-specific method of sending keep-alive on a link. */
void dncp_profile_link_send_network_state(hncp_link l);

/* Profile hook to allow overriding collision handling. */
bool dncp_profile_handle_collision(hncp o);
