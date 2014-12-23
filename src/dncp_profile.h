/*
 * $Id: dncp_profile.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 12:50:58 2014 mstenber
 * Last modified: Tue Dec 23 18:55:46 2014 mstenber
 * Edit time:     21 min
 *
 */

#pragma once

#ifdef DTLS
#include "dtls.h"
#endif /* DTLS */

/* Profile API refers to links; however, try to avoid importing
 * definition of _i.h unless it is really needed. */
typedef struct dncp_link_struct dncp_link_s, *dncp_link;

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
   * dncp_trust.[ch]. */
#endif /* DTLS */
};

struct hncp_bfs_head {
  /* List head for implementing BFS */
  struct list_head head;

  /* Next-hop in path (also used to mark visited nodes) */
  const struct in6_addr *next_hop;
  const struct in6_addr *next_hop4;
  const char *ifname;
  unsigned hopcount;
};

struct dncp_profile_node_data_struct
{
  uint32_t version;

  /* iterator to do bfs-traversal */
  struct hncp_bfs_head bfs;
};

/* Profile-specific validation that the data is valid.*/
struct tlv_attr *dncp_profile_node_validate_data(dncp_node n,
                                                 struct tlv_attr *a);

/* Profile-specific method of sending keep-alive on a link. */
void dncp_profile_link_send_network_state(dncp_link l);

/* Profile hook to allow overriding collision handling. */
bool dncp_profile_handle_collision(dncp o);

/************************************************** I/O abstraction for DNCP */
/* (c.f. hncp_io) */

bool dncp_io_init(dncp o);
void dncp_io_uninit(dncp o);
bool dncp_io_set_ifname_enabled(dncp o, const char *ifname, bool enabled);
int dncp_io_get_hwaddrs(unsigned char *buf, int buf_left);
void dncp_io_schedule(dncp o, int msecs);
hnetd_time_t dncp_io_time(dncp o);

ssize_t dncp_io_recvfrom(dncp o, void *buf, size_t len,
                         char *ifname,
                         struct sockaddr_in6 *src,
                         struct in6_addr *dst);
ssize_t dncp_io_sendto(dncp o, void *buf, size_t len,
                       const struct sockaddr_in6 *dst);
