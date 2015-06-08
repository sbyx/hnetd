/*
 * $Id: dncp_util.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Jun  8 11:36:06 2015 mstenber
 * Last modified: Mon Jun  8 13:52:28 2015 mstenber
 * Edit time:     5 min
 *
 */

#pragma once

#include "prefix.h"
#include "dncp_proto.h"
#include "tlv.h"

/* Assorted utility macros needed by dncp code. Split away from
 * dncp_i.h. Note: some that depend on dncp_i content remain within
 * that header file (this + dncp.h are essentially 'public' part of
 * dncp headers). */

#define DNCP_STRUCT_REPR(i) HEX_REPR(&i, sizeof(i))

#define SA6_F "[%s]:%d%%%d"
#define SA6_D(sa)                                       \
  sa ? ADDR_REPR(&(sa)->sin6_addr) : "(NULL SA6)",      \
    sa ? ntohs((sa)->sin6_port) : 0,                    \
    sa ? (sa)->sin6_scope_id : 0

#define ROUND_BITS_TO_BYTES(b) (((b) + 7) / 8)
#define ROUND_BYTES_TO_4BYTES(b) ((((b) + 3) / 4) * 4)

static inline dncp_t_trust_verdict
dncp_tlv_trust_verdict(const struct tlv_attr *a)
{
  if (tlv_id(a) != DNCP_T_TRUST_VERDICT)
    return NULL;
  if (tlv_len(a) < sizeof(dncp_t_trust_verdict_s) + 1)
    return NULL;
  if (tlv_len(a) > sizeof(dncp_t_trust_verdict_s) + DNCP_T_TRUST_VERDICT_CNAME_LEN)
    return NULL;
  const char *data = tlv_data(a);
  /* Make sure it is also null terminated */
  if (data[tlv_len(a)-1])
    return NULL;
  return (dncp_t_trust_verdict)tlv_data(a);
}

#define dncp_update_number_gt(a,b) \
  ((((uint32_t)(a) - (uint32_t)(b)) & ((uint32_t)1<<31)) != 0)

#define dncp_update_tlv(o, t, d, dlen, elen, is_add)    \
do {                                                    \
  if (is_add)                                           \
    dncp_add_tlv(o, t, d, dlen, elen);                  \
  else                                                  \
    dncp_remove_tlv_matching(o, t, d, dlen);            \
 } while(0)

static inline void sockaddr_in6_set(struct sockaddr_in6 *sin6,
                                    struct in6_addr *a6,
                                    uint16_t port)
{
  memset(sin6, 0, sizeof(*sin6));
#ifdef SIN6_LEN
  sin6->sin6_len = sizeof(*sin6);
#endif /* SIN6_LEN */
  sin6->sin6_family = AF_INET6;
  if (a6)
    sin6->sin6_addr = *a6;
  sin6->sin6_port = htons(port);
}

#define DNCP_NODE_REPR(n) dncp_node_repr(n, alloca(128))
