/*
 * $Id: hncp_i.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Dec 23 13:33:03 2014 mstenber
 * Last modified: Tue Dec 23 18:13:03 2014 mstenber
 * Edit time:     7 min
 *
 */

#ifndef HNCP_I_H
#define HNCP_I_H

#include "dncp_i.h"
#include "hncp.h"
#include "hncp_proto.h"

/* Pretty arbitrary. I wonder if all links can really guarantee MTU
 * size packets going through. However, IPv6 minimum MTU - size of
 * IPv6 header - size of UDP header (we consider only the payload
 * here) should work.  */
#define HNCP_MAXIMUM_MULTICAST_SIZE (1280-40-8)

/* TLV handling */
#include "prefix_utils.h"

static inline hncp_t_assigned_prefix_header
hncp_tlv_ap(const struct tlv_attr *a)
{
  hncp_t_assigned_prefix_header ah;

  if (tlv_id(a) != HNCP_T_ASSIGNED_PREFIX || tlv_len(a) < sizeof(*ah))
    return NULL;
  ah = tlv_data(a);
  if (tlv_len(a) < (sizeof(*ah) + ROUND_BITS_TO_BYTES(ah->prefix_length_bits))
      || ah->prefix_length_bits > 128)
    return NULL;
  return ah;
}

static inline hncp_t_delegated_prefix_header
hncp_tlv_dp(const struct tlv_attr *a)
{
  hncp_t_delegated_prefix_header dh;

  if (tlv_id(a) != HNCP_T_DELEGATED_PREFIX || tlv_len(a) < sizeof(*dh))
    return NULL;
  dh = tlv_data(a);
  if (tlv_len(a) < (sizeof(*dh) + ROUND_BITS_TO_BYTES(dh->prefix_length_bits))
      || dh->prefix_length_bits > 128)
    return NULL;
  return dh;
}

static inline hncp_t_router_address
hncp_tlv_router_address(const struct tlv_attr *a)
{
  if (tlv_id(a) != HNCP_T_ROUTER_ADDRESS
      || tlv_len(a) != sizeof(hncp_t_router_address_s))
    return NULL;
  return tlv_data(a);
}

void hncp_tlv_ap_update(hncp o,
                        const struct prefix *prefix,
                        const char *ifname,
                        bool authoritative,
                        unsigned int preference,
                        bool add);

void hncp_tlv_ra_update(hncp o,
                        uint32_t lid,
                        const struct in6_addr *address,
                        bool add);

bool hncp_init(hncp o, const void *node_identifier, int len);
void hncp_uninit(hncp o);

#endif /* HNCP_I_H */
