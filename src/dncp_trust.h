/*
 * $Id: dncp_trust.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Nov 20 11:46:44 2014 mstenber
 * Last modified: Tue Dec 23 15:28:14 2014 mstenber
 * Edit time:     10 min
 *
 */

#ifndef DNCP_TRUST_H
#define DNCP_TRUST_H

#include "dncp.h"
#include "dncp_proto.h"

typedef struct hncp_trust_struct hncp_trust_s, *hncp_trust;

hncp_trust hncp_trust_create(hncp o, const char *filename);
void hncp_trust_destroy(hncp_trust t);

/*
 * Get the trust verdict value for the node identified by hash within
 * then TLV.
 */
int hncp_trust_get_verdict(hncp_trust t, const hncp_sha256 h);

/*
 * Add/Update local configured trust to have this particular entry
 * too.
 */
void hncp_trust_set(hncp_trust t, const hncp_sha256 h,
                    uint8_t verdict, const char *cname);

#endif /* DNCP_TRUST_H */
