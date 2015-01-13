/*
 * $Id: dncp_trust.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Thu Nov 20 11:46:44 2014 mstenber
 * Last modified: Tue Jan 13 13:36:25 2015 mstenber
 * Edit time:     17 min
 *
 */

#pragma once

#include "dncp.h"
#include "dncp_proto.h"

typedef struct dncp_trust_struct dncp_trust_s, *dncp_trust;

dncp_trust dncp_trust_create(dncp o, const char *filename);
void dncp_trust_destroy(dncp_trust t);

/*
 * Get effective trust verdict for the hash. This operation is
 * immediate and does NOT result in state changes in DNCP.
 */
int dncp_trust_get_verdict(dncp_trust t, const dncp_sha256 h);

/*
 * Publish the request for a verdict into DNCP.
 */
void dncp_trust_request_verdict(dncp_trust t,
                                const dncp_sha256 h,
                                const char *cname);
/*
 * Add/Update local configured trust to have this particular entry
 * too.
 */
void dncp_trust_set(dncp_trust t, const dncp_sha256 h,
                    uint8_t verdict, const char *cname);
