/*
 * hncp_trust.h
 *
 * Author: Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Management of local trust links
 *
 */

#ifndef _LOCAL_TRUST_H
#define _LOCAL_TRUST_H

#include "hncp_trust.h"

/** Initialize the vlist */
void local_trust_init(hncp o);

/** Add a hash to be trusted
  * A hash can be added more than once,
  * It will only waste time */
void local_trust_add_trusted_hash(hncp o, hncp_hash h);

/** Remove a trusted hash, true if hash found */
bool local_trust_remove_trusted_hash(hncp o, hncp_hash h);

/** Remove everything */
void local_trust_purge_trusted_list(hncp o);

#endif /* _LOCAL_TRUST_H */
