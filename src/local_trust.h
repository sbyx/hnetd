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


/** Add a hash to be trusted
  * update : flag to update the tlv */
void local_trust_add_trusted_hash(hncp o, hncp_hash h, bool update);

/** Do the tlv update & trust status update */
void local_trust_update_tlv(hncp o);

/** Add a hash array to be trusted */
void local_trust_add_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update);

/** Remove a trusted hash, true if hash found */
bool local_trust_remove_trusted_hash(hncp o, hncp_hash h, bool update);

/** Remove everything */
void local_trust_purge_trusted_array(hncp o, bool update);

/** Replace the links with a new array */
void local_trust_replace_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update);

/** Removes a hash array from the trust array
 *  Returns if something was done */
bool local_trust_remove_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update);
#endif /* _LOCAL_TRUST_H */
