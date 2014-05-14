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


/** Add a hash to be trusted, and adds it to the tlv */
void local_trust_add_trusted_hash(hncp o, hncp_hash h);

/** Add a hash array to be trusted
 * Makes only one tlv update, at the end */
void local_trust_add_trusted_array(hncp o, hncp_hash h, unsigned int size);

/** Remove a trusted hash, true if hash found */
bool local_trust_remove_trusted_hash(hncp o, hncp_hash h);

/** Remove everything */
void local_trust_purge_trusted_array(hncp o);

/** Replace the links with a new array */
void local_trust_replace_trusted_array(hncp o, hncp_hash h, unsigned int size);

/** Removes a hash array from the trust array
 *  Returns if something was done (and the tlv updated) */
bool local_trust_remove_trusted_array(hncp o, hncp_hash h, unsigned int size);
#endif /* _LOCAL_TRUST_H */
