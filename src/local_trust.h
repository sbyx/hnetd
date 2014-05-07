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

#endif /* _LOCAL_TRUST_H */
