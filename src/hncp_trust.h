/*
 * hncp_trust.h
 *
 * Author: Xavier Bonnetain
 *
 * Web of trust extension for HNCP.
 *
 */

#ifndef HNCP_TRUST_H
#define HNCP_TRUST_H

#include "hncp_proto.h"

/* Checks if the hash is really derived from the key */
bool hncp_trust_valid_key(hncp_hash *hash, char (*key)[]);

/* Returns if the node is trusted */
bool hncp_trust_node_trusted(hncp_hash *hash);

/* Returns the list of directly trusted nodes, to be advertised */
hncp_t_trust_link hncp_trust_trusted_nodes();

/* Update the trust graph with new trust links */
void hncp_trust_add_trust_list(hncp_hash* emitter, hncp_t_trust_link (*trust_list)[]);

/* Checks if some trust links are obsoleted, and updates the graph accordingly */
void hncp_trust_time_update();

#endif /* HNCP_TRUST_H */
