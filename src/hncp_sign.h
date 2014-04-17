/*
 * hncp_sign.h
 *
 * Author: Xavier Bonnetain
 *
 * Signature extension for HNCP.
 *
 */

#ifndef HNCP_SIGN_H
#define HNCP_SIGN_H

#include "hncp.h"

/* Generates the signature */
hncp_t_signature hncp_sign_packet(char (*packet)[], char (*key)[]);

/* Checks the signature */
bool hncp_sign_verify_signature(char (*packet)[], hncp_t_signature *signature, hncp_t_node_data_key *key);

#endif /* HNCP_SIGN_H */
