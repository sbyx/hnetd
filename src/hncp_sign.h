/*
 * hncp_sign.h
 *
 * Author: Xavier Bonnetain
 *
 * Signature extension for HNCP.
 *
 */
#pragma once

#include "hncp_i.h"
struct key {
    char* key;
    int key_size;
};

hncp_hash hncp_sign_hash_signature(const struct key* key);
/* Generates the signature, null if failed */
hncp_t_signature hncp_sign_packet(char* packet, int packet_size, const struct key* key);

/* Checks the signature */
bool hncp_sign_verify_signature(char* packet, int packet_size, hncp_t_signature *signature, const struct key* key);


