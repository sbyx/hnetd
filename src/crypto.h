/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include "hncp_i.h"
#include <polarssl/pk.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <polarssl/cipher.h>

/** Keys */

/** generate an RSA key
  * return 0 when fine, appropriate polarssl err code otherwise */
int crypto_gen_rsa_key(int key_size, pk_context * ctx);

/** get raw ASN.1 DER key from the polarssl struct
  * return the length of the data & a pointer to it in buf */
int crypto_raw_from_key(unsigned char ** buf, pk_context* ctx, bool private);

/** init polarssl struct from raw key
  * return 0 if ok, appropriate polarssl err code otherwise */
int crypto_key_from_raw(pk_context * ctx, const unsigned char * raw_key, size_t size, bool private);

/** Write the key into the file, in ASN.1 DER format
  * return 0 if right, appropriate polarssl err code otherwise */
int crypto_write_key_file(pk_context* ctx, const char * file, bool private);

/** Hashes */

/** MD5 hash of raw data
  * We should have node_identifier_hash == hash(node_key) */
void crypto_md5_hash_from_raw(hncp_hash hash, const unsigned char *key, size_t size);

/** MD5 hash of structured key */
void crypto_md5_hash_from_key(hncp_hash hash, pk_context * ctx, bool private);

/** Size of a hash type */
size_t crypto_hash_len(md_type_t type);

/** Generic hashing. Out must be allocated (see function above for size) */
void crypto_hash_from_raw(unsigned char * out, const unsigned char * in, size_t size, md_type_t type);

/** step-by-step hashing */
void crypto_hash_begin(md_context_t * ctx, md_type_t hash_type);
void crypto_hash_fill(md_context_t *ctx, void *in, size_t size);
unsigned char * crypto_hash_end(md_context_t * ctx);

/** Conversion from HNCP sign type to polarssl digest */
md_type_t polarssl_sign_digest_wrapper(uint16_t hncp_hash_type);

/** Checks if the identifier is derived from the key */
bool crypto_hash_derived_from_raw(hncp_hash h, const unsigned char * raw_key, size_t size);

/** Randomly generates a shared key, an IV... */
int crypto_gen_random(void * rand, char * buf, int size);

/** Signature/encryption */

/** Sign data */
int crypto_make_signature(ctr_drbg_context* p_rng, pk_context* ctx, unsigned char * signature, size_t *sig_len, unsigned char * hash, uint16_t sign_type);

/** Check the message integrity.
  * Don't include the signature header in the data, nor the signature tlv ! */
int crypto_verify_signature(hncp_t_signature sign, pk_context* ctx, uint32_t seq_num, void * data, size_t size);

/** Asymmetric encryption */
/** Maximum size of data to be encrypted(hash type when applicable) */
size_t crypto_pk_encrypt_max_size(pk_context* ctx, uint16_t crypt_type);

/** Maximum size of encrypted data */
size_t crypto_pk_encrypt_max_out_size(pk_context* ctx, uint16_t crypt_type);

/** Encryption to use with a trusted public key */
uint16_t crypto_crypt_type_from_ctx(pk_context *ctx);

int crypto_pk_encrypt_data(ctr_drbg_context* p_rng, pk_context* ctx, void * input, size_t isize, unsigned char * out,
                        size_t* olen, size_t osize, uint16_t crypt_type);

int crypto_pk_decrypt_data(ctr_drbg_context* p_rng, pk_context* ctx, void * input, size_t isize, unsigned char * out,
                        size_t* olen, size_t osize, uint16_t crypt_type);

/** Symmetric encryption */

const cipher_info_t* polarssl_cipher_type(uint16_t symmetric_crypt);
size_t crypto_symmetric_key_length(uint16_t crypt_type);

void crypto_init_empty_cipher(cipher_context_t* ctx);
void crypto_change_symmetric_cipher(cipher_context_t* ctx, const char * key, uint16_t key_type, bool encrypt);
int crypto_cipher_encrypt(cipher_context_t * ctx, uint16_t symmetric_crypt, char ** out, size_t * olen, const char * in, size_t ilen, const char * iv, size_t ivlen);
int crypto_cipher_decrypt(cipher_context_t * ctx, uint16_t symmetric_crypt, char ** out, size_t * olen, const char * in, size_t ilen, const char * iv, size_t ivlen);
