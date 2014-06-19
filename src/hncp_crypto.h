/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#pragma once
#include "hncp_i.h"
#include "hncp_proto.h"
#include "crypto.h"
#include <libubox/vlist.h>

#define RSA_KEY_SIZE 2048


struct trust_key_struct{
  /* Structured key */
  pk_context ctx;
  /* Node, for key indexation */
  struct vlist_node node;

  /* ASN.1 DER key */
  unsigned char * raw_key;
  /* Size of the raw key */
  size_t size;

  /* File where the key is stored,
   * can be NULL */
  char * key_file;

  /* Hash of the key, index for the node
   * & for the key in the key tree */
  hncp_hash_s key_hash;

  /* Flag to identify reliable keys (unused for self key) */
  bool locally_trusted;
  /* Is it a public or private key */
  bool private;
};

typedef struct trust_key_struct trust_key_s, *trust_key;

struct crypto_data{
  /* keys trusted locally */
  struct vlist_tree trust_keys;

  struct vlist_tree symmetric_keys;
  trust_key_s key;

  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  md_context_t md_ctx;

  uint16_t sign_type;
  uint16_t sign_hash;
};

typedef struct crypto_data hncp_crypto_s, *hncp_crypto;

struct symmetric_key_struct{
  cipher_context_t ctx;
  struct vlist_node node;
  hncp_hash_s key_emitter;
  hncp_hash_s key_hash;
};

typedef struct symmetric_key_struct hncp_shared_key_s, *hncp_shared_key;

/** 1 if key generation failed
  * 2 if key file opening failed (if file exists)
  * else 0 */
int hncp_crypto_init(hncp o, char * private_key_file);

/** 0 on success
  * Appropriate polarssl err code on failure */
int hncp_crypto_write_trusted_key(hncp o, trust_key c, char * trust_dir);

/** Free key elements (but not the key) */
void hncp_crypto_del_key(trust_key c);

/** Free the intern cryptographic structure */
void hncp_crypto_del_data(struct crypto_data *data);

/** fetch all the files in trusted_dir & try to cast them in keys
  * and to trust them for now, fails miserably if an invalid
  * file is in the directory
  * returns the number of keys, or -1 if the directory isn't available */
int hncp_crypto_get_trusted_keys(hncp o, char *trusted_dir);

/**  initialize the struct from the context in it */
void hncp_crypto_init_key(trust_key t, char * file_name, bool private);

/** Create the internal key structure */
trust_key hncp_crypto_raw_key_to_trust_key(char * key, size_t size, bool private);

/** Get a registered key from the hash (or NULL if not found) */
trust_key hncp_crypto_key_from_hash(hncp o, hncp_hash hash);

int hncp_crypto_pk_encrypt_data(hncp o, trust_key k, char * data, size_t size, char ** encrypted_data, size_t* len, uint16_t crypt_type, uint16_t crypt_variant);
int hncp_crypto_pk_decrypt_data(hncp o, char * data, size_t size, char ** decrypted_data, size_t* len, uint16_t crypt_type, uint16_t crypt_variant);


/** Callback for sign update in case of tlv change */
void hncp_crypto_local_update_callback(hncp_subscriber s, struct tlv_attr *tlv, __unused bool add);
/*
hncp_crypto_change_keys(hncp o, void *new_algorithm);

hncp_crypto_sign_data(hncp o, void *data, size_t size);

hncp_crypto_verify_data(hncp o, hncp_hash emitter, void *data, size_t size);

hncp_crypto_encrypt_data(hncp o, void *data, size_t size);

hncp_crypto_decrypt_data(hncp o, hncp_hash emitter, void *data, size_t size);

*/
