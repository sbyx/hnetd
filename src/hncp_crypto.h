
#pragma once
#include "hncp_i.h"
#include "hncp_trust.h"
#include "crypto.h"
#include <libubox/vlist.h>
#define TRUST_PRIVATE_KEY_FILE "priv.key"
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

  /* Is it a public or private key */
  bool private;
};

typedef struct trust_key_struct trust_key_s, *trust_key;

/** 1 if key generation failed
  * 2 if key file opening failed (if file exists)
  * else 0 */
int hncp_crypto_init(hncp o);

/** 0 on success
  * Appropriate polarssl err code on failure */
int hncp_crypto_write_trusted_key(hncp o, trust_key c);

/** Suppress a key */
void hncp_crypto_del_key(trust_key c);

/** fetch all the files in trusted_dir & try to cast them in keys
  * and to trust them for now, fails miserably if an invalid
  * file is in the directory
  * returns the number of keys, or -1 if the directory isn't available */
int hncp_crypto_get_trusted_keys(hncp o, char *trusted_dir);

/** generate an RSA key structure, for any usage
  * (The init function takes care of the local key) */
trust_key hncp_crypto_gen_rsa_key(hncp o, int key_size);

/* Convert a hash to an hex string */
char * hash2str(hncp_hash h);
/*
hncp_crypto_change_keys(hncp o, void *new_algorithm);

hncp_crypto_sign_data(hncp o, void *data, size_t size);

hncp_crypto_verify_data(hncp o, hncp_hash emitter, void *data, size_t size);

hncp_crypto_encrypt_data(hncp o, void *data, size_t size);

hncp_crypto_decrypt_data(hncp o, hncp_hash emitter, void *data, size_t size);

*/
