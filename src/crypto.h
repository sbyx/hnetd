
#include "hncp_i.h"
#include <polarssl/pk.h>


/** generate an RSA key
  * return 0 when fine, appropriate polarssl err code otherwise */
int crypto_gen_rsa_key(int key_size, pk_context * ctx);

/** get raw ASN.1 DER key from the polarssl struct
  * return the length of the data & a pointer to it in buf */
int crypto_key_to_raw(pk_context* ctx, unsigned char ** buf, bool private);

/** init polarssl struct from raw key
  * return 0 if ok, appropriate polarssl err code otherwise */
int crypto_key_from_raw(pk_context * ctx, unsigned char * raw_key, size_t size, bool private);

/** Write the key into the file, in ASN.1 DER format
  * return 0 if right, appropriate polarssl err code otherwise */
int crypto_write_key_file(pk_context* ctx, char * file, bool private);

/** MD5 hash of raw data
  * We should have node_identifier_hash == hash(node_key) */
void crypto_hash_from_key(hncp_hash hash, void *key, size_t size);
