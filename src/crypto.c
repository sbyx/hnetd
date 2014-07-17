/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#define KEY_BUFFER_SIZE (1 << 12)

#include <polarssl/md.h>
#include <polarssl/rsa.h>
#include <polarssl/cipher.h>
#include "crypto.h"
#include "trust_graph.h"

int crypto_gen_rsa_key(int key_size, pk_context * ctx){
  int ret;

  entropy_context entropy;
  ctr_drbg_context ctr_drbg;
  entropy_init(&entropy);
  pk_init(ctx);
  ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (unsigned char *) "Hnetd Trust", 11);
  if (ret < 0)
    goto fail;

  ret = pk_init_ctx(ctx, pk_info_from_type(POLARSSL_PK_RSA));
  if (ret < 0)
    goto fail;

  L_DEBUG("rsa key generation");
  ret = rsa_gen_key(pk_rsa(*ctx), ctr_drbg_random, &ctr_drbg, key_size, 65537);
  if(ret < 0)
    goto fail;

  L_DEBUG("key generation done");
  return ret;

fail:
  L_ERR("Failed to generate an RSA key");
  return ret;

}

uint16_t crypto_crypt_type_from_ctx(pk_context *ctx){
  switch(pk_get_type(ctx)){
    case(POLARSSL_PK_RSA):
      return PK_CRYPT_TYPE_RSAAES_OAEP_SHA512;
    default:
      L_ERR("Unsupported key");
      return 0;
  }

}

/* return the length of the data & a pointer to it in buf */
int crypto_raw_from_key(unsigned char ** buf, pk_context* ctx, bool private){
  *buf = malloc(KEY_BUFFER_SIZE);
  int len = private ? pk_write_key_der(ctx, *buf, KEY_BUFFER_SIZE) : pk_write_pubkey_der(ctx, *buf, KEY_BUFFER_SIZE);
  if(len < 0)
    return len;
  /* pk_write_key_der writes at the end. So we move */
  unsigned char * begin = *buf + KEY_BUFFER_SIZE - len;
  memmove( *buf, begin, len);
  *buf = realloc( *buf, len);
  return len;
}

int crypto_write_key_file(pk_context* ctx, const char * file, bool private){
  unsigned char* buf;
  int ret = crypto_raw_from_key(&buf, ctx, private);
  if(ret < 0)
    goto fail_end;

  size_t len = ret;

  FILE* f = fopen(file, "w");
  if(!f)
    goto fail;

  if(fwrite(buf, 1, len, f) != len){
    fclose(f);
    goto fail;
  }
  free(buf);
  fclose(f);
  return 0;
fail:
  ret = POLARSSL_ERR_PK_FILE_IO_ERROR;
fail_end:
  free(buf);
  L_ERR("File write failed !");
  return ret;
}

int crypto_key_from_raw(pk_context * ctx, const unsigned char * raw_key, size_t size, bool private){
  pk_init(ctx);
  return private ? pk_parse_key(ctx, raw_key, size, NULL, 0) : pk_parse_public_key(ctx, raw_key, size);
}

md_type_t polarssl_sign_digest_wrapper(uint16_t hncp_sign_type){
  switch(hncp_sign_type){
    case(SIGN_TYPE_RSA_PKCS15_SHA512):
    case(SIGN_TYPE_RSA_SSAPSS_SHA512):
      return POLARSSL_MD_SHA512;
  }
  L_ERR("Unknown sign type");
  return POLARSSL_MD_NONE;
}

size_t crypto_hash_len(md_type_t type){
  const md_info_t * info = md_info_from_type(type);
  return md_get_size(info);
}

void crypto_hash_from_raw(unsigned char * out, const unsigned char * in, size_t size, md_type_t type){
  if(type == POLARSSL_MD_NONE)
    return;
  const md_info_t * info = md_info_from_type(type);
  md(info, in, size, out);
}

void crypto_hash_begin(md_context_t * ctx, md_type_t hash_type){
  md_init_ctx(ctx, md_info_from_type(hash_type));
}

void crypto_hash_fill(md_context_t *ctx, void *in, size_t size){
  md_update(ctx, in, size);
}

unsigned char * crypto_hash_end(md_context_t * ctx){
  unsigned char * out = malloc(md_get_size(ctx->md_info));
  md_finish(ctx, out);
  md_free_ctx(ctx);
  return out;
}

void crypto_md5_hash_from_raw(hncp_hash hash, const unsigned char *raw, size_t size){
 crypto_hash_from_raw((unsigned char *) hash, raw, size, POLARSSL_MD_MD5);
}

void crypto_md5_hash_from_key(hncp_hash hash, pk_context * ctx, bool private){
  unsigned char * buf;
  int i = crypto_raw_from_key(&buf, ctx, private);
  crypto_md5_hash_from_raw(hash, buf, i);
  free(buf);
}

bool crypto_hash_derived_from_raw( hncp_hash h, const unsigned char * raw_key, size_t size){
  hncp_hash_s h2;
  crypto_md5_hash_from_raw(&h2, raw_key, size);
  return HASH_EQUALS(h, &h2);
}

int crypto_make_signature(ctr_drbg_context* p_rng, pk_context* ctx, unsigned char * signature, size_t *sig_len, unsigned char * hash, uint16_t sign_type){

  md_type_t md = polarssl_sign_digest_wrapper(sign_type);
  size_t md_size = crypto_hash_len(md);

  rsa_context * c;

  switch(sign_type){
    case SIGN_TYPE_RSA_PKCS15_SHA512:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V15;
      c->hash_id = 0;
      break;
    case SIGN_TYPE_RSA_SSAPSS_SHA512:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V21;
      c->hash_id = md;
      break;
    default:
      L_ERR("Unknown signature type\n");
      return POLARSSL_ERR_PK_BAD_INPUT_DATA;
  }

  int r =  pk_sign(ctx, md, hash, md_size, signature, sig_len, ctr_drbg_random, p_rng);

  return r;
}

int crypto_verify_signature(hncp_t_signature sign, pk_context* ctx, uint32_t seq_num, void * data, size_t size){
  md_type_t hash_type = polarssl_sign_digest_wrapper(sign->sign_type);

  md_context_t md_ctx;
  crypto_hash_begin(&md_ctx, sign->sign_type);
  crypto_hash_fill(&md_ctx, &seq_num, sizeof(uint32_t));
  crypto_hash_fill(&md_ctx, data, size);
  unsigned char * hash = crypto_hash_end(&md_ctx);

  int r = pk_verify(ctx, hash_type, hash, 0, sign->signature, size);
  free(hash);

  return r;
}

int crypto_gen_random(void * rand, char * buf, int size){
  return ctr_drbg_random(rand, (unsigned char *) buf, size);
}

void crypto_init_empty_cipher(cipher_context_t* ctx){
  cipher_init_ctx(ctx, cipher_info_from_type(POLARSSL_CIPHER_AES_128_CBC));
}

void crypto_change_symmetric_cipher(cipher_context_t* ctx, const char * key, uint16_t key_type, bool encrypt){
  if(cipher_free_ctx(ctx))
    L_ERR("free ctx failed");

  cipher_init_ctx(ctx, polarssl_cipher_type(key_type));
  size_t key_len = crypto_symmetric_key_length(key_type);
  const operation_t op = encrypt ? POLARSSL_ENCRYPT : POLARSSL_DECRYPT;
  cipher_setkey(ctx, (const unsigned char *) key, key_len << 3, op);
}

size_t crypto_symmetric_key_length(uint16_t crypt_type){
  switch(crypt_type){
    case(SYMMETRIC_CRYPT_TYPE_AES_CBC_256):
      return 32;
  }
  L_ERR("Unknown cipher type");
  return 0;
}

size_t crypto_pk_encrypt_max_size(pk_context* ctx, uint16_t crypt_type){
  md_type_t md;
  switch(crypt_type){
    case PK_CRYPT_TYPE_RSAAES_PKCS15:
      return pk_rsa(*ctx)->len -11;
    case PK_CRYPT_TYPE_RSAAES_OAEP_SHA512:
      md = POLARSSL_MD_SHA512;
      return pk_rsa(*ctx)->len - 2 - 2 * crypto_hash_len(md);
  }
  L_ERR("Unknown crypt type");
  return 0;
}

size_t crypto_pk_encrypt_max_out_size(pk_context* ctx, uint16_t crypt_type){
  rsa_context *c;
  switch(crypt_type){
    case PK_CRYPT_TYPE_RSAAES_PKCS15:
    case PK_CRYPT_TYPE_RSAAES_OAEP_SHA512:
    c = pk_rsa(*ctx);
    return c->len;
  }
  L_ERR("Unknown crypt type");
  return 0;

}

int crypto_pk_encrypt_data(ctr_drbg_context* p_rng, pk_context* ctx, void * input, size_t isize, unsigned char * out,
                        size_t* olen, size_t osize, uint16_t crypt_type){
  rsa_context * c;
  switch(crypt_type){
    case PK_CRYPT_TYPE_RSAAES_PKCS15:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V15;
      break;
    case PK_CRYPT_TYPE_RSAAES_OAEP_SHA512:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V21;
      c->hash_id = POLARSSL_MD_SHA512;
      break;
    default:
      L_ERR("Unknown crypt type");
      return POLARSSL_ERR_PK_BAD_INPUT_DATA;
  }

  int r = pk_encrypt(ctx, input, isize, out, olen, osize, ctr_drbg_random, p_rng);

  return r;
}

int crypto_pk_decrypt_data(ctr_drbg_context* p_rng, pk_context* ctx, void * input, size_t isize, unsigned char * out,
                        size_t* olen, size_t osize, uint16_t crypt_type){
  rsa_context * c;
  switch(crypt_type){
    case PK_CRYPT_TYPE_RSAAES_PKCS15:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V15;

      break;
    case PK_CRYPT_TYPE_RSAAES_OAEP_SHA512:
      c = pk_rsa(*ctx);
      c->padding = RSA_PKCS_V21;
      c->hash_id = POLARSSL_MD_SHA512;
      break;
    default:
      L_ERR("Unknown crypt type");
      return POLARSSL_ERR_PK_BAD_INPUT_DATA;
  }
  int r = pk_decrypt(ctx, input, isize, out, olen, osize, ctr_drbg_random, p_rng);
  return r;
}

const cipher_info_t* polarssl_cipher_type(uint16_t symmetric_crypt){
  cipher_id_t cipher;

  switch(symmetric_crypt){
    case SYMMETRIC_CRYPT_TYPE_AES_CBC_256:
      cipher = POLARSSL_CIPHER_AES_256_CBC;
      break;
    default:
      L_ERR("Unknown cipher type");
      cipher = POLARSSL_CIPHER_ID_NONE;
  };

  return cipher_info_from_type(cipher);

}

static size_t encrypted_len(uint16_t symmetric_crypt, size_t ilen){
  const cipher_info_t * info = polarssl_cipher_type(symmetric_crypt);
  unsigned int bs = info->block_size;
  return bs * ((ilen - 1)/bs + 1);
}

static int crypto_cipher_data(cipher_context_t * ctx, uint16_t symmetric_crypt, char ** out, size_t * olen, const char * in, size_t ilen, const char * iv, size_t ivlen){
  *out = malloc(sizeof(encrypted_len(symmetric_crypt, ilen)));
  int r;
  r = cipher_set_iv(ctx, (const unsigned char *) iv, ivlen);
  if(r)
    return r;
  r = cipher_update(ctx, (const unsigned char *) in, ilen, (unsigned char *)*out, olen);
  if(r)
    return r;
  size_t * dlen = malloc(sizeof(size_t));
  r = cipher_finish(ctx, (unsigned char *)*out + *olen, dlen);
  if(r)
    return r;
  *olen += *dlen;
  return r;
}

int crypto_cipher_encrypt(cipher_context_t * ctx, uint16_t symmetric_crypt, char ** out, size_t * olen, const char * in, size_t ilen, const char * iv, size_t ivlen){
  if(cipher_get_operation(ctx) != POLARSSL_ENCRYPT)
    return POLARSSL_ERR_CIPHER_BAD_INPUT_DATA;
  return crypto_cipher_data(ctx, symmetric_crypt, out, olen, in, ilen, iv, ivlen);
}

int crypto_cipher_decrypt(cipher_context_t * ctx, uint16_t symmetric_crypt, char ** out, size_t * olen, const char * in, size_t ilen, const char * iv, size_t ivlen){
  if(cipher_get_operation(ctx) != POLARSSL_DECRYPT)
    return POLARSSL_ERR_CIPHER_BAD_INPUT_DATA;
  return crypto_cipher_data(ctx, symmetric_crypt, out, olen, in, ilen, iv, ivlen);
}
/*
int crypto_cipher_encrypt_data(cipher_context_t *ctx, uint16_t symmetric_crypt){
  cipher_update()
}

int crypto_cipher_decrypt_data()
*/
