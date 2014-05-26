
#define KEY_BUFFER_SIZE (1 << 12)
#include <polarssl/ctr_drbg.h>
#include <polarssl/entropy.h>
#include <libubox/md5.h>


#include "crypto.h"


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

/* return the length of the data & a pointer to it in buf */
int crypto_key_to_raw(pk_context* ctx, unsigned char ** buf, bool private){
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

int crypto_write_key_file(pk_context* ctx, char * file, bool private){
  unsigned char* buf;
  int ret = crypto_key_to_raw(ctx, &buf, private);
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

int crypto_key_from_raw(pk_context * ctx, unsigned char * raw_key, size_t size, bool private){
  pk_init(ctx);
  return private ? pk_parse_key(ctx, raw_key, size, NULL, 0) : pk_parse_public_key(ctx, raw_key, size);
};

void crypto_hash_from_key(hncp_hash hash, void *key, size_t size){
  md5_ctx_t ctx;
  md5_begin(&ctx);
  md5_hash(key, size, &ctx);
  md5_end(hash->buf, &ctx);

}
