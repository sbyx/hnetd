
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>

#define TRUSTED_KEY_DIR "trust"



#include "hncp_crypto.h"
#include "local_trust.h"


int hncp_crypto_init(hncp o){

  pk_context* ctx = &o->trust->ctx;
  pk_init(ctx);

  o->trust->local_trust_dir = strdup(TRUSTED_KEY_DIR);

  if(access(TRUST_PRIVATE_KEY_FILE, F_OK) == -1){
    /* No file yet */
    if(crypto_gen_rsa_key(RSA_KEY_SIZE, &o->trust->ctx)){
      return 1;
    }
    crypto_write_key_file(ctx, TRUST_PRIVATE_KEY_FILE, true);
  }
  else
  if(pk_parse_keyfile(ctx, TRUST_PRIVATE_KEY_FILE, NULL)){
    L_ERR("Failed to parse key file");
    return 2;
  }

  return 0;
};


int hncp_crypto_get_trusted_keys(hncp o, char *trusted_dir){
  struct stat s;
  int ret = 0;
  if(!stat(trusted_dir, &s)){
    L_ERR("No trusted key : %s doesn't exists", trusted_dir);
    return -1;
  }
  if(!S_ISDIR(s.st_mode)){
    L_ERR("No trusted key : %s is not a directory", trusted_dir);
    return -1;
  }

  struct dirent *ent;
  DIR *dir = opendir(trusted_dir);
  trust_key c;
  while((ent = readdir(dir)) != NULL){
    if(ent->d_type != DT_REG)
      continue;
    c = malloc(sizeof(trust_key_s));

    char *buf = malloc(strlen(trusted_dir)+strlen(ent->d_name)+2);
    sprintf(buf,"%s/%s", trusted_dir, ent->d_name);

    pk_init(&c->ctx);
    pk_parse_public_keyfile(&c->ctx, buf);
    c->size = crypto_key_to_raw(&c->ctx, &c->raw_key, false);
    c->key_file = buf;
    crypto_hash_from_key(&c->key_hash, c->raw_key, c->size);
    vlist_add(&o->trust->local_trust_keys, &c->node, &c->key_hash);
    local_trust_add_trusted_hash(o, &c->key_hash, false);
    ret++;
  }
  local_trust_update_tlv(o);
  return ret;
}

void hncp_crypto_del_key(trust_key c){
  free(c->raw_key);
  free(c->key_file);
  free(c);
}

char * hash2str(hncp_hash h){
  char * ret = malloc(2*sizeof(h->buf)+1);
  unsigned char * c = (unsigned char *) h->buf;
  for(size_t i = 0; i < sizeof(h->buf); i++){
    sprintf(ret+2*i,"%02x",c[i]);
    printf("%i\n",i);
  }
  return ret;
}

trust_key hncp_crypto_raw_key_to_trust_key(unsigned char * key, size_t size, bool private){
  trust_key t = malloc(sizeof(trust_key_s));
  crypto_key_from_raw(&t->ctx, key, size,private);
  t->key_file = NULL;
  t->raw_key = malloc(size);
  memcpy(t->raw_key, key, size);
  t->size = size;
  crypto_hash_from_key(&t->key_hash, key, size);
  t->private = private;
  return t;
}

trust_key hncp_crypto_gen_rsa_key(__unused hncp o, int key_size){
  trust_key t = malloc(sizeof(trust_key_s));
  if(crypto_gen_rsa_key(key_size, &t->ctx))
    goto fail;
  t->key_file = NULL;
  int r = crypto_key_to_raw(&t->ctx, &t->raw_key, true);
  if(r < 0)
    goto fail;
  t->size = (size_t) r;
  crypto_hash_from_key(&t->key_hash, &t->raw_key, t->size);
  t->private = true;
  return t;
fail:
  L_ERR("Fail to create key structure");
  free(t);
  return NULL;
}

int hncp_crypto_write_trusted_key(hncp o, trust_key c){
  if(!c->key_file){
    char *buf = malloc(FILENAME_MAX);
    char *strh = hash2str(&c->key_hash);
    sprintf(buf, "%s/%s.pub", o->trust->local_trust_dir, strh);
    c->key_file = buf;
  }
  return crypto_write_key_file(&c->ctx, c->key_file, c->private);
}
