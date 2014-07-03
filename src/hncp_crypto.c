/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <stdio.h>
#include <polarssl/error.h>
#include "hncp_crypto.h"
#include "local_trust.h"

static void  update_trust_key(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  if(node_old && !node_new){
    trust_key k = container_of(node_old, trust_key_s, node);
    hncp_crypto_del_key(k);
    free(k);
  }
  /* else
  if(node_old && node_new)
  */
}

void print_polarssl_err(int err){
    char buf[512];
    polarssl_strerror(err, buf, sizeof(buf));
    printf("%s\n", buf);
    return;
}

trust_key hncp_crypto_key_from_hash(hncp o, hncp_hash hash){
  return vlist_find(&o->trust->crypto->trust_keys, hash, &o->trust->crypto->key, node);
}

void hncp_crypto_set_key_tlv(hncp o, trust_key k){
  hncp_remove_tlvs_by_type(o, HNCP_T_NODE_KEY);
  hncp_update_tlv_raw(o, HNCP_T_NODE_KEY, k->raw_key, k->size, true);
}

int hncp_crypto_init(hncp o, char * private_key_file, char * trusted_key_dir){

  o->trust->crypto = malloc(sizeof(struct crypto_data));
  hncp_crypto crypto = o->trust->crypto;
  pk_context* ctx = &crypto->key.ctx;
  pk_init(ctx);
  bool new_key = false;

  if(access(private_key_file, F_OK) == 0){
    if(pk_parse_keyfile(ctx, private_key_file, NULL)){
      L_ERR("Failed to parse key file");
      return 2;
    }
  }else{
    /* No file yet */
    if(crypto_gen_rsa_key(RSA_KEY_SIZE, ctx)){
      return 1;
    }
    new_key = true;
  }
  crypto->key_dir = strdup(trusted_key_dir);
  hncp_crypto_init_key(&crypto->key, private_key_file, true);
  entropy_init(&crypto->entropy);
  ctr_drbg_init(&crypto->ctr_drbg, ctr_drbg_random, &crypto->entropy, (const unsigned char *) "Sign/crypto", 11);

  if (new_key)
    hncp_crypto_write_trusted_key(o, &crypto->key, ".");
  hncp_set_own_hash(o, &crypto->key.key_hash);

  vlist_init(&crypto->trust_keys, compare_hash, update_trust_key);
  crypto->trust_keys.keep_old = false;
  crypto->trust_keys.no_delete = false;

  o->trust->crypto_used = true;

  crypto->sign_hash = SIGN_HASH_SHA512;
  crypto->sign_type = SIGN_TYPE_RSA_SSAPSS;
  hncp_crypto_set_key_tlv(o, &crypto->key);

  if(access(trusted_key_dir, F_OK))
    hncp_crypto_get_trusted_keys(o, trusted_key_dir);
  else
    mkdir(trusted_key_dir, 0700);
  return 0;
};

int hncp_crypto_get_trusted_keys(hncp o, char * trusted_dir){
  if(!trusted_dir)
    return -1;
  struct stat s;
  int ret = 0;
  if(stat(trusted_dir, &s)){
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
    sprintf(buf, "%s/%s", trusted_dir, ent->d_name);
    pk_init(&c->ctx);
    int r = pk_parse_public_keyfile(&c->ctx, buf);
    if(r){
      printf("On file %s :\n", buf);
      print_polarssl_err(r);
      pk_free(&c->ctx);
      free(buf);
      free(c);
      continue;
    }
    r = crypto_raw_from_key(&c->raw_key, &c->ctx, false);
    c->size = r;
    c->key_file = buf;
    c->locally_trusted = true;
    crypto_md5_hash_from_raw(&c->key_hash, c->raw_key, c->size);
    vlist_add(&o->trust->crypto->trust_keys, &c->node, &c->key_hash);
    local_trust_add_trusted_hash(o, &c->key_hash);
    ret++;
  }
  closedir(dir);
  return ret;
}

void hncp_crypto_set_trusted_key(hncp o, trust_key k, bool temporary){
  k->locally_trusted = true;
  if(!temporary)
    hncp_crypto_write_trusted_key(o, k, o->trust->crypto->key_dir);
  local_trust_add_trusted_hash(o, &k->key_hash);
}


void hncp_crypto_revoke_trusted_key(hncp o, trust_key k, bool was_temporary){
  if(!k->locally_trusted){
    L_WARN("Can't revoke a not trusted key");
    return;
  }
  k->locally_trusted = false;
  int r = remove(k->key_file);
  if(!was_temporary && r)
    L_ERR("Couldn't remove the key file of %s.", HEX_REPR(&k->key_hash, HNCP_HASH_LEN));
  local_trust_remove_trusted_hash(o, &k->key_hash);
}

void hncp_crypto_del_key(trust_key c){
  pk_free(&c->ctx);
  free(c->raw_key);
  free(c->key_file);
}

void hncp_crypto_del_data(struct crypto_data *data){
  vlist_flush_all(&data->trust_keys);
  hncp_crypto_del_key(&data->key);
  free(data->key_dir);
  free(data);
}

trust_key hncp_crypto_raw_key_to_trust_key(char * key, size_t size, bool private){
  trust_key t = malloc(sizeof(trust_key_s));
  crypto_key_from_raw(&t->ctx, (unsigned char *) key, size,private);
  hncp_crypto_init_key(t, NULL, private);
  return t;
}

void hncp_crypto_init_key(trust_key t, char * file_name, bool private){
  t->private = private;
  t->key_file = strdup(file_name);
  t->locally_trusted = false;
  int i  = crypto_raw_from_key(&t->raw_key, &t->ctx, false);
  if(i<0){
    print_polarssl_err(i);
    return;
  }
  t->size = i;
  crypto_md5_hash_from_raw(&t->key_hash, t->raw_key, t->size);
}

int hncp_crypto_write_trusted_key(__unused hncp o, trust_key c, char * trust_dir){
  if(!c->key_file){
    const char *strh = HEX_REPR(&c->key_hash, HNCP_HASH_LEN);
    char *buf = malloc(strlen(trust_dir) + strlen(strh)+6);
    sprintf(buf, "%s/%s.pub", trust_dir, strh);
    c->key_file = buf;
  }
  return crypto_write_key_file(&c->ctx, c->key_file, c->private);
}

int hncp_crypto_sign_tlvs(hncp o, uint16_t sign_type, uint16_t hash_type){
  if(!o->trust->crypto_used)
    return 0;
  struct crypto_data *d = o->trust->crypto;
  size_t sig_len;
  hncp_t_signature tlv = malloc(sizeof(hncp_t_signature)+POLARSSL_MPI_MAX_SIZE);

  tlv->hash_type = hash_type;
  tlv->sign_type = sign_type;
  crypto_hash_begin(&d->md_ctx, hash_type);
  hncp_tlv tlv_it;

  vlist_for_each_element(&o->tlvs, tlv_it, in_tlvs){
    if(tlv_id(&tlv_it->tlv) == HNCP_T_SIGNATURE)
      continue;
    crypto_hash_fill(&d->md_ctx, &tlv_it->tlv, tlv_len(&tlv_it->tlv));
  }

  unsigned char * hash = crypto_hash_end(&d->md_ctx);

  int r = crypto_make_signature(&d->ctr_drbg, &d->key.ctx, tlv->signature, &sig_len, hash, sign_type, hash_type);
  free(hash);

  if(!r){
    size_t final_len = sizeof(hncp_t_signature_s) + sig_len;
    hncp_remove_tlvs_by_type(o, HNCP_T_SIGNATURE);
    hncp_update_tlv_raw(o, HNCP_T_SIGNATURE, tlv, final_len, true);
  }
  free(tlv);
  return r;
}

int hncp_crypto_pk_encrypt_data(hncp o, trust_key k, char * data, size_t size, char ** encrypted_data, size_t* len, uint16_t crypt_type, uint16_t crypt_variant){
  size_t esize = crypto_pk_encrypt_max_out_size(&k->ctx, crypt_type);
  *encrypted_data = malloc(esize);
  return crypto_pk_encrypt_data(&o->trust->crypto->ctr_drbg, &k->ctx, data, size, (unsigned char *) *encrypted_data, len, esize, crypt_type, crypt_variant);
}

int hncp_crypto_pk_decrypt_data(hncp o, char * data, size_t size, char ** decrypted_data, size_t* len, uint16_t crypt_type, uint16_t crypt_variant){
  size_t esize = crypto_pk_encrypt_max_size(&o->trust->crypto->key.ctx, crypt_type, crypt_variant);
  *decrypted_data = malloc(esize);
  return crypto_pk_decrypt_data(&o->trust->crypto->ctr_drbg, &o->trust->crypto->key.ctx, data, size, (unsigned char *) *decrypted_data, len, esize, crypt_type, crypt_variant);
}

void hncp_crypto_local_update_callback(hncp_subscriber s, struct tlv_attr *tlv, __unused bool add){
  hncp_trust t = container_of(s, hncp_trust_s, sub);
  if(t->crypto_used){
    hncp o = t->hncp;
    if(tlv_id(tlv) != HNCP_T_SIGNATURE){
      if(hncp_crypto_sign_tlvs(o, t->crypto->sign_type, t->crypto->sign_hash))
        L_ERR("Failed to update signature");
    }
  }
}


/*
bool hncp_crypto_valid_signature()
*/
