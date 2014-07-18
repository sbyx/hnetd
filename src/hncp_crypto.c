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
#include <errno.h>

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

static int compare_symmetric_keys(const void *key1, const void *key2, __unused void *c){
  return memcmp(key1, key2, sizeof(struct key_id));
}

static void update_symmetric_key(__unused struct vlist_tree *t, __unused struct vlist_node *node_new, struct vlist_node *node_old){
  if(node_old){
    hncp_shared_key s = container_of(node_old, hncp_shared_key_s, node);
    cipher_free_ctx(&s->ctx);
    free(s);
  }
}

void print_polarssl_err(int err){
    char buf[512];
    polarssl_strerror(err, buf, sizeof(buf));
    L_ERR("%s", buf);
    return;
}

trust_key hncp_crypto_key_from_hash(hncp o, hncp_hash hash){
  return vlist_find(&o->trust->crypto->trust_keys, hash, &o->trust->crypto->key, node);
}

void hncp_crypto_set_key_tlv(hncp o, trust_key k){
  unsigned char * raw_key;
  /* Don't use k->raw_key, as we do NOT want to advertise the private key */
  int size = crypto_raw_from_key(&raw_key, &k->ctx, false);
  hncp_remove_tlvs_by_type(o, HNCP_T_NODE_KEY);
  hncp_update_tlv_raw(o, HNCP_T_NODE_KEY, raw_key, size, true);
  free(raw_key);
}

int hncp_crypto_init(hncp o, char * private_key_file, char * trusted_key_dir){
  int r;
  o->trust->crypto = malloc(sizeof(struct crypto_data));
  hncp_crypto crypto = o->trust->crypto;
  pk_context* ctx = &crypto->key.ctx;
  pk_init(ctx);
  bool new_key = false;

  if(access(private_key_file, F_OK) == 0){
    r = pk_parse_keyfile(ctx, private_key_file, NULL);
    if(r){
      L_ERR("Failed to parse key file");
      return r;
    }
  }else{
    /* No file yet */
    r = crypto_gen_rsa_key(RSA_KEY_SIZE, ctx);
    if(r){
      L_ERR("Failed to generate a key");
      return r;
    }

    new_key = true;
  }

  crypto->key_dir = trusted_key_dir ? strdup(trusted_key_dir) : NULL;
  hncp_crypto_init_key(&crypto->key, private_key_file, true);
  entropy_init(&crypto->entropy);
  ctr_drbg_init(&crypto->ctr_drbg, ctr_drbg_random, &crypto->entropy, (const unsigned char *) "Sign/crypto", 11);

  if (new_key)
    r = hncp_crypto_write_trusted_key(o, &crypto->key, ".");
  if(r)
    return r;

  r = !hncp_set_own_hash(o, &crypto->key.key_hash);

  vlist_init(&crypto->trust_keys, compare_hash, update_trust_key);
  crypto->trust_keys.keep_old = false;
  crypto->trust_keys.no_delete = false;

  vlist_init(&crypto->symmetric_keys, compare_symmetric_keys, update_symmetric_key);
  crypto->symmetric_keys.keep_old = false;
  crypto->symmetric_keys.no_delete = false;
  o->trust->crypto_used = true;

  crypto->sign_type = SIGN_TYPE_RSA_SSAPSS_SHA512;

  crypto->own_symmetric_key = NULL;
  crypto->symmetric_key_emitter = false;

  hncp_crypto_set_key_tlv(o, &crypto->key);

  o->trust->my_graph = hncp_trust_get_graph_or_create_it(o, &o->own_node->node_identifier_hash);
  hncp_trust_recalculate_trust_links(o);

  if(hncp_crypto_get_trusted_keys(o, trusted_key_dir))
    crypto->temporary_only = true;
  else
    crypto->temporary_only = false;

  crypto->own_symmetric_key = NULL;
  crypto->symmetric_key_emitter = false;
  crypto_init_empty_cipher(&crypto->used_symmetric_key.ctx);
  return r;
};

int hncp_crypto_get_trusted_keys(hncp o, char * trusted_dir){
  if(!trusted_dir)
    return -1;
  struct stat s;
  int ret = 0;
  if(stat(trusted_dir, &s)){
    if(mkdir(trusted_dir, 0700))
      goto fail_dir;
  }
  if(!S_ISDIR(s.st_mode)){
    goto fail_dir;
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
      L_ERR("On file %s :", buf);
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
    c->encryption_type = crypto_crypt_type_from_ctx(&c->ctx);
    crypto_md5_hash_from_raw(&c->key_hash, c->raw_key, c->size);
    vlist_add(&o->trust->crypto->trust_keys, &c->node, &c->key_hash);
    local_trust_add_trusted_hash(o, &c->key_hash);
    ret++;
  }
  closedir(dir);
  return ret;
fail_dir:
  L_ERR("failed to create directory %s. Trust will be temporary.", trusted_dir);
  return 2;

}


void hncp_crypto_set_trusted_key(hncp o, trust_key k, bool temporary){
  if(!k){
    L_ERR("Public key not found");
    return;
  }
  k->locally_trusted = true;
  if(!temporary && !o->trust->crypto->temporary_only)
    hncp_crypto_write_trusted_key(o, k, o->trust->crypto->key_dir);
  local_trust_add_trusted_hash(o, &k->key_hash);
}


void hncp_crypto_mistrust_trusted_key(hncp o, trust_key k, bool was_temporary){
  if(!k->locally_trusted){
    L_WARN("Can't revoke a key not trusted");
    return;
  }
  k->locally_trusted = false;
  if(!was_temporary && !o->trust->crypto->temporary_only){
    int r = remove(k->key_file);
    if(r)
      L_ERR("Couldn't remove the key file of %s.", HEX_REPR(&k->key_hash, HNCP_HASH_LEN));
  }
  local_trust_remove_trusted_hash(o, &k->key_hash);
}

void hncp_crypto_del_key(trust_key c){
  pk_free(&c->ctx);
  free(c->raw_key);
  free(c->key_file);
}

void hncp_crypto_del_data(struct crypto_data *data){
  vlist_flush_all(&data->trust_keys);
  vlist_flush_all(&data->symmetric_keys);
  hncp_crypto_del_key(&data->key);
  free(data->own_symmetric_key);
  cipher_free_ctx(&data->used_symmetric_key.ctx);
  free(data->key_dir);
  free(data);
}

trust_key hncp_crypto_raw_key_to_trust_key(char * key, size_t size, bool private){
  trust_key t = malloc(sizeof(trust_key_s));
  crypto_key_from_raw(&t->ctx, (unsigned char *) key, size,private);
  hncp_crypto_init_key(t, "", private);
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
  t->encryption_type = crypto_crypt_type_from_ctx(&t->ctx);
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

int hncp_crypto_sign_tlvs(hncp o, uint32_t sequence_number, uint16_t sign_type){
  if(!o->trust->crypto_used)
    return 0;
  struct crypto_data *d = o->trust->crypto;
  size_t sig_len;
  hncp_t_signature tlv = malloc(sizeof(hncp_t_signature)+POLARSSL_MPI_MAX_SIZE);

  tlv->sign_type = sign_type;
  crypto_hash_begin(&d->md_ctx, polarssl_sign_digest_wrapper(sign_type));
  crypto_hash_fill(&d->md_ctx, &sequence_number, sizeof(uint32_t));

  hncp_tlv tlv_it;

  vlist_for_each_element(&o->tlvs, tlv_it, in_tlvs){
    if(tlv_id(&tlv_it->tlv) == HNCP_T_SIGNATURE)
      continue;
    crypto_hash_fill(&d->md_ctx, &tlv_it->tlv, tlv_len(&tlv_it->tlv));
  }

  unsigned char * hash = crypto_hash_end(&d->md_ctx);

  int r = crypto_make_signature(&d->ctr_drbg, &d->key.ctx, tlv->signature, &sig_len, hash, sign_type);
  free(hash);

  if(!r){
    size_t final_len = sizeof(hncp_t_signature_s) + sig_len;
    hncp_remove_tlvs_by_type(o, HNCP_T_SIGNATURE);
    hncp_update_tlv_raw(o, HNCP_T_SIGNATURE, tlv, final_len, true);
  }
  free(tlv);
  return r;
}

void hncp_crypto_make_own_shared_key(hncp o, uint16_t key_type){
  hncp_crypto c = o->trust->crypto;
  hncp_shared_key sk = malloc(sizeof(hncp_shared_key_s));
  crypto_init_empty_cipher(&sk->ctx);
  sk->identifier.emitter = o->own_node->node_identifier_hash;
  sk->identifier.id = 1;
  sk->key_type = key_type;
  size_t key_len = crypto_symmetric_key_length(key_type);
  c->own_symmetric_key = malloc(key_len);
  crypto_gen_random(&o->trust->crypto->ctr_drbg, c->own_symmetric_key, key_len);
  crypto_change_symmetric_cipher(&sk->ctx, c->own_symmetric_key, key_type, false);
  vlist_add(&c->symmetric_keys, &sk->node, &sk->identifier);
  hncp_crypto_set_shared_key(o, c->own_symmetric_key, &sk->identifier, key_type);
  c->symmetric_key_emitter = true;
}

void hncp_crypto_set_shared_key(hncp o, const char *key, struct key_id * id, uint16_t key_type){
  hncp_crypto c = o->trust->crypto;
  crypto_change_symmetric_cipher(&c->used_symmetric_key.ctx, key, key_type, true);
  c->used_symmetric_key.identifier = *id;
  c->used_symmetric_key.key_type = key_type;
}

void hncp_crypto_set_shared_key_tlv(hncp o, hncp_hash target){
  hncp_crypto c = o->trust->crypto;
  size_t len;
  char * encrypted_data;
  trust_key target_key = hncp_crypto_key_from_hash(o, target);
  hncp_crypto_pk_encrypt_data(o, target_key, c->own_symmetric_key, crypto_symmetric_key_length(c->used_symmetric_key.key_type),&encrypted_data, &len);
  hncp_t_shared_key tlv = alloca(sizeof(hncp_t_shared_key_s)+len);
  tlv->key_id = c->used_symmetric_key.identifier.id;
  tlv->target = *target;
  tlv->crypt_type = htobe16(c->used_symmetric_key.key_type);

  memcpy(tlv->encrypted_key, encrypted_data, len);
  free(encrypted_data);
  hncp_update_tlv_raw(o, HNCP_T_SHARED_KEY, tlv, sizeof(hncp_t_shared_key_s)+len, true);
}

int hncp_crypto_pk_encrypt_data(hncp o, trust_key k, char * data, size_t size, char ** encrypted_data, size_t* len){
  size_t esize = crypto_pk_encrypt_max_out_size(&k->ctx, k->encryption_type);
  *encrypted_data = malloc(esize);
  return crypto_pk_encrypt_data(&o->trust->crypto->ctr_drbg, &k->ctx, data, size, (unsigned char *) *encrypted_data, len, esize, k->encryption_type);
}

int hncp_crypto_pk_decrypt_data(hncp o, char * data, size_t size, char ** decrypted_data, size_t* len){
  hncp_crypto c = o->trust->crypto;
  size_t esize = crypto_pk_encrypt_max_size(&c->key.ctx, c->key.encryption_type);
  *decrypted_data = malloc(esize);
  return crypto_pk_decrypt_data(&c->ctr_drbg, &c->key.ctx, data, size, (unsigned char *) *decrypted_data, len, esize, c->key.encryption_type);
}

int hncp_crypto_cipher_encrypt(hncp o, char * data, size_t size, char ** encrypted_data, size_t * len, char *iv, size_t iv_len){
  hncp_shared_key sk = &o->trust->crypto->used_symmetric_key;
  return crypto_cipher_encrypt(&sk->ctx, sk->key_type, encrypted_data, len, data, size, iv, iv_len);
}

int hncp_crypto_cipher_decrypt(hncp o, struct key_id* key_id,  char * data, size_t size, char ** decrypted_data, size_t * len, char *iv, size_t iv_len){
  hncp_shared_key sk = vlist_find(&o->trust->crypto->symmetric_keys, key_id, &o->trust->crypto->used_symmetric_key, node);
  if(!sk){
    L_ERR("Key for decryption not found");
    return POLARSSL_ERR_CIPHER_BAD_INPUT_DATA;
  }
  return crypto_cipher_decrypt(&sk->ctx, sk->key_type, decrypted_data, len, data, size, iv, iv_len);
}


