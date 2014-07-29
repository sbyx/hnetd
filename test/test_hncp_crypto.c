/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */


#include "hncp_crypto.h"
#include "hncp_trust.h"
#include "sput.h"
#include "smock.h"
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <polarssl/pk.h>
#include <polarssl/rsa.h>

/* Force to regen rsa private key. Comment to fasten.
 * (Notable difference when using valgrind) */
//#define FORCE_RSA_GEN
/* Force to regen rsa key pool */
//#define FORCE_RSA_PUB_GEN

#define RSA_PUB_KEY_NUM 3
#define PUBKEY_DIR "hncp-pki-trust"
#define CACHE_FILE "cache.key"
#define TRUST_PRIVATE_KEY_FILE "hncp-pki.key"

int log_level = LOG_DEBUG;


/* Fake structures to keep pa's default config happy. */
void *iface_register_user;
void *iface_unregister_user;

struct iface* iface_get( __unused const char *ifname )
{
  return NULL;
}

void iface_all_set_dhcp_send(__unused const void *dhcpv6_data, __unused size_t dhcpv6_len,
                             __unused const void *dhcp_data, __unused size_t dhcp_len)
{
}

#define MPI_CHECK(a,b,C) ((mpi_cmp_mpi(&a->C, &b->C) == 0) )

bool rsa_priv_equal(rsa_context* a, rsa_context* b){
  return MPI_CHECK(a, b, D ) && MPI_CHECK(a, b, DP) && MPI_CHECK(a, b, DQ) \
      && MPI_CHECK(a, b, E ) && MPI_CHECK(a, b, N ) && MPI_CHECK(a, b, P ) \
      && MPI_CHECK(a, b, Q ) && MPI_CHECK(a, b, QP);
}

static inline bool rsa_pub_equal(rsa_context* a, rsa_context* b){
  return MPI_CHECK(a, b, N) && MPI_CHECK(a, b, E);
}

/* Function to add a pool of RSA 2048 public keys in a directory */
void populate_pubkey_dir(char *t_dir, int num){
  struct dirent *ent;
  DIR *dir = opendir(t_dir);

  int d = 0;
  pk_context ctx;
  char buf[FILENAME_MAX];

  if(!dir)
    goto mkdir;

  while((ent = readdir(dir)) != NULL){
    if(ent->d_type != DT_REG)
      continue;
    pk_init(&ctx);
    snprintf(buf, sizeof(buf),"%s/%s", t_dir, ent->d_name);
    if(!pk_parse_public_keyfile(&ctx, buf))
      d++;
    pk_free(&ctx);
  }
  closedir(dir);

mkdir:
  mkdir(t_dir, 0770);
  for(int i = d; i<num; i++){
    pk_context ctx;
    hncp_hash_s h;
    char buf[FILENAME_MAX];

    pk_init(&ctx);

    crypto_gen_rsa_key(RSA_KEY_SIZE, & ctx);
    crypto_md5_hash_from_key(&h, &ctx, false);
    snprintf(buf, sizeof(buf), "%s/%s.pub", t_dir, HEX_REPR(&h, HNCP_HASH_LEN));
    crypto_write_key_file(&ctx, buf, false);
    pk_free(&ctx);
  }

  dir = opendir(t_dir);

  while((ent = readdir(dir)) != NULL){
    if(ent->d_type != DT_REG)
      continue;
    pk_init(&ctx);
    sprintf(buf, "%s/%s", t_dir, ent->d_name);

    if(!pk_parse_public_keyfile(&ctx, buf)){
      hncp_hash h = malloc(sizeof(hncp_hash_s));
      crypto_md5_hash_from_key(h, &ctx, false);
      pk_free(&ctx);
      smock_push("hash", h);
    }
  }
  closedir(dir);
}

void test_self_rsa(void){
  hncp o = hncp_create(true);
  #ifdef FORCE_RSA_GEN
  remove(TRUST_PRIVATE_KEY_FILE);
  #endif // FORCE_RSA_GEN
  hncp_hash_s h;
  crypto_md5_hash_from_key(&h, &o->trust->crypto->key.ctx, false);
  sput_fail_unless(HASH_EQUALS(&h, &o->own_node->node_identifier_hash), "Hash derived from key");
  sput_fail_if(rsa_check_privkey(pk_rsa(o->trust->crypto->key.ctx)), "Valid key");
  pk_context ctx;
  pk_init(&ctx);

  sput_fail_if(crypto_write_key_file(&o->trust->crypto->key.ctx, CACHE_FILE, true), "Private key written to file");
  sput_fail_if(pk_parse_keyfile(&ctx, CACHE_FILE, NULL), "File parsing ok");
  sput_fail_if(rsa_check_privkey(pk_rsa(ctx)), "Valid parsed key");
  rsa_priv_equal(pk_rsa(o->trust->crypto->key.ctx), pk_rsa(ctx));
  sput_fail_unless(rsa_priv_equal(pk_rsa(o->trust->crypto->key.ctx), pk_rsa(ctx)), "Same keys");
  pk_free(&ctx);
  pk_init(&ctx);
  sput_fail_if(crypto_write_key_file(&o->trust->crypto->key.ctx, CACHE_FILE, false), "Public key written to file");
  sput_fail_if(pk_parse_public_keyfile(&ctx, CACHE_FILE), "File parsing ok");
  hncp_run(o);
  sput_fail_unless(rsa_pub_equal(pk_rsa(o->trust->crypto->key.ctx), pk_rsa(ctx)), "Valid public key");
  remove(CACHE_FILE);
  pk_free(&ctx);
  hncp_destroy(o);
}

void test_public_key(void){
  #ifdef FORCE_RSA_PUB_GEN
  char buf[FILENAME_MAX+8];
  snprintf(buf, sizeof(buf), "rm -r \"%s\"", PUBKEY_DIR);
  if(access(buf, F_OK))
    system(buf);
  #endif // FORCE_RSA_PUB_GEN
  populate_pubkey_dir(PUBKEY_DIR, RSA_PUB_KEY_NUM);
  hncp_s s;
  hncp o = &s;
  hncp_init(o, "hncp-pki", 0, true);

  for(int i = 0; i < RSA_PUB_KEY_NUM; i++){
    hncp_hash h = (hncp_hash) smock_pull("hash");
    char buf[100];
    sprintf(buf, "Node %i trusted", i);
    char * c = buf;
    sput_fail_unless(hncp_trust_node_trusted(o, h), c);
    trust_key k = hncp_crypto_key_from_hash(o, h);
    hncp_crypto_mistrust_trusted_key(o, k, true);
    sprintf(buf, "Node %i mistrusted", i);
    sput_fail_if(hncp_trust_node_trusted(o, h), c);
    hncp_crypto_set_trusted_key(o, k, true);
    sprintf(buf, "Node %i trusted again", i);
    sput_fail_unless(hncp_trust_node_trusted(o, h), c);
    free(h);
  }
  sput_fail_unless(smock_empty(), "Right number of hashes");
  hncp_run(o);
  sput_fail_unless(
    hncp_trust_message_integrity_check(
      o, &o->own_node->node_identifier_hash, htonl(o->own_node->update_number), o->own_node->tlv_container),
      "Valid published tlvs");

  trust_key k = hncp_crypto_raw_key_to_trust_key((char *)o->trust->crypto->key.raw_key, o->trust->crypto->key.size, false);
  vlist_add(&o->trust->crypto->trust_keys, &k->node, &k->key_hash);
  hncp_crypto_make_own_shared_key(o, SYMMETRIC_CRYPT_TYPE_AES_CBC_256);
  hncp_crypto_set_shared_key_tlv(o, &o->own_node->node_identifier_hash);

  hncp_tlv tlv_it;
  bool found = false;
  vlist_for_each_element(&o->tlvs, tlv_it, in_tlvs){
    if(tlv_id(&tlv_it->tlv) != HNCP_T_SHARED_KEY)
      continue;
    found = true;
    break;
  }
  sput_fail_unless(found, "Shared key advertised");
  hncp_t_shared_key sk = (hncp_t_shared_key) &tlv_it->tlv.data;
  char * decrypted;
  size_t len = 42;
  hncp_crypto_pk_decrypt_data(o, (char *)sk->encrypted_key, tlv_len(&tlv_it->tlv)-sizeof(hncp_t_shared_key_s), &decrypted, &len);
  sput_fail_unless(len == crypto_symmetric_key_length(o->trust->crypto->used_symmetric_key.key_type), "Encrypted key length ok");
  sput_fail_unless(o->trust->crypto->used_symmetric_key.key_type == be16toh(sk->crypt_type), "Encrypted key type ok");

  sput_fail_unless(memcmp(decrypted, o->trust->crypto->own_symmetric_key, len) == 0, "same key decoded");
  free(decrypted);
  hncp_uninit(o);
}

int main(__unused int argc, __unused char **argv)
{
  openlog("test_hncp_crypto", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("rsa"); /* graph structure & links */
  sput_run_test(test_self_rsa);
  sput_leave_suite();
  sput_enter_suite("pk");
  sput_run_test(test_public_key);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
