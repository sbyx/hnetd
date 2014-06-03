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
#define PUBKEY_DIR "pub_cache"
#define CACHE_FILE "cache.key"
#define TRUST_PRIVATE_KEY_FILE "priv.key"

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
    char *c;
    pk_init(&ctx);

    crypto_gen_rsa_key(RSA_KEY_SIZE, & ctx);
    crypto_md5_hash_from_key(&h, &ctx, false);
    c = hash2str(&h);
    snprintf(buf, sizeof(buf), "%s/%s.pub", t_dir, c);
    crypto_write_key_file(&ctx, buf, false);
    free(c);
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
  hncp o = hncp_create();
  #ifdef FORCE_RSA_GEN
  remove(TRUST_PRIVATE_KEY_FILE);
  #endif // FORCE_RSA_GEN
  sput_fail_if(hncp_trust_init(o, TRUST_PRIVATE_KEY_FILE), "Init ok");
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
  sput_fail_unless(rsa_pub_equal(pk_rsa(o->trust->crypto->key.ctx), pk_rsa(ctx)), "Valid public key");
  remove(CACHE_FILE);
  pk_free(&ctx);
  hncp_trust_destroy(o);
  hncp_destroy(o);
}

void test_public_key(void){
  #ifdef FORCE_RSA_PUB_GEN
  char buf[FILENAME_MAX+8];
  snprintf(buf, sizeof(buf), "rm -r \"%s\"", PUBKEY_DIR);
  if(access(buf, F_OK))
    system(buf);
  #endif // FORCE_RSA_PUB_GEN
  hncp o = hncp_create();
  hncp_trust_init(o, TRUST_PRIVATE_KEY_FILE);
  populate_pubkey_dir(PUBKEY_DIR, RSA_PUB_KEY_NUM);
  hncp_crypto_get_trusted_keys(o, PUBKEY_DIR);

  for(int i = 0; i < RSA_PUB_KEY_NUM; i++){
    hncp_hash h = (hncp_hash) smock_pull("hash");
    char buf[100];
    sprintf(buf, "Node %i trusted", i);
    char * c = buf;
    sput_fail_unless(hncp_trust_node_trusted(o, h), c);
    free(h);
  }
  sput_fail_unless(smock_empty(), "Right number of hashes");
  hncp_trust_destroy(o);
  hncp_destroy(o);
}

int main(__unused int argc, __unused char **argv)
{
  openlog("test_hncp_crypto", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("rsa"); /* graph structure & links */
  sput_run_test(test_self_rsa);
  sput_run_test(test_public_key);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
