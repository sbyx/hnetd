/*
 * hncp_trust.h
 *
 * Author: Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Web of trust extension for HNCP.
 *
 */

#ifndef HNCP_TRUST_H
#define HNCP_TRUST_H

#include "hncp_i.h"
#include "hncp_sign.h"
#include "trust_graph.h"
#include <libubox/vlist.h>
#include <libubox/list.h>
#include <polarssl/pk.h>
#include "hncp_crypto.h"

struct hncp_trust_struct{
  /* list of nodes in the graph, indexed by node hash */
  struct vlist_tree trust_graphs;

  hncp_subscriber_s sub;
  /* pointer to me in the graph */
  hncp_trust_graph my_graph;

  /* Array of locally trusted hashes */
  hncp_hash local_trust_array;
  unsigned int array_size;

  /* Contains keys, entropy & prng */
  struct crypto_data *crypto;

  /* whether the PKI is used (disabling only affect structure destruction) */
  bool crypto_used;

  /* version number of the local trust links */
  uint32_t tlv_version;


};

typedef struct hncp_trust_struct hncp_trust_s, *hncp_trust;

struct hash_list{
  struct list_head list;
  hncp_hash_s h;
};

/* Fetch a graph pointer from a node identifier hash pointer */
#define graph_from_hash(o, hash)\
  vlist_find(&(o->trust->trust_graphs), hash, o->trust->my_graph, vlist_node)

/** Hash comparison, for vlists */
static int __unused compare_hash(const void *hash1, const void *hash2, __unused void *c){
  return HASH_CMP(hash1, hash2);
};

/** Creates an empty web of trust
  *  -1 if the crypto init failed, else 0 */
int hncp_trust_init(hncp o, char * priv_key_file);

/** Checks if the tlv set (assumed to be ordered) is valid :
  * The key is valid
  * The node identifier hash is the md5 hash of the key
  * The signature is valid
  * There is only one hash, one key, one trust array, one signature */
bool hncp_trust_message_integrity_check(hncp o, struct tlv_attr *tlv_container);

/** Checks if the node hash is trusted */
bool hncp_trust_node_trusted(hncp o, hncp_hash hash);

/** Reverse trust check */
bool hncp_trust_node_trusts_me(hncp o, hncp_hash hash);

/** Update/create the trust graph with new trust links
 * trusted : array of hashes
 * size : size of the array */
void hncp_trust_update_graph(hncp o, hncp_hash emitter, hncp_hash trusted, int size);

/** Destroys everything, frees all memory */
void hncp_trust_destroy(hncp o);

/** Create the graph node, and put it into o if it doesn't exists
 * Fetch it otherwise */
hncp_trust_graph hncp_trust_get_graph_or_create_it(hncp o, hncp_hash hash);

#endif /* HNCP_TRUST_H */
