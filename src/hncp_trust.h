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
#include "local_trust.h"
#include <libubox/vlist.h>
#include <libubox/list.h>
#include <polarssl/pk.h>
#include "hncp_crypto.h"

struct key_list{
  struct list_head list;
  trust_key key;
};

struct hncp_trust_struct{
  /* list of nodes in the graph, indexed by node hash */
  struct vlist_tree trust_graphs;

  hncp_subscriber_s sub;

  /* Friend search :
   * Trust the neighbours, forget them if they don't trust back after a timeout */
  struct uloop_timeout friend_search_timeout;

  struct list_head temporary_friend_key_list;

  /* pointer to me in the graph */
  hncp_trust_graph my_graph;

  /* list of locally trusted hashes */
  struct vlist_tree local_trust;


  /* Contains keys, entropy & prng */
  struct crypto_data *crypto;

  hncp hncp;
  /* version number of the local trust links */
  uint32_t tlv_version;

  bool want_friend;

  /* whether the PKI is used (disabling for some unit testing) */
  bool crypto_used;


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
int compare_hash(const void *hash1, const void *hash2, __unused void *c);

/** Creates an empty web of trust
  *  -1 if the crypto init failed, else 0 */
int hncp_trust_init(hncp o, char * priv_key_file, char * trusted_key_dir);

/** Checks if the tlv set (assumed to be ordered) is valid :
  * The key is valid
  * The node identifier hash is the md5 hash of the key
  * The signature is valid
  * There is only one hash, one key, one trust array, one signature */
bool hncp_trust_message_integrity_check(hncp o, hncp_hash node_identifier_hash, struct tlv_attr *node_data_tlv);

/** Checks if the node hash is trusted */
bool hncp_trust_node_trusted(hncp o, hncp_hash hash);

/** Reverse trust check */
bool hncp_trust_node_trusts_me(hncp o, hncp_hash hash);

/** Add a new trust link */
void hncp_trust_add_trust_link(hncp o, hncp_hash emitter, hncp_hash target);

/** Revoke this trust link */
void hncp_trust_del_trust_link(hncp o, hncp_hash emitter, hncp_hash target);

/** Wrapper for the two preceding functions */
void hncp_trust_update_trusts_link(hncp o, hncp_hash emitter, hncp_hash target, bool add);

/** Destroys everything, frees all memory */
void hncp_trust_destroy(hncp o);

/** Create the graph node, and put it into o if it doesn't exists
 * Fetch it otherwise */
hncp_trust_graph hncp_trust_get_graph_or_create_it(hncp o, hncp_hash hash);

#endif /* HNCP_TRUST_H */
