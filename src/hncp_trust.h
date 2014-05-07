/*
 * hncp_trust.h
 *
 * Author: Xavier Bonnetain
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
/* Fetch a graph pointer from a node identifier hash pointer */
#define graph_from_hash(o, hash)\
  vlist_find(&(o->trust->trust_graphs), hash, o->trust->my_graph, vlist_node)

struct hncp_trust_struct{
  /* list of nodes in the graph, indexed by node hash */
  struct vlist_tree trust_graphs;
  /* pointer tp me in the graph */
  hncp_trust_graph my_graph;

  /* Array of locally trusted hashes */
  hncp_hash local_trust_array;
  unsigned int array_size;

  /* version number of the local trust links */
  uint32_t tlv_version;


};

struct hash_list{
  struct list_head list;
  hncp_hash_s h;
};

/** Creates an empty web of trust */
void hncp_trust_init(hncp o);
/** Checks if the hash is really derived from the key (TODO) */
bool hncp_trust_valid_key(hncp_hash hash, struct key* key);

/** Checks if the node hash is trusted */
bool hncp_trust_node_trusted(hncp o, hncp_hash hash);

/** Reverse trust check */
bool hncp_trust_node_trusts_me(hncp o, hncp_hash hash);

/** Update/create the trust graph with new trust links
 * l : array of hashes
 * size : size of the array */
void hncp_trust_update_graph(hncp o, hncp_hash emitter, hncp_hash l, int size);
/* Checks if some trust links are obsoleted, and updates the graph accordingly */
//void hncp_trust_time_update();
/** Destroys all the nodes & links */
static inline void hncp_trust_destroy_nodes(hncp o){
  vlist_flush_all(&o->trust->trust_graphs);
};
/** Destroys everything, frees all memory */
static inline void hncp_trust_destroy(hncp o){
  hncp_trust_destroy_nodes(o);
  free(o->trust->local_trust_array);
  free(o->trust);
}
/** Create the graph node, and put it into o if it doesn't exists
 * Fetch it otherwise */
hncp_trust_graph hncp_trust_get_graph_or_create_it(hncp o, hncp_hash hash);


#endif /* HNCP_TRUST_H */
