/*
 * Author : Xavier Bonnetain
 *
 * Manages the Trust Link TLVs & Local node trust graph.
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */


#include "local_trust.h"

struct local_trust_struct{
  struct vlist_node node;
  hncp_hash_s node_hash;
};

typedef struct local_trust_struct local_trust_s, *local_trust;


static void update_local_trust(struct vlist_tree *tree, struct vlist_node *node_new, struct vlist_node *node_old){
    hncp_trust t = container_of(tree, hncp_trust_s, local_trust);
    hncp o = t->hncp;
    /* Get the new container if it's really new, and the old otherwise. */
    local_trust l = node_old ? container_of(node_old, local_trust_s, node) : container_of(node_new, local_trust_s, node);

    /* Take care of the TLV in cas of creation/destruction */
    if((!node_new) ^ (!node_old)){
        hncp_trust_update_trusts_link(o, &o->own_node->node_identifier_hash, &l->node_hash, node_new);
        hncp_t_trust_link tlv = alloca(sizeof(hncp_t_trust_link_s));
        tlv->trusted_hash = l->node_hash;
        hncp_update_tlv_raw(o, HNCP_T_TRUST_LINK, tlv, sizeof(hncp_t_trust_link_s), node_new);
      }

    /* Supress old link, if any */
    if(node_old){
      free(l);
    }
};

void local_trust_init(hncp o){
  hncp_trust t = o->trust;
  vlist_init(&t->local_trust, compare_hash, update_local_trust);
  t->local_trust.keep_old = false;
  t->local_trust.no_delete = false;
}

void local_trust_add_trusted_hash(hncp o, hncp_hash h){
  hncp_trust t = o->trust;
  local_trust l = malloc(sizeof(local_trust_s));
  l->node_hash = *h;
  vlist_add(&t->local_trust, &l->node, &l->node_hash);

}

bool local_trust_remove_trusted_hash(hncp o, hncp_hash h){
  hncp_trust t = o->trust;
  local_trust l;
  l = vlist_find(&t->local_trust, h, l, node);
  if(l){
    vlist_delete(&t->local_trust, &l->node);
    return true;
  }
  return false;
}


void local_trust_purge_trusted_list(hncp o){
  vlist_flush_all(&o->trust->local_trust);
}
