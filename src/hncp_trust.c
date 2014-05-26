/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include "hncp_trust.h"
#include <stdio.h>

/* Dummy : Everything is good and beautiful
bool hncp_trust_valid_key(hncp_hash hash, struct key* key){
    if( hash || key){};

    return true;
}; */


static int compare_hash(const void *hash1, const void *hash2, __unused void *c){
  return memcmp(hash1, hash2, HNCP_HASH_LEN);
};


static void update_trust_graph( __unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  if((!node_new) && node_old){
    /* Node destruction and memory free */
    hncp_trust_graph g = container_of(node_old, hncp_trust_graph_s, vlist_node);
    trust_graph_destroy(g);
  }

};

static void  update_trust_key(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  if(node_old && !node_new){
    hncp_crypto_del_key(container_of(node_old, trust_key_s, node));
  }
  /* else
  if(node_old && node_new)
  */
}
/* Add the graph node to the graph list. */
static inline void hncp_trust_add_node(hncp o, hncp_trust_graph g){
  vlist_add(&o->trust->trust_graphs,&g->vlist_node, &g->hash);
}

static inline hncp_trust_graph hncp_trust_create_graph(hncp o, const hncp_hash hash){
  hncp_trust_graph g = trust_graph_create(hash);
  hncp_trust_add_node(o, g);
  return g;
}

int hncp_trust_init(hncp o){
  hncp_trust s = malloc(sizeof(hncp_trust_s));
  //memset(s, 0, sizeof(hncp_trust_s));

  s->array_size = 0;
  s->local_trust_array = NULL;
  s->tlv_version = 0;

  vlist_init(&(s->trust_graphs), compare_hash, update_trust_graph);
  s->trust_graphs.keep_old = false;
  s->trust_graphs.no_delete = false;

  vlist_init(&(s->local_trust_keys), compare_hash, update_trust_key);
  s->local_trust_keys.keep_old = false;
  s->local_trust_keys.no_delete = false;

  hncp_hash own_hash = &(o->own_node->node_identifier_hash);
  /* No arrow yet */
  o->trust = s;
  s->my_graph = hncp_trust_create_graph(o, own_hash);
  s->my_graph->trusted = true;

  return hncp_crypto_init(o);
};

void hncp_trust_destroy(hncp o){
  hncp_trust t = o->trust;
  hncp_trust_destroy_nodes(o);
  if(t->local_trust_array)
    free(t->local_trust_array);
  vlist_flush_all(&t->local_trust_keys);
  pk_free(&t->ctx);
  free(t->local_trust_dir);
  free(t);
}

hncp_trust_graph hncp_trust_get_graph_or_create_it(hncp o, hncp_hash hash){
  hncp_trust_graph g = graph_from_hash(o, hash);
  if(!g)
    g = hncp_trust_create_graph(o, hash);
  return g;
}

void hncp_trust_flood_trust_links(hncp_trust_graph g){
  struct list_head head;
  INIT_LIST_HEAD(&head);
  if(g->trusted)
    add_graph_last(&head, g);
  while(!list_empty(&head)){
    struct _trusted_list* l = list_first_entry(&head, struct _trusted_list, list);
    g = l->node;
    struct _trusted_list* t;
    _for_each_trust_graph(g, t){
      if(!t->node->trusted){
        t->node->trusted = true;
        add_graph_last(&head, t->node);
      }
    }
    list_del(&l->list);
    free(l);
  }
};

void hncp_trust_recalculate_trust_links(hncp o){
  hncp_trust_graph g;
  vlist_for_each_element(&o->trust->trust_graphs, g, vlist_node){
    g->trusted = false;
  }
  o->trust->my_graph->trusted = true;
  hncp_trust_flood_trust_links(o->trust->my_graph);
}


void hncp_trust_update_graph(hncp o, hncp_hash emitter, hncp_hash trusted, int size){
  hncp_trust_graph g = hncp_trust_get_graph_or_create_it(o, emitter);
  bool empty = list_empty(&g->arrows);
  trust_graph_remove_trust_links(g);

  for(int i = 0; i < size; i++){
    hncp_trust_graph g_trusted = hncp_trust_get_graph_or_create_it(o, &trusted[i]);
    trust_graph_add_trust_link(g, g_trusted);
  };

  if(empty)
    hncp_trust_flood_trust_links(g);
  else
    hncp_trust_recalculate_trust_links(o);
}


bool hncp_trust_node_trusted(hncp o, hncp_hash hash){
  hncp_trust_graph g = graph_from_hash(o, hash);
  if(!g)
    return false;
  return g->trusted;
};


bool hncp_trust_node_trusts_me(hncp o, hncp_hash hash){
   hncp_trust_graph node = graph_from_hash(o, hash);
   if(!node)
    return false;
   return trust_graph_is_trusted(node, &(o->own_node->node_identifier_hash));
};
