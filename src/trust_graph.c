/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */


#include "trust_graph.h"


void init_explo(struct list_head* l, hncp_trust_graph g){
  INIT_LIST_HEAD(l);
  add_graph_last(l, g);
}


/* Remove marking after an explo, and free the list used for that */
static void trust_graph_to_reset(struct list_head* l){
  while(!list_empty(l)){
    struct _trusted_list* e = list_first_entry(l, struct _trusted_list, list);
    e->node->marked = false;
    list_del(&e->list);
    free(e);
  }
};


bool trust_graph_is_trusted(hncp_trust_graph g, hncp_hash node_hash){
  struct list_head l;
  init_explo(&l, g);
  bool result = false;
  if(memcmp(node_hash, &(g->hash), HNCP_HASH_LEN) == 0){
    result = true;
    goto end;
  };
  g->marked = true;
  struct _trusted_list* entry;
  list_for_each_entry(entry, &l, list){
    hncp_trust_graph graph = entry->node;
    struct _trusted_list* item;
    _for_each_trust_graph(graph, item){
      hncp_trust_graph node = item->node;
      if(!node->marked){
        if(memcmp(node_hash, &(node->hash),HNCP_HASH_LEN) == 0){
          /* Node found */
          result = true;
          goto end;
        };
        /* Adding node to the explo list */
        node->marked = true;
        add_graph_last(&l, node);
      };
    };
  };
end:
  /*resets graph, free list */
  trust_graph_to_reset(&l);
  return result;
};


void trust_graph_add_trust_link(hncp_trust_graph emitter, hncp_trust_graph trusted){
  struct _trusted_list *link = malloc(sizeof(struct _trusted_list));
  if(!link){
    L_ERR("Failed to add a trust link");
    return;
  }
  link->node = trusted;
  list_add_tail(&link->list,&emitter->arrows);
};

void trust_graph_add_trust_array(hncp_trust_graph emitter, hncp_trust_graph array[], unsigned int size){
  for(unsigned int i = 0; i<size; i++)
    trust_graph_add_trust_link(emitter, array[i]);
};


bool trust_graph_remove_trust_link(hncp_trust_graph emitter, hncp_trust_graph trusted){
  struct _trusted_list* entry;
  list_for_each_entry(entry, &emitter->arrows, list){
    if(entry->node == trusted){
      list_del(&entry->list);
      free(entry);
      return true;
    }
  }
  return false;
};


void trust_graph_remove_trust_links(hncp_trust_graph g){
  while(!list_empty(&g->arrows)){
    struct _trusted_list* e = list_first_entry(&g->arrows, struct _trusted_list, list);
    list_del(&e->list);
    free(e);
  }
};
