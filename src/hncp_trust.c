/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include "hncp_trust.h"
#include <stdio.h>


static void update_trust_graph( __unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  if((!node_new) && node_old){
    /* Node destruction and memory free */
    hncp_trust_graph g = container_of(node_old, hncp_trust_graph_s, vlist_node);
    trust_graph_destroy(g);
  }
};


static void hncp_trust_tlv_update_callback(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add);

static void hncp_trust_local_tlv_callback(hncp_subscriber s, struct tlv_attr *tlv, bool add);

static void hncp_trust_node_change_callback(hncp_subscriber s, hncp_node n, bool add);

/* Add the graph node to the graph list. */
static inline void hncp_trust_add_node(hncp o, hncp_trust_graph g){
  vlist_add(&o->trust->trust_graphs,&g->vlist_node, &g->hash);

}

static inline hncp_trust_graph hncp_trust_create_graph(hncp o, const hncp_hash hash){
  hncp_trust_graph g = trust_graph_create(hash);
  hncp_trust_add_node(o, g);
  return g;
}

int hncp_trust_init(hncp o, char * private_key_file){
  hncp_trust s = malloc(sizeof(hncp_trust_s));
  //memset(s, 0, sizeof(hncp_trust_s));
  if(!s)
    return -1;
  s->array_size = 0;
  s->local_trust_array = NULL;
  s->tlv_version = 0;

  vlist_init(&(s->trust_graphs), compare_hash, update_trust_graph);
  s->trust_graphs.keep_old = false;
  s->trust_graphs.no_delete = false;

  int r = 0;
  o->trust = s;
  s->hncp = o;
  s->crypto_used = false;

  s->want_friend = false;

  /* Don't consider random adresses as functions */
  memset(&s->sub, 0, sizeof(hncp_subscriber_s));

  if(private_key_file){
    r = hncp_crypto_init(o, private_key_file);
    s->sub.local_tlv_change_callback = hncp_trust_local_tlv_callback;
    s->sub.tlv_change_callback = hncp_trust_tlv_update_callback;
  }
  s->sub.node_change_callback = hncp_trust_node_change_callback;
  hncp_hash own_hash = &(o->own_node->node_identifier_hash);
  /* No arrow yet */

  s->my_graph = hncp_trust_create_graph(o, own_hash);
  s->my_graph->trusted = true;

  hncp_subscribe(o, &s->sub);

  return r;
};

void hncp_trust_destroy(hncp o){
  hncp_trust t = o->trust;
  if(t->crypto_used) hncp_crypto_del_data(t->crypto);
  t->crypto_used = false;
  hncp_unsubscribe(o, &t->sub);
  vlist_flush_all(&o->trust->trust_graphs);
  if(t->local_trust_array)
    free(t->local_trust_array);

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
  if(g->trusted){
    add_graph_last(&head, g);
  }
  while(!list_empty(&head)){
    struct _trusted_list* l = list_first_entry(&head, struct _trusted_list, list);
    g = l->node;
    struct _trusted_list* t;
    _for_each_trust_graph(g, t){
      if(!t->node->trusted){
        t->node->trusted = true;
        if(t->node->hncp_node)
          t->node->hncp_node->trusted = true;
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

  hncp_node n;
  hncp_for_each_node(o, n){
    n->trusted = false;
  }

  o->own_node->trusted = true;
  o->trust->my_graph->trusted = true;
  hncp_trust_flood_trust_links(o->trust->my_graph);
}

/** Update/create the trust graph with new trust links
 * trusted : array of hashes
 * size : size of the array */
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

/** Callbacks */

/** Two things :
  * a function to check the validity of the message (hncp_trust_message_integrity_check() )
  * functions to parse the tlvs (using subscription stuff) (at this time, only key & trust links) */
void hncp_trust_update_key(hncp_subscriber s, __unused hncp_node n, struct tlv_attr *tlv, bool add){
  if(add){
    hncp_trust t = container_of(s, hncp_trust_s, sub);
    trust_key k = hncp_crypto_raw_key_to_trust_key(tlv->data, tlv_len(tlv), false);
    vlist_add(&t->crypto->trust_keys, &k->node, &k->key_hash);
  }
}

void hncp_trust_update_trusts_links(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add){
  hncp_t_trust_link ta = (hncp_t_trust_link) &tlv->data;
  hncp_trust t = container_of(s, hncp_trust_s, sub);
  if(t->want_friend && HASH_EQUALS(&ta->trusted_hash, &t->hncp->own_node->node_identifier_hash)){
    trust_key k = hncp_crypto_key_from_hash(t->hncp, &n->node_identifier_hash);
    if(!k)
      L_ERR("Public key for %s not found !", HEX_REPR(&n->node_identifier_hash, HNCP_HASH_LEN));
    else{
      k->locally_trusted = true;
      local_trust_add_trusted_hash(t->hncp, &n->node_identifier_hash, true);
    }
  }
  if(add){
    hncp_trust_update_graph(t->hncp, &n->node_identifier_hash, &ta->trusted_hash, 1);
  }else
    hncp_trust_update_graph(t->hncp, &n->node_identifier_hash, NULL, 0);
}

/* The signature_tlv must be a pointer to the last element of tlvs */
bool _hncp_trust_integrity_check(hncp o, unsigned char *tlvs, hncp_hash h, struct tlv_attr *node_key_tlv,
                                                  struct tlv_attr *signature_tlv){

  unsigned char * raw_key = (unsigned char *) node_key_tlv->data;
  size_t key_size = tlv_len(node_key_tlv);

  if(! crypto_hash_derived_from_raw(h, raw_key, key_size))
    return false;

  trust_key t = hncp_crypto_key_from_hash(o, h);
  pk_context *ctx;
  if(!t){
    ctx = alloca(sizeof(pk_context));
  if(crypto_key_from_raw(ctx, raw_key, key_size, false)){
    pk_free(ctx);
    return false;
    }
  }else
    ctx = &t->ctx;

  hncp_t_signature sign = (hncp_t_signature) signature_tlv->data;
  size_t len = ((unsigned char *) signature_tlv) - tlvs;
  bool r = crypto_verify_signature(sign, ctx, tlvs, len);
  if(!t)
    pk_free(ctx);
  return r;
}

bool hncp_trust_message_integrity_check(hncp o, hncp_hash identifier_hash, struct tlv_attr *tlv_container){
  struct tlv_attr *node_key_tlv = NULL;
  struct tlv_attr *signature_tlv = NULL;

  struct tlv_attr *iter_tlv;
  unsigned int id;
  unsigned int uid = 0; /* Tlv id begins at 1 */
  tlv_for_each_attr(iter_tlv, tlv_container){
    id = tlv_id(iter_tlv);
    /* Reject if the trust tlvs (key, signature, trust links) are not unique */
    if(id == uid)
      return false;
    switch(id){
      case HNCP_T_NODE_DATA_KEY:
        node_key_tlv = iter_tlv;
        goto end_unique;
      case HNCP_T_SIGNATURE:
        signature_tlv = iter_tlv;
      end_unique:
        uid = tlv_id(iter_tlv);
    }
  }
  if(!node_key_tlv || !signature_tlv)
    return false;
 return _hncp_trust_integrity_check(o, (unsigned char *) tlv_container->data, identifier_hash, node_key_tlv, signature_tlv);
}

static void hncp_trust_local_tlv_callback(hncp_subscriber s, struct tlv_attr *tlv, bool add){
  hncp_crypto_local_update_callback(s, tlv, add);
}

static void hncp_trust_tlv_update_callback(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add){
  if(hncp_node_is_self(n))
    return;
  switch(tlv_id(tlv)){
    case HNCP_T_NODE_DATA_KEY:
      hncp_trust_update_key(s, n, tlv, add);
      break;
    case HNCP_T_TRUST_LINK:
      hncp_trust_update_trusts_links(s, n, tlv, add);
  }
}

static void hncp_trust_node_change_callback(hncp_subscriber s, hncp_node n, bool add){
  hncp_trust t = container_of(s, hncp_trust_s, sub);
  hncp_trust_graph g = hncp_trust_get_graph_or_create_it(t->hncp, &n->node_identifier_hash);
  n->trusted = false;
  g->hncp_node = add ? n : NULL;
}
