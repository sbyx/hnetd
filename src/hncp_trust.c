/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#include "hncp_trust.h"
#include "tlv.h"
#include <stdio.h>


static void update_trust_graph( __unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  if((!node_new) && node_old){
    /* Node destruction and memory free */
    hncp_trust_graph g = container_of(node_old, hncp_trust_graph_s, vlist_node);
    trust_graph_destroy(g);
  }
};

static void update_trust_status(__unused struct vlist_tree *t, struct vlist_node *node_new, struct vlist_node *node_old){
  hncp_node n_new = container_of(node_new, hncp_node_s, in_trusted_nodes);
  hncp_node n_old = container_of(node_old, hncp_node_s, in_trusted_nodes);

  if(node_new == node_old)
    return;


  if(node_old)
    hncp_notify_subscribers_node_trust_changed(n_old, false);

  if(node_new)
    hncp_notify_subscribers_node_trust_changed(n_new, true);


}
/** Hash comparison, for vlists */
int compare_hash(const void *hash1, const void *hash2, __unused void *c){
  return HASH_CMP(hash1, hash2);
};

static void hncp_trust_tlv_update_callback(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add);

static void hncp_trust_local_tlv_callback(hncp_subscriber s, struct tlv_attr *tlv, bool add);

static void hncp_trust_node_change_callback(hncp_subscriber s, hncp_node n, bool add);

static void hncp_trust_end_friend_search(struct uloop_timeout * t);

/* Add the graph node to the graph list. */
static inline void hncp_trust_add_node(hncp o, hncp_trust_graph g){
  vlist_add(&o->trust->trust_graphs,&g->vlist_node, &g->hash);

}

static inline hncp_trust_graph hncp_trust_create_graph(hncp o, const hncp_hash hash){
  hncp_trust_graph g = trust_graph_create(hash);
  hncp_trust_add_node(o, g);
  return g;
}

int hncp_trust_init(hncp o, char * private_key_file, char * trusted_key_dir){
  hncp_trust s = malloc(sizeof(hncp_trust_s));
  //memset(s, 0, sizeof(hncp_trust_s));
  if(!s)
    return -1;

  o->trust = s;

  vlist_init(&s->trust_graphs, compare_hash, update_trust_graph);
  s->trust_graphs.keep_old = false;
  s->trust_graphs.no_delete = false;


  vlist_init(&s->trusted_nodes, compare_hash, update_trust_status);
  s->trusted_nodes.keep_old = false;
  s->trusted_nodes.no_delete = false;

  local_trust_init(o);

  s->friend_search_timeout.pending = NULL;
  int r = 0;
  s->hncp = o;
  s->crypto_used = false;

  s->want_friend = false;
  s->shared_key_emitter = false;
  INIT_LIST_HEAD(&s->temporary_friend_key_list);

  /* Don't consider random adresses as functions */
  memset(&s->sub, 0, sizeof(hncp_subscriber_s));

  if(private_key_file){
    r = hncp_crypto_init(o, private_key_file, trusted_key_dir);
    s->sub.local_tlv_change_callback = hncp_trust_local_tlv_callback;
    s->sub.tlv_change_callback = hncp_trust_tlv_update_callback;
  }
  s->sub.node_change_callback = hncp_trust_node_change_callback;
  hncp_hash own_hash = &(o->own_node->node_identifier_hash);
  /* No arrow yet */

  s->my_graph = hncp_trust_create_graph(o, own_hash);
  s->my_graph->trusted = true;
  s->my_graph->trusts_me = true;

  hncp_subscribe(o, &s->sub);

  return r;
};

void hncp_trust_destroy(hncp o){
  hncp_trust t = o->trust;
  local_trust_purge_trusted_list(o);

  if(t->crypto_used) hncp_crypto_del_data(t->crypto);
  t->crypto_used = false;
  hncp_unsubscribe(o, &t->sub);
  vlist_flush_all(&o->trust->trust_graphs);

  free(t);
}

hncp_trust_graph hncp_trust_get_graph_or_create_it(hncp o, hncp_hash hash){
  hncp_trust_graph g = graph_from_hash(o, hash);
  if(!g){
    g = hncp_trust_create_graph(o, hash);
   }
  return g;
}

void hncp_trust_update_trusted_node_set(hncp o){
  hncp_trust_graph g;
  vlist_for_each_element(&o->trust->trust_graphs, g, vlist_node){
    if(!g->hncp_node)
      continue;
    if(g->trusted && g->trusts_me){
      g->hncp_node->in_trusted_nodes_set = true;
      vlist_add(&o->trust->trusted_nodes, &g->hncp_node->in_trusted_nodes, &g->hncp_node->node_identifier_hash);
    }else
      g->hncp_node->in_trusted_nodes_set = false;
  }
  vlist_flush(&o->trust->trusted_nodes);
}

void hncp_trust_flood_trust_link(hncp o, hncp_trust_graph emitter, hncp_trust_graph target){

  struct list_head head;
  INIT_LIST_HEAD(&head);
  if(emitter->trusted){
    add_graph_last(&head, target);
    target->trusted = true;
    }

  hncp_trust_graph g;
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

  if(target->trusts_me){
    add_graph_last(&head, emitter);
    emitter->trusts_me = true;
  }

  while(!list_empty(&head)){
    struct _trusted_list* l = list_first_entry(&head, struct _trusted_list, list);
    g = l->node;
    struct _trusted_list* t;
    _for_each_rev_trust_graph(g, t){
      if(!t->node->trusts_me){
        t->node->trusts_me = true;
        add_graph_last(&head, t->node);
      }
    }
    list_del(&l->list);
    free(l);
  }

  hncp_trust_update_trusted_node_set(o);
};

void hncp_trust_recalculate_trust_links(hncp o){
  hncp_trust_graph g;
  vlist_for_each_element(&o->trust->trust_graphs, g, vlist_node){
    g->trusted = false;
    g->trusts_me = false;
  }

  o->trust->my_graph->trusted = true;
  o->trust->my_graph->trusts_me = true;
  hncp_trust_flood_trust_link(o, o->trust->my_graph, o->trust->my_graph);
}

/** Update/create the trust graph with new trust links
 * trusted : array of hashes
 * size : size of the array */
void hncp_trust_add_trust_link(hncp o, hncp_hash emitter, hncp_hash target){
  hncp_trust_graph g = hncp_trust_get_graph_or_create_it(o, emitter);
  hncp_trust_graph g_trusted = hncp_trust_get_graph_or_create_it(o, target);
  trust_graph_add_trust_link(g, g_trusted);

  if(g->trusted ||g_trusted->trusts_me)
    hncp_trust_flood_trust_link(o, g, g_trusted);
}

void hncp_trust_del_trust_link(hncp o, hncp_hash emitter, hncp_hash target){
  hncp_trust_graph g = hncp_trust_get_graph_or_create_it(o, emitter);
  hncp_trust_graph g_trusted = hncp_trust_get_graph_or_create_it(o, target);
  bool existed = trust_graph_remove_trust_link(g, g_trusted);
  if(existed && (g->trusted || g_trusted->trusts_me))
    hncp_trust_recalculate_trust_links(o);
}

void hncp_trust_update_trusts_link(hncp o, hncp_hash emitter, hncp_hash target, bool add){
  if(add)
    hncp_trust_add_trust_link(o, emitter, target);
  else
    hncp_trust_del_trust_link(o, emitter, target);
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
   return node->trusts_me;
};

static void hncp_trust_end_friend_search(struct uloop_timeout * u){
  hncp_trust t = container_of(u, hncp_trust_s, friend_search_timeout);
  t->want_friend = false;
  while(!list_empty(&t->temporary_friend_key_list)){
    struct key_list * k = list_first_entry(&t->temporary_friend_key_list, struct key_list, list);
    list_del(&k->list);
    hncp_crypto_mistrust_trusted_key(t->hncp, k->key, true);
    free(k);
  }
}

void hncp_trust_begin_friend_search(hncp o, int seconds){
  hncp_trust t = o->trust;

  /* Remove an old friend search, if any */
  if(t->want_friend)
    uloop_timeout_cancel(&t->friend_search_timeout);

  t->want_friend = true;
  hncp_link link;
  hncp_neighbor n;

  struct key_list * list;

  while(!list_empty(&t->temporary_friend_key_list)){
    list = list_first_entry(&t->temporary_friend_key_list, struct key_list, list);
    list_del(&list->list);
    hncp_crypto_mistrust_trusted_key(t->hncp, list->key, true);
    free(list);
  }

  vlist_for_each_element(&o->links, link, in_links){
    if(link->conf->safe_link){
      vlist_for_each_element(&link->neighbors, n, in_neighbors){
        trust_key k = hncp_crypto_key_from_hash(o, &n->node_identifier_hash);
        if(!k)/* key unavailable */
          continue;
        if(k->locally_trusted) /* key already trusted */
          continue;
        if(!trust_graph_is_directly_trusted(o->trust->my_graph, &n->node_identifier_hash)){ /* Set temporary trust */
          list = malloc(sizeof(struct key_list));
          list->key = k;
          list_add_tail(&list->list, &o->trust->temporary_friend_key_list);
          hncp_crypto_set_trusted_key(o, k, true);
        }else
          hncp_crypto_set_trusted_key(o, k, false); /* Set permanent trust */
      }

    }

  }
  t->friend_search_timeout.cb = hncp_trust_end_friend_search;
  uloop_timeout_set(&t->friend_search_timeout, seconds*1000);
}

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

static inline struct key_list * _hash_in_list(struct list_head* head, hncp_hash hash){
  struct key_list * entry;
  list_for_each_entry(entry, head, list){
    if(HASH_EQUALS(&entry->key->key_hash, hash))
      return entry;
  }
  return NULL;
}

void hncp_trust_update_trusts_links(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add){
  hncp_t_trust_link ta = (hncp_t_trust_link) &tlv->data;
  hncp_trust t = container_of(s, hncp_trust_s, sub);
  if(add){
    hncp_trust_add_trust_link(t->hncp, &n->node_identifier_hash, &ta->trusted_hash);

    if(t->want_friend && HASH_EQUALS(&ta->trusted_hash, &t->hncp->own_node->node_identifier_hash)){
      struct key_list * entry = _hash_in_list(&t->temporary_friend_key_list, &n->node_identifier_hash);
      if(entry){
        list_del(&entry->list); /* Suppression from the temporary trust link. The link is now parmanent */

        free(entry);
      }
    }

  }else
    hncp_trust_del_trust_link(t->hncp, &n->node_identifier_hash, &ta->trusted_hash);
}

/* The signature_tlv must be a pointer to the last element of tlvs */
static bool _hncp_trust_integrity_check(hncp o, unsigned char *tlvs, hncp_hash h, uint32_t sequence_number, struct tlv_attr *node_key_tlv,
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
  bool r = crypto_verify_signature(sign, ctx, sequence_number, tlvs, len);
  if(!t)
    pk_free(ctx);
  return r;
}

bool hncp_trust_message_integrity_check(hncp o, hncp_hash identifier_hash, uint32_t sequence_number, struct tlv_attr *tlv_container){
  struct tlv_attr *node_key_tlv = NULL;
  struct tlv_attr *signature_tlv = NULL;

  struct tlv_attr *iter_tlv;
  unsigned int id;
  unsigned int uid = 0; /* Tlv id begins at 1 */
  unsigned int oldid = 0;
  char * end = tlv_len(tlv_container)+ (char *)tlv_container;

  tlv_for_each_attr(iter_tlv, tlv_container){
    if((char *) iter_tlv > end || iter_tlv < tlv_container)
      return false;
    id = tlv_id(iter_tlv);
    /* Reject if the trust tlvs (key, signature) are not unique or if the tlvs are not well sorted */
    if(oldid > id || id == uid)
      return false;

    switch(id){
      case HNCP_T_NODE_KEY:
        node_key_tlv = iter_tlv;
        goto end_unique;
      case HNCP_T_SIGNATURE:
        signature_tlv = iter_tlv;
      end_unique:
        uid = id;
    }
    oldid = id;
  }
  if(!node_key_tlv || !signature_tlv)
    return false;
 return _hncp_trust_integrity_check(o, (unsigned char *) tlv_container->data, identifier_hash, sequence_number, node_key_tlv, signature_tlv);
}

static void hncp_trust_local_tlv_callback(hncp_subscriber s, struct tlv_attr *tlv, bool add){
  hncp_crypto_local_update_callback(s, tlv, add);
}

static void hncp_trust_tlv_update_callback(hncp_subscriber s, hncp_node n, struct tlv_attr *tlv, bool add){
  if(hncp_node_is_self(n))
    return;
  switch(tlv_id(tlv)){
    case HNCP_T_NODE_KEY:
      hncp_trust_update_key(s, n, tlv, add);
      break;
    case HNCP_T_TRUST_LINK:
      hncp_trust_update_trusts_links(s, n, tlv, add);
  }
}

static void hncp_trust_node_change_callback(hncp_subscriber s, hncp_node n, bool add){
  hncp_trust t = container_of(s, hncp_trust_s, sub);
  hncp_trust_graph g = hncp_trust_get_graph_or_create_it(t->hncp, &n->node_identifier_hash);
  n->in_trusted_nodes_set = false;
  g->hncp_node = add ? n : NULL;
}
