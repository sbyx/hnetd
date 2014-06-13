/*
 * Author : Xavier Bonnetain
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */


#include "local_trust.h"

void add_trust_tlv(hncp o, hncp_hash h){
  hncp_t_trust_link tlv = alloca(sizeof(hncp_t_trust_link_s));
  if(!tlv){
    L_ERR("malloc (%lu) failed for trust link tlv", sizeof(hncp_t_trust_link_s));
    return;
  }
  tlv->trusted_hash = *h;
  hncp_update_tlv_raw(o, HNCP_T_TRUST_LINK, tlv, sizeof(hncp_t_trust_link_s), true);
}

void local_trust_update_tlv(hncp o){

  hncp_trust_update_graph(o, &o->own_node->node_identifier_hash, o->trust->local_trust_array, o->trust->array_size);

  hncp_remove_tlvs_by_type(o, HNCP_T_TRUST_LINK);

  for(unsigned int i = 0; i< o->trust->array_size; i++){
    add_trust_tlv(o, o->trust->local_trust_array + i);
  }
}

void local_trust_add_trusted_hash(hncp o, hncp_hash h, bool update){
  hncp_trust t = o->trust;
  t->array_size++;
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  t->local_trust_array[t->array_size-1] = *h;
  if(update)
    local_trust_update_tlv(o);
}


void local_trust_add_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update){
  hncp_trust t = o->trust;
  unsigned int orig_size = t->array_size;
  t->array_size+= size;
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  memcpy(&t->local_trust_array[orig_size], h, size * sizeof(hncp_hash_s));
  if(update)
    local_trust_update_tlv(o);
}

static inline void check_free_array(hncp_trust t){
  if(t->array_size == 0){
    free(t->local_trust_array);
    t->local_trust_array = NULL;
  }
}

bool local_trust_remove_trusted_hash(hncp o, hncp_hash h, bool update){
  unsigned int i;
  hncp_trust t = o->trust;
  for(i = 0; i < t->array_size; i++){
    if(HASH_EQUALS(&t->local_trust_array[i], h))
      goto remove;
  }
  return false;
remove:
  t->array_size--;
  memmove(&t->local_trust_array[i], &t->local_trust_array[i+1], (t->array_size-i) * sizeof(hncp_hash_s));
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  check_free_array(t);
  if(update)
    local_trust_update_tlv(o);
  return true;
}


bool local_trust_remove_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update){
  bool done = false;
  for(unsigned int i = 0; i<size; i++){
    if(local_trust_remove_trusted_hash(o, &h[i], false))
     done = true;
  }
  if(update && done)
    local_trust_update_tlv(o);
  return done;
}


void _purge_trusted_array(hncp o){
  hncp_trust t = o->trust;
  t->array_size = 0;
  check_free_array(t);
}

void local_trust_replace_trusted_array(hncp o, hncp_hash h, unsigned int size, bool update){
  _purge_trusted_array(o);
  local_trust_add_trusted_array(o, h, size, update);
}


void local_trust_purge_trusted_array(hncp o, bool update){
  _purge_trusted_array(o);
  if(update)
    local_trust_update_tlv(o);
}
