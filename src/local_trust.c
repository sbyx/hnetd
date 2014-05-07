#include "local_trust.h"

void update_local(hncp o){
  size_t len = o->trust->array_size * sizeof(hncp_hash_s);
  hncp_t_trust_array tlv = malloc(sizeof(hncp_t_trust_array_s) + len);

  tlv->sequence_number = ++(o->trust->tlv_version);
  tlv->timeout = 0; /* Dummy */
  memcpy(tlv->hashes, o->trust->local_trust_array, len);
  hncp_trust_update_graph(o, &o->own_node->node_identifier_hash, o->trust->local_trust_array, o->trust->array_size);

  hncp_remove_tlvs_by_type(o, HNCP_T_TRUST_ARRAY);

  hncp_update_tlv_raw(o, HNCP_T_TRUST_ARRAY, tlv, len + sizeof(hncp_t_trust_array_s), true);
  free(tlv);
}


void local_trust_add_trusted_hash(hncp o, hncp_hash h){
  hncp_trust t = o->trust;
  t->array_size++;
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  t->local_trust_array[t->array_size-1] = *h;

  update_local(o);
}


void local_trust_add_trusted_array(hncp o, hncp_hash h, unsigned int size){
  hncp_trust t = o->trust;
  unsigned int orig_size = t->array_size;
  t->array_size+= size;
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  memcpy(&t->local_trust_array[orig_size], h, size * sizeof(hncp_hash_s));

  update_local(o);
}

static inline void check_free_array(hncp_trust t){
  if(t->array_size == 0){
    free(t->local_trust_array);
    t->local_trust_array = NULL;
  }
}
bool local_trust_remove_trusted_hash(hncp o, hncp_hash h){
  unsigned int i;
  hncp_trust t = o->trust;
  for(i = 0; i < t->array_size; i++){
    if(memcmp(&t->local_trust_array[i], h, HNCP_HASH_LEN) == 0)
      goto remove;
  }
  return false;
remove:
  t->array_size--;
  memmove(&t->local_trust_array[i], &t->local_trust_array[i+1], (t->array_size-i) * sizeof(hncp_hash_s));
  t->local_trust_array = realloc(t->local_trust_array, t->array_size * sizeof(hncp_hash_s));
  check_free_array(t);
  update_local(o);
  return true;
}


void local_trust_purge_trusted_array(hncp o){
  hncp_trust t = o->trust;
  t->array_size = 0;
  check_free_array(t);
  update_local(o);
}
