#ifndef _TRUST_GRAPH_H
#define _TRUST_GRAPH_H

#include "hncp_i.h"
#include <libubox/vlist.h>
#include <libubox/list.h>
#include <stdio.h>


/** Node of the trust graph */
struct trust_graph_struct {
    /* For a global node indexation */
    struct vlist_node vlist_node;

    struct list_head arrows;

    struct list_head rev_arrows;
    /* pointer to the hncp node struct (only the field
    "trusted" is relevant for now) */
    hncp_node hncp_node;

    hncp_hash_s hash;

    /* wheter I trust the node */
    bool trusted;

    /* wheter it trusts me */
    bool trusts_me;
    /* For graph exploration
     * Clearly not thread-safe ! */
    bool marked;
};

typedef struct trust_graph_struct hncp_trust_graph_s, *hncp_trust_graph;


/** List of trusted nodes (arrows of the trust graph) */
struct _trusted_list {
    /* Node trusted */
    hncp_trust_graph node;
    /* Next element */
    struct list_head list;
};

#define HASH_CMP(h1, h2) (memcmp(h1, h2, HNCP_HASH_LEN))
#define HASH_EQUALS(h1, h2) (HASH_CMP(h1, h2) == 0)

/** Struct init */
void trust_graph_init(hncp_trust_graph g, hncp_hash hash);

/** Alloc & init */
hncp_trust_graph trust_graph_create(hncp_hash hash);

#define _for_each_arrow(head, item)\
  list_for_each_entry(item, head, list)

#define _for_each_trust_graph(graph, item)\
  _for_each_arrow(&graph->arrows, item)

/* For bfs explo of the graph */
static inline void add_graph_last(struct list_head* l, hncp_trust_graph g){
  struct _trusted_list* e = malloc(sizeof(struct _trusted_list));
  e->node = g;
  list_add_tail(&e->list, l);
}

/** True if the element in node g trusts the node with hash hash */
bool trust_graph_is_trusted(hncp_trust_graph g, hncp_hash hash);

/** Direct add of a trust link ; no existence check done */
void trust_graph_add_trust_link(hncp_trust_graph emitter, hncp_trust_graph trusted);

/** Deletion of a link, true if the link existed */
bool trust_graph_remove_trust_link(hncp_trust_graph emitter, hncp_trust_graph trusted);

void trust_graph_add_trust_array(hncp_trust_graph emitter, hncp_trust_graph array[], unsigned int size);

/** Deletion of _all_ the trust links from the node */
void trust_graph_remove_trust_links(hncp_trust_graph g);

static inline void trust_graph_destroy(hncp_trust_graph g){
  trust_graph_remove_trust_links(g);
  free(g);
}


#endif /* _TRUST_GRAPH_H */
