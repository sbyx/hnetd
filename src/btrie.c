/*
 * Optimized binary trie
 * Author: Pierre Pfister <pierre@darou.fr>
 *
 */

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#include "btrie.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define iterm_up 0x0
#define iterm_left 0x1
#define iterm_right 0x2
#define iterm_only_up 0x3

typedef btrie_key_t pkey_t;
typedef btrie_plen_t plen_t;

#ifndef BTRIE_KEY_NETWORK_BYTE_ORDER
#define ntohk(i) (i)
#define htonk(i) (i)
#else
#include <arpa/inet.h>
#if BTRIE_KEY == 8
#define ntohk(i) (i)
#define htonk(i) (i)
#elif BTRIE_KEY == 16
#define ntohk(i) ntohs(i)
#define htonk(i) htons(i)
#elif BTRIE_KEY == 32
#define ntohk(i) ntohl(i)
#define htonk(i) htonl(i)
#elif BTRIE_KEY == 64
#error 64 bits is not supported in network byte order
#endif
#endif

#if BTRIE_KEY == 8
#define remain_mask    0x07u
#define index_shift    3
#define first_bit_mask 0x80u
#define full_mask      0xffu
#elif BTRIE_KEY == 16
#define remain_mask    0x0fu
#define index_shift    4
#define first_bit_mask 0x8000u
#define full_mask      0xffffu
#elif BTRIE_KEY == 32
#define remain_mask    0x1fu
#define index_shift    5
#define first_bit_mask 0x80000000u
#define full_mask      0xffffffffu
#elif BTRIE_KEY == 64
#define remain_mask    0x3fu
#define index_shift    6
#define first_bit_mask 0x8000000000000000u
#define full_mask      0xffffffffffffffffu
#endif

#define index(i) ((i) >> index_shift)
#define remain(i) ((i) & remain_mask)
#define mask(i) ((full_mask >> (BTRIE_KEY - 1 - (i))) << (BTRIE_KEY - 1 - (i)))
#define nthbit(key, i) ((key) & (first_bit_mask >> (i)))

void *__bt_p; //Helper for iterators

static struct btrie *btrie_node_lookup(struct btrie *n, const pkey_t *key, plen_t plen)
{
	while(n->plen <= plen &&
			!(n->plen && ((ntohk(key[index(n->plen - 1)]) ^ n->key) & mask(remain(n->plen - 1))))) {

		if(n->plen == plen)
			return n;

		if(nthbit(ntohk(key[index(n->plen)]), remain(n->plen))) {
			if(n->child[1]) {
				n = n->child[1];
			} else {
				return n;
			}
		} else {
			if(n->child[0]) {
				n = n->child[0];
			} else {
				return n;
			}
		}
	}
	return n->parent;
}

static inline struct btrie *btrie_new_node(struct btrie *parent, struct btrie **child)
{
	struct btrie *node;
	if(!(node = malloc(sizeof(struct btrie))))
		return NULL;
	INIT_LIST_HEAD(&node->elements.l);
	node->elements.node = NULL;
	node->parent = parent;
	node->child[0] = NULL;
	node->child[1] = NULL;
	*child = node;
	return node;
}

static void btrie_delete_maybe(struct btrie *n)
{
	struct btrie *o, **c, *p;
	while(list_empty(&n->elements.l) && n->parent && (!n->child[0] || !n->child[1])) {
		o = n->child[0];
		if(!o)
			o = n->child[1];

		if(o && !(n->plen & remain_mask))
			return;

		c = &n->parent->child[0];
		if(*c != n)
			c = &n->parent->child[1];

		*c = o;
		p = n->parent;
		free(n);

		if(o) {
			o->parent = p;
			return;
		}
		n = p;
	}
}

static struct btrie *btrie_add_leaf(struct btrie *parent, struct btrie **child,
		const pkey_t *key, plen_t plen)
{
	struct btrie *node;
	*child = NULL;
	if(!(node = btrie_new_node(parent, child))) {
		btrie_delete_maybe(parent); //Maybe parent(s) can be deleted
		return NULL;
	}

	plen_t next_i = index(parent->plen);
	plen_t index = index(plen - 1);
	node->key = ntohk(key[next_i]);
	if(index == next_i) { //Last element
		node->plen = plen;
		return node;
	}

	node->plen = ((next_i + 1) << index_shift); //Maximum plen for this element
	if(ntohk(key[next_i + 1]) & first_bit_mask) { //First bit of the next block
		return btrie_add_leaf(node, &node->child[1], key, plen);
	} else {
		return btrie_add_leaf(node, &node->child[0], key, plen);
	}
}

/* Two nodes with the same beginning have to be joined
 * min_match = minimal matching length (not multiples of 32) */
static struct btrie *btrie_solve_conflict(struct btrie *current, struct btrie **child,
		const pkey_t *key, plen_t plen, plen_t min_match)
{
	struct btrie *node;
	plen_t match_len = min_match;
	plen_t max_match = current->plen;
	if(plen < max_match)
		max_match = plen;

	plen_t index = index(min_match - 1);
	pkey_t no_mask = ~mask(remain(min_match - 1));
	pkey_t no_maxmask = ~mask(remain(max_match - 1));
	pkey_t diff = ntohk(key[index]) ^ current->key;
	while(no_mask != no_maxmask &&
			(no_mask >>= 1) &&
			!(diff & (~no_mask))) {
		++match_len;
	}

	if(!(node = btrie_new_node(current->parent, child)))
		return NULL;

	node->plen = match_len;
	node->key = ntohk(key[index(match_len - 1)]);
	current->parent = node;

	if(nthbit(current->key, remain(match_len))) {
		node->child[1] = current;
		return (match_len == plen)?node:btrie_add_leaf(node, &node->child[0], key, plen);
	} else {
		node->child[0] = current;
		return (match_len == plen)?node:btrie_add_leaf(node, &node->child[1], key, plen);
	}
}

static struct btrie *btrie_node_add(struct btrie *n, const pkey_t *key, plen_t plen)
{
	struct btrie **next;
	if(nthbit(ntohk(key[index(n->plen)]), remain(n->plen))) {
		next = &n->child[1];
	} else {
		next = &n->child[0];
	}

	if(*next) {
		return btrie_solve_conflict(*next, next, key, plen, n->plen + 1);
	} else {
		return btrie_add_leaf(n, next, key, plen);
	}
}

static struct btrie *btrie_node_goc(struct btrie *root, const btrie_key_t *key, btrie_plen_t len, int create)
{
	struct btrie *node = btrie_node_lookup(root, key, len);
	if(node->plen == len)
		return node;

	if (create)
		return btrie_node_add(node, key, len);

	return NULL;
}

void btrie_init(struct btrie *root) {
	memset(root, 0, sizeof(struct btrie));
	INIT_LIST_HEAD(&root->elements.l);
	root->elements.node = NULL;
}

#define node(element) ((struct btrie *) (element)) //elements is first field in btrie
#define element(list) ((struct btrie_element *) (list)) //l is first field in btrie_element
#define next_element(e) element((e)->l.next)

int btrie_add(struct btrie *root, struct btrie_element *e, const pkey_t *key, plen_t len)
{
	struct btrie *n = btrie_node_goc(root, key, len, 1);
	if(n) {
		e->node = n;
		list_add_tail(&e->l, &n->elements.l);
		return 0;
	}
	return -1;
}

void btrie_remove(struct btrie_element *e)
{
	list_del(&e->l);
	if(list_empty(&e->node->elements.l))
		btrie_delete_maybe(e->node);
}

void btrie_get_key(struct btrie_element *e, btrie_key_t *key)
{
	struct btrie *node = e->node;

	if(!node->plen)
		return;

	key[index(node->plen - 1)] = htonk(node->key & mask(remain(node->plen - 1)));

	while((node = node->parent) && node->plen) {
		if(!remain(node->plen)) {
			key[index(node->plen - 1)] = htonk(node->key);
		}
	}
}

struct btrie_element *btrie_next(struct btrie_element *prev)
{
	prev = next_element(prev);
	if(prev->node)
		return prev;
	return NULL;
}

struct btrie_element *btrie_first(struct btrie *root, btrie_key_t *key, btrie_plen_t len)
{
	struct btrie *t;
	if(!(t = btrie_node_goc(root, key, len, 0)))
		return NULL;

	return btrie_next(&t->elements);
}

struct btrie_element *btrie_next_up(struct btrie_element *prev)
{
	struct btrie *node;
	prev = next_element(prev);
loop:
	if(prev->node)
		return prev;

	node = node(prev);
	if(node->parent) {
		prev = next_element(&node->parent->elements);
		goto loop;
	}

	return NULL;
}

struct btrie_element *btrie_first_up(struct btrie *root, btrie_key_t *key, btrie_plen_t len)
{
	return btrie_next_up(&(btrie_node_lookup(root, key, len))->elements);
}

struct btrie_element *btrie_next_down(struct btrie_element *prev, btrie_plen_t len) //len is necessary to know when to stop
{
	struct btrie *node;
	if(!prev)
		return NULL;

next: //Try next element
	prev = next_element(prev);
	if(prev->node)
		return prev;

	node = node(prev);
//Try on the left of the current node (no goto here)
	if(node->child[0]) {
		prev = &node->child[0]->elements;
		goto next;
	}

right: //Try on the right of the current node
	if(node->child[1]) {
		prev = &node->child[1]->elements;
		goto next;
	}

up: //Go back up
	if(!node->parent || node->parent->plen < len) {
		return NULL;
	}

	if(node->parent->child[0] == node) {
		node = node->parent;
		goto right;
	} else {
		node = node->parent;
		goto up;
	}

	return NULL; //avoid warning
}

struct btrie_element *__btrie_skip_down(struct btrie_element *prev, btrie_plen_t len)
{
	struct btrie *node = prev->node;

	while(node->parent && node->parent->plen >= len) {
		if(node == node->parent->child[1]) {
			node = node->parent;
			continue;
		}

		node = node->parent;
		if(node->child[1]) {
			prev = btrie_next_down(&node->child[1]->elements, len);
			return prev?(&prev->node->elements):NULL;
		}
	}
	return NULL;
}

struct btrie_element *btrie_first_down(struct btrie *root, btrie_key_t *key, btrie_plen_t len)
{
	struct btrie *node = btrie_node_lookup(root, key, len);
	struct btrie *child;
	if(node->plen == len) {
		return btrie_next_down(&node->elements, len);
	} else {
		if(nthbit(ntohk(key[index(node->plen)]), remain(node->plen))) {
			child = node->child[1];
		} else {
			child = node->child[0];
		}
		/* Goal here is to find if a child is inside the key */
		if(!child || len >= child->plen || ((ntohk(key[index(node->plen)]) ^ child->key) & mask(remain(len - 1)))) {
			return NULL;
		} else {
			return btrie_next_down(&child->elements, len);
		}
	}
}

struct btrie_element *btrie_next_updown(struct btrie_element *prev, btrie_key_t *key, btrie_plen_t len)
{
	struct btrie *node;
	if(!prev)
		return NULL;

	node = prev->node;
	if(!prev->node) //If list head
		node = node(prev);

	if(node->plen >= len)
		return btrie_next_down(prev, len);
next:
	prev = next_element(prev);
	if(prev->node)
		return prev;

	if(nthbit(ntohk(key[index(node->plen)]), remain(node->plen))) {
		node = node->child[1];
	} else {
		node = node->child[0];
	}

	if(!node)
		return NULL;

	if(node->plen >= len) {
		if(!((ntohk(key[index(len - 1)]) ^ node->key) & mask(remain(len - 1))) ) {
			return btrie_next_down(&node->elements, len);
		} else {
			return NULL;
		}
	} else {
		if(!((ntohk(key[index(node->plen - 1)]) ^ node->key) & mask(remain(node->plen - 1))) ) {
			prev = &node->elements;
			goto next;
		} else {
			return NULL;
		}
	}
}

struct btrie_element *btrie_first_updown(struct btrie *root, btrie_key_t *key, btrie_plen_t len)
{
	return btrie_next_updown(&root->elements, key, len);
}
