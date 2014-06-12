/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 *
 * Optimized binary trie
 *
 * That file provides an optimized binary trie structure.
 * Stored elements (given as 'struct list_head') are associated to keys.
 * Keys are bit sequences of given length (maximum length is 2^BTRIE_PLEN - 1).
 * Keys are provided as arrays of elements of BTRIE_KEY bits. Array elements
 * must be correctly aligned.
 *
 * Simple binary tries use one node per key length bit, which is inefficient when
 * keys are sparse. This structure is able to compress long nodes branches up
 * to BTRIE_KEY bits. For example, if A/n is stored alone, it will only use
 * ((n-1) / BTRIE_KEY + 1) nodes.
 *
 * Two iteration modes are also provided.
 * 'Down' mode allows iterating over all elements stored or all elements
 * which keys are included in a given key.
 * 'Up' mode allows iterating over all elements that are including the given key.
 *
 */

#ifndef BTRIE_H_
#define BTRIE_H_

#include <libubox/list.h>
#include <stdint.h>

#ifdef container_of
#undef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

/* Key bit length must be included in  [0, 2^BTRIE_PLEN - 1].
 * You can optimize memory usage by reducing this value.
 * It can take values 8, 16, 32 or 64. */
#define BTRIE_PLEN 8

/* Keys must be provided as arrays of elements of given size and
 * must therefore be correctly aligned.
 * The bigger the value, the best the tree is compressed when elements'
 * keys are sparse. But when keys are not sparse, it may be interesting
 * to reduce this length.
 * It can take values 8, 16, 32 or 64 (64 is not available in network byte order). */
#define BTRIE_KEY 32

/* As keys are bit sequences provided as possibly non single byte elements, endianness matters.
 * Defining this value specifies that the key is stored in network byte order. If not defined,
 * each key array element is considered as an integer of BTRIE_KEY bits in home byte order. */
#define BTRIE_KEY_NETWORK_BYTE_ORDER

/* Private */
#define TYPE_GLUE(a,b,c) a##b##c
#define TYPE_INT(x) TYPE_GLUE(uint, x, _t)
typedef TYPE_INT(BTRIE_PLEN) btrie_plen_t;
typedef TYPE_INT(BTRIE_KEY) btrie_key_t;
/***********/

struct btrie;

struct btrie_element {
	struct list_head l; //Must be first for cast
	struct btrie *node;
};

/* Initializes a btrie structure as a trie root. */
void btrie_init(struct btrie *root);

/* Insert an element in the trie.
 * Returns 0 if insertion succeeded or -1 if some malloc failed. */
int btrie_add(struct btrie *root, struct btrie_element *new, const btrie_key_t *key, btrie_plen_t len);

/* Removes an entry from the trie. */
void btrie_remove(struct btrie_element *e);

/* Returns the key bit length of the key associated with a provided element.
 * The element must be currently inserted in a btrie. */
#define btrie_get_keylen(e) ((e)->node->plen)

/* Writes the value of the key associated with an element inside the provided key array.
 * The element must be currently inserted in a btrie.
 * The key array must be long enough to contain the key. */
void btrie_get_key(struct btrie_element *e, btrie_key_t *key);

#define btrie_empty(root) (list_empty(&(root)->elements.l) && !(root)->child[0] && !(root)->child[0])

/***** Private to iterators -- see below ****/
extern void *__bt_p;
#define __bt_e(el, e, field) (container_of(el, typeof(*(e)), field))
#define __bt_next_e(e, field, next, key, len) (__bt_e(next(&(e)->field, key, len), e, field))
#define __bt_null_e(e, field) (e == __bt_e(NULL, e, field))
#define __bt_next(el, key, len) (btrie_next(el))
#define __bt_next_down(el, key, len) (btrie_next_down(el, len))
#define __bt_next_up(el, key, len) (btrie_next_up(el))
#define __bt_first_entry(e, root, key, len, first, field) (typeof(e))((__bt_null_e((typeof(e))(__bt_p = __bt_e(first(root, key, len), e, field)), field))?NULL:__bt_p)
#define __bt_fe(el, root, key, len, first, next) \
	for(el = first(root, key, len); el != NULL; el = next(el, key, len))
#define __bt_fe_s(el, el2, root, key, len, first, next) \
	for(el = first(root, key, len), el2 = (el)?(next(el, key, len)):NULL; el != NULL; el = (el2), el2 = (el2)?next(el2, key, len):NULL)
#define __bt_fe_e(e, root, key, len, first, next, field) \
	for(e = __bt_e(first(root, key, len), e, field); !__bt_null_e(e, field); e = __bt_next_e(e, field, next, key, len))
#define __bt_fe_es(e, e2, root, key, len, first, next, field) \
	for(e = __bt_e(first(root, key, len), e, field), \
				e2 = __bt_e( ((__bt_null_e(e, field))?NULL:(next(&(e)->field, key, len))), e, field ) ;\
		!__bt_null_e(e, field); \
		e = e2, e2 = __bt_e( ((__bt_null_e(e2, field))?NULL:(next(&(e)->field, key, len))), e, field)  )

struct btrie_element *__btrie_skip_down(struct btrie_element *prev, btrie_plen_t len);
/*********************************************/

/* Iterates over all elements associated with a given key */
struct btrie_element *btrie_first(struct btrie *root, const btrie_key_t *key, btrie_plen_t len);
struct btrie_element *btrie_next(struct btrie_element *prev);
#define btrie_first_entry(e, root, key, len ,field) __bt_first_entry(e, root, key, len, btrie_first, field)

#define btrie_for_each(el, root, key, len) 												\
			__bt_fe(el, root, key, len, btrie_first, __bt_next)
#define btrie_for_each_safe(el, el2, root, key, len) 									\
			__bt_fe_s(el, el2, root, key, len, btrie_first, __bt_next)
#define btrie_for_each_entry(entry, root, key, len, field) 								\
			__bt_fe_e(entry, root, key, len, btrie_first, __bt_next, field)
#define btrie_for_each_entry_safe(entry, entry2, root, key, len, field) 				\
			__bt_fe_es(entry, entry2, root, key, len, btrie_first, __bt_next, field)

/* Iterates over all elements which key is equal to or begin with a given key (Elements down the tree) */
struct btrie_element *btrie_first_down(struct btrie *root, const btrie_key_t *key, btrie_plen_t len);
struct btrie_element *btrie_next_down(struct btrie_element *prev, btrie_plen_t len);
#define btrie_first_down_entry(e, root, key, len ,field) __bt_first_entry(e, root, key, len, btrie_first_down, field)

#define btrie_for_each_down(el, root, key, len) 												\
			__bt_fe(el, root, key, len, btrie_first_down, __bt_next_down)
#define btrie_for_each_down_safe(el, el2, root, key, len) 										\
			__bt_fe_s(el, el2, root, key, len, btrie_first_down, __bt_next_down)
#define btrie_for_each_down_entry(entry, root, key, len, field) 								\
			__bt_fe_e(entry, root, key, len, btrie_first_down, __bt_next_down, field)
#define btrie_for_each_down_entry_safe(entry, entry2, root, key, len, field)					\
			__bt_fe_es(entry, entry2, root, key, len, btrie_first_down, __bt_next_down, field)

/* skip_down allows to continue iterating but skipping all elements which keys are contained
 * or equal the current element's key. It must be called with the same arguments.
 * When safe, the current element can be deleted after skip is called (not before). */
#define btrie_skip_down(el, len) \
	el = __btrie_skip_down(el, len)
#define btrie_skip_down_safe(el, el2, len) \
	el2 = btrie_next_down(__btrie_skip_down(el, len), len)
#define btrie_skip_down_entry(entry, len, field) \
	entry = __bt_e(__btrie_skip_down(&(entry)->field, len), entry, field)
#define btrie_skip_down_entry_safe(entry, entry2, len, field) \
	entry2 = __bt_next_e(__bt_e(__btrie_skip_down(&(entry)->field, len), entry, field), field, __bt_next_down, key, len)

/* Iterates over all elements which key is equal to or contains a given key (Elements up the tree) */
struct btrie_element *btrie_first_up(struct btrie *root, const btrie_key_t *key, btrie_plen_t len);
struct btrie_element *btrie_next_up(struct btrie_element *prev);
#define btrie_first_up_entry(e, root, key, len ,field) __bt_first_entry(e, root, key, len, btrie_first_up, field)

#define btrie_for_each_up(el, root, key, len) 												\
			__bt_fe(el, root, key, len, btrie_first_up, __bt_next_up)
#define btrie_for_each_up_safe(el, el2, root, key, len) 									\
			__bt_fe_s(el, el2, root, key, len, btrie_first_up, __bt_next_up)
#define btrie_for_each_up_entry(entry, root, key, len, field) 								\
			__bt_fe_e(entry, root, key, len, btrie_first_up, __bt_next_up, field)
#define btrie_for_each_up_entry_safe(entry, entry2, root, key, len, field) 					\
			__bt_fe_es(entry, entry2, root, key, len, btrie_first_up, __bt_next_up, field)

/* Iterates over all elements which key contains or is contained in a given key (Do both up and down)
 * Up elements are visited first, from shortest prefix to longest. Down elements are visited afterward. */
struct btrie_element *btrie_first_updown(struct btrie *root, const btrie_key_t *key, btrie_plen_t len);
struct btrie_element *btrie_next_updown(struct btrie_element *prev, const btrie_key_t *key, btrie_plen_t len);
#define btrie_first_updown_entry(e, root, key, len ,field) __bt_first_entry(e, root, key, len, btrie_first_updown, field)

#define btrie_for_each_updown(el, root, key, len) 												\
			__bt_fe(el, root, key, len, btrie_first_updown, btrie_next_updown)
#define btrie_for_each_updown_safe(el, el2, root, key, len) 									\
			__bt_fe_s(el, el2, root, key, len, btrie_first_updown, btrie_next_updown)
#define btrie_for_each_updown_entry(entry, root, key, len, field) 								\
			__bt_fe_e(entry, root, key, len, btrie_first_updown, btrie_next_updown, field)
#define btrie_for_each_updown_entry_safe(entry, entry2, root, key, len, field) 					\
			__bt_fe_es(entry, entry2, root, key, len, btrie_first_updown, btrie_next_updown, field)

/* Iterates over all available keys contained in the prefix given by key and min_len.
 * The key is updated at each step and contains the available key. */
struct btrie *btrie_first_available(struct btrie *root, btrie_key_t *iter_key, btrie_plen_t *iter_len,
		const btrie_key_t *contain_key, btrie_plen_t contain_len);
struct btrie *btrie_next_available(struct btrie *prev, btrie_key_t *iter_key, btrie_plen_t *iter_len,
		btrie_plen_t contain_len);

/* Iterates over all available keys, using a particular key as starting point and looping indefinitly. */
struct btrie *btrie_first_available_loop(struct btrie *root,
		btrie_key_t *iter_key, btrie_plen_t *iter_len,
		const btrie_key_t *contain_key, btrie_plen_t contain_len, btrie_plen_t first_len);
struct btrie *btrie_next_available_loop(struct btrie *prev,
		btrie_key_t *iter_key, btrie_plen_t *iter_len,
		btrie_plen_t contain_len);

#define btrie_for_each_available(root, node, iter_key, iter_len, contain_key, contain_len) \
			for(node = btrie_first_available(root, iter_key, iter_len, contain_key, contain_len); node; \
					node = btrie_next_available(node, iter_key, iter_len, contain_len))

#define btrie_for_each_available_loop(root, node, iter_key, iter_len, contain_key, contain_len, first_len) \
		for(node = btrie_first_available_loop(root, iter_key, iter_len, contain_key, contain_len, first_len); node; \
							node = btrie_next_available_loop(node, iter_key, iter_len, contain_len))

#define btrie_for_each_available_loop_stop(root, node, n0, l0, iter_key, iter_len, contain_key, contain_len, first_len) \
		for(node = btrie_first_available_loop(root, iter_key, iter_len, contain_key, contain_len, first_len), n0 = NULL; \
					(n0)?(node != n0 || *(iter_len) != l0):((n0 = node) && ((l0 = *(iter_len)) || 1)); \
							node = btrie_next_available_loop(node, iter_key, iter_len, contain_len))

/* Returns the amount of key space available in the given subtree.
 * BTRIE_AVAILABLE_ALL is returned when the given prefix is available.
 * BTRIE_AVAILABLE_ALL >> 1 if one half is available and the other half is not,
 * BTRIE_AVAILABLE_ALL >> 1 + BTRIE_AVAILABLE_ALL >> 2 if one half plus one quarter are available, etc...
 * Available prefixes of length > target_len or length >= 64 + len are ignored. */
#define BTRIE_AVAILABLE_ALL 0x8000000000000000u
uint64_t btrie_available_space(struct btrie *root, const btrie_key_t *key, btrie_plen_t len, btrie_plen_t target_len);

/* Gives the number of keys of length target_len available and belonging in the given key. */
#define btrie_available_prefixes_count(root, key, len, target_len) \
			(btrie_available_space(root, key, len, target_len) >> (63 - (target_len - len)))

/***************Private**************/
struct btrie {
	struct btrie_element elements; //Must be first for cast
	struct btrie *parent;
	struct btrie *child[2];
	btrie_plen_t plen;
	btrie_key_t key;
};
/************************************/

#endif /* BTRIE_H_ */
