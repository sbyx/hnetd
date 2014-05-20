
#ifndef typeof
#define typeof __typeof
#endif

#ifndef container_of
#define container_of(ptr, type, member) (           \
    (type *)( (char *)ptr - offsetof(type,member) ))
#endif

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#include <stddef.h>
#include <stdlib.h>

static int malloc_fails = 0;
static int malloc_called = 0;
void *test_malloc(size_t size)
{
	malloc_called = 1;

	if(malloc_fails)
		return NULL;

	return malloc(size);
}

#define malloc test_malloc
#include "btrie.c"

#include "sput.h"
#include "smock.h"

#include <stdlib.h>
#include <stddef.h>

#if BTRIE_KEY == 8
#define key_hex_repr "%02x"
#elif BTRIE_KEY == 16
#define key_hex_repr "%04x"
#elif BTRIE_KEY == 32
#define key_hex_repr "%08x"
#elif BTRIE_KEY == 64
#define key_hex_repr "%016lx"
#endif

int test_count_down(struct btrie *root, pkey_t *k, uint8_t bitlen)
{
	int i = 0;
	struct btrie_element *e;
	btrie_for_each_down(e, root, k, bitlen) {
		++i;
	}
	return i;
}

int test_count_up(struct btrie *root, pkey_t *k, uint8_t bitlen)
{
	int i = 0;
	struct btrie_element *e;
	btrie_for_each_up(e, root, k, bitlen) {
		++i;
	}
	return i;
}

int test_count_updown(struct btrie *root, pkey_t *k, uint8_t bitlen)
{
	int i = 0;
	struct btrie_element *e;
	btrie_for_each_updown(e, root, k, bitlen) {
		++i;
	}
	return i;
}

static size_t test_count_available(struct btrie *root, const pkey_t *contain_key, plen_t contain_len, pkey_t *iter_key)
{
	struct btrie *n;
	size_t ctr = 0;
	plen_t iter_len;
	btrie_for_each_available(root, n, iter_key, &iter_len, contain_key, contain_len, 0) {
		ctr++;
	}
	return ctr;
}

static uint64_t test_count_space(struct btrie *root, const pkey_t *contain_key, plen_t contain_len, pkey_t *iter_key, plen_t target_len)
{
	struct btrie *n;
	uint64_t ctr = 0;
	plen_t iter_len;
	if(target_len - contain_len > 63)
		target_len = contain_len + 63;

	btrie_for_each_available(root, n, iter_key, &iter_len, contain_key, contain_len, 0) {
		if(iter_len <= target_len)
			ctr += BTRIE_AVAILABLE_ALL >> (iter_len - contain_len);
	}
	return ctr;
}

void test_print_key(pkey_t *k, uint8_t bitlen)
{
	if(!bitlen) {
		printf("0/0");
		return;
	}

	int i;
	for(i = 0; i < index(bitlen - 1); i++) {
		printf(key_hex_repr, ntohk(k[i]));
	}
	printf(key_hex_repr, (ntohk(k[index(bitlen - 1)]) & mask(remain(bitlen - 1))));
	printf("/%i", bitlen);
}

void btrie_check(struct btrie *n)
{
	sput_fail_unless(!n->parent || !list_empty(&n->elements.l) || (n->child[0] && n->child[1]) ||
			(!(n->plen & remain_mask) && (n->child[0] || n->child[1])), "Node exists for a reason");
	if(n->child[0]) {
		sput_fail_if(nthbit(n->child[0]->key, remain(n->plen)), "Correct child side");
		sput_fail_unless(n->child[0]->parent == n, "Correct parent for left child");
		sput_fail_unless(n->child[0]->plen > n->plen, "Greater prefix length");
		if(index(n->child[0]->plen - 1) == index(n->plen - 1)) {
			sput_fail_unless(!((n->child[0]->key ^ n->key) & mask(remain(n->plen - 1))), "Valid key");
		}
		btrie_check(n->child[0]);
	}
	if(n->child[1]) {
		sput_fail_unless(nthbit(n->child[1]->key, remain(n->plen)), "Correct child side");
		sput_fail_unless(n->child[1]->parent == n, "Correct parent for right child");
		sput_fail_unless(n->child[1]->plen > n->plen, "Greater prefix length");
		if(index(n->child[1]->plen - 1) == index(n->plen - 1)) {
			sput_fail_unless(!((n->child[1]->key ^ n->key) & mask(remain(n->plen - 1))), "Valid key");
		}
		btrie_check(n->child[1]);
	}
}

void btrie_print(struct btrie *node, int rec)
{
	int i;
	struct list_head *l;
	for(i=0; i<rec; i++)
		printf("  ");
	printf("%p - 0x"key_hex_repr"/%i (", node, node->key, node->plen);

	list_for_each(l, &node->elements.l) {
		printf("%p ", element(l));
	}
	printf(") (\n");

	if(node->child[0]) {
		btrie_print(node->child[0], rec + 1);
	} else {
		for(i=0; i<rec+1; i++)
				printf("  ");
		printf("null\n");
	}
	//printf("\n");
	if(node->child[1]) {
		btrie_print(node->child[1], rec + 1);
	} else {
		for(i=0; i<rec+1; i++)
				printf("  ");
		printf("null\n");
	}
}


void test_btrie()
{
	int i;
	void *a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	void *b = "aabbbbbbbbbbbbbbbbbbbbbbbbbb";
	struct btrie t;
	struct btrie_element e[4], *el;

	btrie_init(&t);
	btrie_check(&t);

	sput_fail_if(t.child[0], "Only root");
	sput_fail_if(t.child[1], "Only root");
	sput_fail_if(btrie_first(&t, NULL, 0), "No element");
	sput_fail_if(btrie_first(&t, a, 1), "No element");
	sput_fail_if(btrie_first(&t, a, 64), "No element");

	for(i=0;i<135; i++) {
		sput_fail_if(btrie_add(&t, &e[0], a, i), "New element");
		sput_fail_unless(el = btrie_first(&t, a, i), "Got list");
		if(el) {sput_fail_unless(el == &e[0], "Got list");}
		if(i) {sput_fail_if(btrie_first(&t, a, i - 1), "No there");}
		sput_fail_if(btrie_first(&t, a, i + 1), "No there");
		sput_fail_unless(test_count_down(&t, NULL, 0) == 1, "Correct number of elements");
		sput_fail_unless(test_count_up(&t, a, i) == 1, "Correct number of elements");
		sput_fail_unless(test_count_updown(&t, NULL, 0) == 1, "Correct number of elements");
		sput_fail_unless(test_count_updown(&t, a, i + 1) == 1, "Correct number of elements");
		if(i) {sput_fail_unless(test_count_updown(&t, a, i - 1) == 1, "Correct number of elements");}
		sput_fail_unless(i == 0 || t.child[0] || t.child[1], "Only root");
		btrie_remove(&e[0]);
		sput_fail_if(btrie_first(&t, a, i), "No element");
		sput_fail_if(t.child[0], "Only root");
		sput_fail_if(t.child[1], "Only root");
		sput_fail_unless(test_count_down(&t, NULL, 0) == 0, "Correct number of elements");
		sput_fail_unless(test_count_up(&t, NULL, 0) == 0, "Correct number of elements");
	}

	sput_fail_unless(test_count_down(&t, NULL, 0)==0, "No elements");
	struct btrie_element elements[2][135];
	for(i=0; i<135; i++) {
		sput_fail_if(btrie_first(&t, a, i), "No element yet");
		sput_fail_if(btrie_add(&t, &elements[0][i], a, i), "Adding element");
		sput_fail_unless(btrie_first(&t, a, i), "Element found");
		sput_fail_unless(test_count_down(&t, NULL, 0) == i+1, "Correct number of elements");
		sput_fail_unless(test_count_down(&t, a, i) == 1, "Correct number of elements");
		sput_fail_unless(test_count_up(&t, a, i) == i+1, "Correct number of elements");
		sput_fail_unless(test_count_up(&t, a, i + 10) == i+1, "Correct number of elements");
		sput_fail_unless(test_count_updown(&t, a, i) == i+1, "Correct number of elements");
		if(i) {
			sput_fail_unless(test_count_up(&t, a, i - 1) == i, "Correct number of elements");
			sput_fail_unless(test_count_updown(&t, a, i - 1) == i+1, "Correct number of elements");
		}
	}
	btrie_check(&t);

	for(i=0; i<135; i++) {
		sput_fail_if((el = btrie_first(&t, b, i)) &&
				(el == &elements[1][i] || element(el->l.next) == &elements[1][i]), "No element yet");
		sput_fail_if(btrie_add(&t, &elements[1][i], b, i), "Adding element");
		sput_fail_unless(btrie_first(&t, b, i), "Element found");
		sput_fail_unless(test_count_down(&t, NULL, 0)==135 + i + 1, "Correct number of elements");
	}
	btrie_check(&t);

	for(i=0; i<135; i++) {
		sput_fail_unless((el = btrie_first(&t, a, i)), "Got element");
		sput_fail_unless(el == &elements[0][i] || element(el->l.next) == &elements[0][i], "Correct list element");
		btrie_remove(&elements[0][i]);
		sput_fail_if((el = btrie_first(&t, a, i)) &&
				(element(el->l.next) == &elements[0][i] || element(el->l.prev) == &elements[0][i]), "No element anymore");
		sput_fail_unless(test_count_down(&t, NULL, 0)==270 - i - 1, "Correct number of elements");
	}
	btrie_check(&t);

	for(i=0; i<135; i++) {
		sput_fail_unless((el = btrie_first(&t, b, i)), "Got element");
		sput_fail_unless(el == &elements[1][i] || element(el->l.next) == &elements[1][i], "Correct list element");
		btrie_remove(&elements[1][i]);
		sput_fail_if((el = btrie_first(&t, b, i)) && (element(el->l.next) == &elements[1][i] || element(el->l.prev) == &elements[1][i]), "No element anymore");
		sput_fail_unless(test_count_down(&t, NULL, 0)==135 - i - 1, "Correct number of elements");
	}
	btrie_check(&t);
	sput_fail_if(t.child[0], "Only root");
	sput_fail_if(t.child[1], "Only root");
}

struct btrie_entry {
	struct btrie_element e;
	int id;
};

#define BIT_LEN 160
#define STR_LEN BIT_LEN/8
#define STACK "rand"
#define TRIE_SIZE 1120
#define ROUNDS 2000

int test_rand_get()
{
	int i = rand();
	smock_push_int(STACK, i);
	return i;
}

int test_rand_getagain()
{
	return smock_pull_int(STACK);
}

void test_btrie_stress_push(struct btrie *root, void *str, void *check, uint8_t diversity, int id)
{
	struct btrie_entry *entry;
	void *key = calloc(1, STR_LEN);
	int count_down = 0;
	int count_up = 0;
	int count_updown = 0;
	if(!(entry = malloc(sizeof(struct btrie_entry)))) {
		sput_fail_if(1, "malloc error");
		return;
	}
	entry->id = id;
	uint8_t mod = test_rand_get() % STR_LEN;
	uint8_t bitlen = test_rand_get() % ((mod*8) + 1);
	((uint8_t *)str)[mod] = test_rand_get() % diversity;
	if(!(id % 10)) {
		//Check count
		count_down = test_count_down(root, str, bitlen);
		count_up = test_count_up(root, str, bitlen);
		count_updown = test_count_updown(root, str, bitlen);

		test_count_available(root, str, bitlen, key); //Just execute, looking for faults
		test_count_available(root, str, 0, key); //Just execute, looking for faults
		if(test_count_space(root, str, 0, key, 63) != btrie_available_space(root, str, 0, 63)) {
			sput_fail_if(1, "Invalid space count");
		}
		memcpy(key, str, STR_LEN);
		if(test_count_space(root, str, 11, key, 63) != btrie_available_space(root, str, 11, 63)) {
			sput_fail_if(1, "Invalid space count 2");
		}

		//Malloc fails
		malloc_fails = 1;
		malloc_called = 0;
		if(btrie_add(root, &entry->e, str, bitlen)) {
		} else {
			if(malloc_called)
				sput_fail_if(1,"Addition should fail");
			btrie_remove(&entry->e);
		}
		malloc_fails = 0;
	}

	if(btrie_add(root, &entry->e, str, bitlen))
		sput_fail_if(1,"can't add element");

	btrie_get_key(&entry->e, (btrie_key_t *) check);
	sput_fail_unless(bitlen == btrie_get_keylen(&entry->e), "Correct key length");
	if(bitlen) {
		sput_fail_if(((((btrie_key_t *) check)[index(bitlen-1)]) ^ (((btrie_key_t *) str)[index(bitlen-1)])) & htonk(mask(remain(bitlen - 1))), "Incorrect last key value");
		int i;
		for(i = 0; i < index(bitlen-1); i++) {
			sput_fail_if(((btrie_key_t *) check)[i] != ((btrie_key_t *) str)[i], "Incorrect key value");
		}
	}

	if(!(id % 10)) {
		//check count
		if(test_count_down(root, str, bitlen) != count_down + 1) {
			sput_fail_if(1, "Down count is not coherent");
		}
		if(test_count_up(root, str, bitlen) != count_up + 1) {
			sput_fail_if(1, "Up count is not coherent");
		}
		if(test_count_updown(root, str, bitlen) != count_updown + 1) {
			sput_fail_if(1, "Up count is not coherent");
		}
	}

	if(!(id % 200)) {
		btrie_check(root);
	}

	free(key);
	return;
}

void test_btrie_stress_pull(struct btrie *root, void *str, uint8_t diversity, int id)
{
	struct btrie_entry *entry;
	uint8_t mod = test_rand_getagain() % STR_LEN;
	uint8_t bitlen = test_rand_getagain() % ((mod*8) + 1);
	((uint8_t *)str)[mod] = test_rand_getagain() % diversity;
	btrie_for_each_down_entry(entry, root, str, bitlen, e) {
		if(entry->id == id) {
			btrie_remove(&entry->e);
			free(entry);
			return;
		}
	}
	sput_fail_if(1, "Element not found");
}

void test_btrie_stress()
{
	struct btrie t;
	int push = 0;
	int pull = 0;

	void *str1 = calloc(1, STR_LEN);
	void *str2 = calloc(1, STR_LEN);
	void *check = calloc(1, STR_LEN);
	srand(0);

	btrie_init(&t);

	int i;
	for(i = 0; i < TRIE_SIZE; i++) {
		test_btrie_stress_push(&t, str1, check, 255, push);
		push++;
	}

	for(i = 0; i < ROUNDS; i++) {
		test_btrie_stress_push(&t, str1, check, 255, push);
		push++;
		test_btrie_stress_pull(&t, str2, 255, pull);
		pull++;
		//btrie_check(&t);
	}
	for(i = 0; i < TRIE_SIZE; i++) {
		test_btrie_stress_pull(&t, str2, 255, pull);
		pull++;
	}
	free(str1);
	free(str2);
	sput_fail_if(t.child[0], "Only root");
	sput_fail_if(t.child[1], "Only root");
}

#ifdef BTRIE_KEY_NETWORK_BYTE_ORDER

#include "prefixes_library.h"

struct btrie_pentry {
	struct btrie_element e;
	struct prefix *p;
};

static void test_check_prefix(struct btrie_pentry *pentry)
{
	struct prefix cmp;
	cmp.plen = btrie_get_keylen(&pentry->e);
	btrie_get_key(&pentry->e, (btrie_key_t *)&cmp.prefix);
	sput_fail_if(prefix_cmp(&cmp, pentry->p), "Correct prefix");
}

static void test_btrie_prefix()
{
	struct btrie t;
	int i,l;
	struct btrie_element *elem, *elem2;
	struct btrie_pentry *pentry, *pentry2;

	btrie_init(&t);


#define psize 15
	struct prefix p[] = {
			PL_PV4, PL_PV4_1, PL_PV4_1_1,
			PL_P1, PL_P1_0, PL_P1_01, PL_P1_01A, PL_P1_02, PL_P1_02A, PL_P1_04, PL_P1_10,
			PL_P2, PL_P2_01, PL_P2_02,
			PL_P3
	};

	struct btrie_pentry elems[psize];
	for(i = 0; i<psize; i++) {
		elems[i].p = &p[i];
		btrie_add(&t, &elems[i].e, (btrie_key_t *)&elems[i].p->prefix, elems[i].p->plen);

		for(l = 0; l<psize; l++) {
			struct btrie_element *get = btrie_first(&t, (btrie_key_t *)&p[l].prefix, p[l].plen);
			if((l > i && get) || ( l <= i && !get)) {
				sput_fail_if(1, "Element present or not");
			}
		}
	}


	btrie_for_each_up(elem, &t, NULL, 0) {
		sput_fail_if(1, "No element up to root");
	}

	i = 0;
	btrie_for_each_down(elem, &t, NULL, 0) {
		pentry = container_of(elem, struct btrie_pentry, e);
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry(pentry, &t, NULL, 0, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry(pentry, &t, NULL, 0, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		if(i == 1) {
			i = 3;
			btrie_skip_down_entry(pentry, 0, e);
			continue;
		}
		if(i == 5) {
			i = 7;
			btrie_skip_down_entry(pentry, 0, e);
			continue;
		}
		if(i == 14) {
			i = 15;
			btrie_skip_down_entry(pentry, 0, e);
			continue;
		}
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	i = 0;
	btrie_for_each_down_safe(elem, elem2, &t, NULL, 0) {
		pentry = container_of(elem, struct btrie_pentry, e);
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry_safe(pentry, pentry2, &t, NULL, 0, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry_safe(pentry, pentry2, &t, NULL, 0, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect element");
		if(i == 1) {
			i = 3;
			btrie_skip_down_entry_safe(pentry, pentry2, 0, e);
			continue;
		}
		if(i == 5) {
			i = 7;
			btrie_skip_down_entry_safe(pentry, pentry2, 0, e);
			continue;
		}
		if(i == 14) {
			i = 15;
			btrie_skip_down_entry_safe(pentry, pentry2, 0, e);
			continue;
		}
		i++;
	}
	sput_fail_unless( i == psize, "Correct number of elements");

	//including PL_P1_0
	i = 0;
	btrie_for_each_up_entry(pentry, &t, (btrie_key_t *)&p[4].prefix, p[4].plen, e) {
		sput_fail_if(pentry->p != &p[4 - i], "Incorrect prefix");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 2, "Correct number of elements");

	i = 0;
	btrie_for_each_up_entry_safe(pentry, pentry2, &t, (btrie_key_t *)&p[4].prefix, p[4].plen, e) {
		sput_fail_if(pentry->p != &p[4 - i], "Incorrect prefix");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 2, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry(pentry, &t, (btrie_key_t *)&p[4].prefix, p[4].plen, e) {
		sput_fail_if(pentry->p != &p[i+4], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 6, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry_safe(pentry, pentry2, &t, (btrie_key_t *)&p[4].prefix, p[4].plen, e) {
		sput_fail_if(pentry->p != &p[i+4], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 6, "Correct number of elements");

	i = 0;
	btrie_for_each_up(elem, &t, (btrie_key_t *)&p[1].prefix, p[1].plen + 1) {
		pentry = container_of(elem, struct btrie_pentry, e);
		sput_fail_if(pentry->p != &p[1 - i], "Incorrect prefix");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 2, "Correct number of elements");

	i = 0;
	btrie_for_each_down(elem, &t, (btrie_key_t *)&p[1].prefix, p[1].plen + 1) {
		pentry = container_of(elem, struct btrie_pentry, e);
		sput_fail_if(pentry->p != &p[i+2], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 1, "Correct number of elements");

	i = 0;
	btrie_for_each_up_entry(pentry, &t, (btrie_key_t *)&p[1].prefix, p[1].plen + 1, e) {
		sput_fail_if(pentry->p != &p[1 - i], "Incorrect prefix");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 2, "Correct number of elements");

	i = 0;
	btrie_for_each_down_entry(pentry, &t, (btrie_key_t *)&p[1].prefix, p[1].plen + 1, e) {
		sput_fail_if(pentry->p != &p[i+2], "Incorrect element");
		test_check_prefix(pentry);
		i++;
	}
	sput_fail_unless( i == 1, "Correct number of elements");

	/* updown */
	i = 0;
	btrie_for_each_updown_entry(pentry, &t, (btrie_key_t *)&p[1].prefix, p[1].plen, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect prefix");
		i++;
	}
	sput_fail_unless( i == 3, "Correct number of elements");

	i = 0;
	btrie_for_each_updown_entry(pentry, &t, (btrie_key_t *)&p[1].prefix, p[1].plen - 1, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect prefix");
		i++;
	}
	sput_fail_unless( i == 3, "Correct number of elements");

	i = 3;
	btrie_for_each_updown_entry(pentry, &t, (btrie_key_t *)&p[4].prefix, p[4].plen, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect prefix");
		i++;
	}
	sput_fail_unless( i == 10, "Correct number of elements");

	i = 3;
	btrie_for_each_updown_entry(pentry, &t, (btrie_key_t *)&p[4].prefix, p[4].plen - 1, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect prefix");
		i++;
	}
	sput_fail_unless( i == 11, "Correct number of elements");

	i = 3;
	btrie_for_each_updown_entry(pentry, &t, (btrie_key_t *)&p[4].prefix, p[4].plen + 1, e) {
		sput_fail_if(pentry->p != &p[i], "Incorrect prefix");
		i++;
	}
	sput_fail_unless( i == 10, "Correct number of elements");

}

#endif

#define BTRIE_AVAIL_ITER 100

static void test_btrie_available()
{
	struct btrie t;
	struct btrie_element e;
	plen_t len;
	pkey_t key[4], key2[4];
	int i, j, iter;


	btrie_init(&t);
	for(i=0; i< 4 * BTRIE_KEY; i++) {
		len = 0;
		btrie_first_available(&t, key2, &len, key, i, 0);
		sput_fail_unless(len == i, "Everything is available");
		sput_fail_unless(test_count_available(&t, key, i, key2) == 1, "One single available");
		sput_fail_unless(btrie_available_space(&t, NULL, 0, 4 * BTRIE_KEY) == BTRIE_AVAILABLE_ALL, "Everything is available");
	}

	for(iter = 0; iter < BTRIE_AVAIL_ITER; iter++) {
		key[0] = rand();
		key[1] = rand();
		key[2] = rand();
		key[3] = rand();
		for(i=0; i< 4 * BTRIE_KEY; i++) {
			btrie_add(&t, &e, key, i);
			for(j=0; j<=i; j++) {
				if(test_count_available(&t, key, j, key2) != (unsigned) i - j) {
					sput_fail_unless(0, "Should be i - j available prefixes");
				}
				if(i - j < 64 &&
						(btrie_available_space(&t, key, j, 4 * BTRIE_KEY) != (BTRIE_AVAILABLE_ALL - (BTRIE_AVAILABLE_ALL >> (i - j))))) {
					sput_fail_unless(0, "Correct amount of available");
				}
			}
			btrie_remove(&e);
		}
	}
}

#ifdef BTRIE_KEY_NETWORK_BYTE_ORDER
void test_btrie_available_list(struct btrie *root)
{
	struct btrie *n;
	struct prefix available, can;
	printf("Listing available prefixes \n");
	btrie_for_each_available(root, n, (btrie_key_t *)&available.prefix, &available.plen, NULL, 0, 0)
	{
		prefix_canonical(&can, &available);
		printf("Available prefix: %s\n", PREFIX_REPR(&can));
	}
	printf("\n");
}

void test_btrie_available_prefix()
{
	struct btrie t;
	struct prefix p = PL_P1, p2 = PL_P2_01;
	struct btrie_element e1, e2;
	btrie_init(&t);
	test_btrie_available_list(&t);
	btrie_add(&t, &e1, (btrie_key_t *)&p.prefix, p.plen);
	test_btrie_available_list(&t);
	btrie_add(&t, &e2, (btrie_key_t *)&p2.prefix, p.plen);
	test_btrie_available_list(&t);
}
#endif

int main( __unused int argc,  __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("Test btrie"); /* optional */
  sput_run_test(test_btrie);
  sput_run_test(test_btrie_stress);
#ifdef BTRIE_KEY_NETWORK_BYTE_ORDER
  sput_run_test(test_btrie_prefix);
#endif
  sput_run_test(test_btrie_available);
#ifdef BTRIE_KEY_NETWORK_BYTE_ORDER
  sput_run_test(test_btrie_available_prefix);
#endif
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
