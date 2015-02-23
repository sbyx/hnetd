/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 */

#include <sys/stat.h> //Because stat.h uses __unused

#include "pa_store.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>

struct pa_store_prefix {
	struct list_head in_store;
	struct list_head in_link;
	pa_prefix prefix;
	pa_plen plen;
};

static int pa_store_cache(struct pa_store *store, struct pa_store_link *link, pa_prefix *prefix, pa_plen plen);

static struct pa_store_link *pa_store_link_goc(struct pa_store *store, const char *name, int create)
{
	struct pa_store_link *l;
	list_for_each_entry(l, &store->links, le) {
		if(!strcmp(l->name, name)) {
			return l;
		}
	}
	if(!create || !(l = malloc(sizeof(*l))))
		return NULL;

	strcpy(l->name, name);
	INIT_LIST_HEAD(&l->prefixes);
	l->n_prefixes = 0;
	l->link = NULL;
	l->max_prefixes = 0;
	list_add(&l->le, &store->links);
	return l;
}

/*  */
static void pa_store_getwords(char *line, char *words[], size_t nwords)
{
	size_t i;
	for(i=0; i<nwords; i++)
		words[i] = NULL;

	i = 0;
	size_t pos = 0, reading = 0;
	while(1) {
		switch (line[pos]) {
		case '\0':
			return;
		case ' ':
		case '\n':
		case '\t':
			if(reading) {
				line[pos] = '\0';
				reading = 0;
			}
			break;
		default:
			if(!reading) {
				reading = 1;
				if(i < nwords)
					words[i] = &line[pos];
				i++;
			}
			break;
		}
		pos++;
	}
}

#define PAS_PE(test, errmsg, ...) \
		if(test) { \
			if(!err) {\
				PA_WARNING("Parsing error in file %s", store->filepath);\
				err = -1;\
			}\
			PA_WARNING(" - "errmsg" at line %d", ##__VA_ARGS__, (int)linecnt); \
			continue;\
		}

int pa_store_load(struct pa_store *store, const char *filepath)
{
	FILE *f;
	if(!(f = fopen(filepath, "r"))) {
		PA_WARNING("Cannot open file %s (read mode) - %s", store->filepath, strerror(errno));
		return -1;
	}

	char *line = NULL;
	ssize_t read;
	size_t len;
	size_t linecnt = 0;
	int err = 0;
	while ((read = getline(&line, &len, f)) != -1) {
		linecnt++;
		char *words[4];
		pa_store_getwords(line, words, 4);

		if(!words[0] || words[0][0] == '#')
			continue;

		if(!strcmp(words[0], PA_STORE_PREFIX)) {
			pa_prefix px;
			pa_plen plen;
			struct pa_store_link *l;
			PAS_PE(!words[1] || !words[2], "Missing arguments");
			PAS_PE(words[3] && words[3][0] != '#', "Too many arguments");
			PAS_PE(!pa_prefix_fromstring(words[2], &px, &plen), "Invalid prefix");
			PAS_PE(strlen(words[1]) >= PA_STORE_NAMELEN, "Link name '%s' is too long", words[1]);
			PAS_PE(!(l = pa_store_link_goc(store, words[1], 1)), "Internal error");
			pa_store_cache(store, l, &px, plen);
		} else if(!strcmp(words[0], PA_STORE_WTOKEN)) {
			uint32_t token_count;
			PAS_PE(!words[1] || sscanf(words[1], "%"SCNu32, &token_count) != 1, "Invalid token count");
		} else {
			PAS_PE(1,"Unknown type %s", words[0]);
		}
	}

	free(line);
	fclose(f);
	return err;
}

int pa_store_save(struct pa_store *store)
{
	FILE *f;
	if(!store->filepath) {
		PA_WARNING("No specified file.");
		return -1;
	}

	if(!(f = fopen(store->filepath, "w"))) {
		PA_WARNING("Cannot open file %s (write mode) - %s", store->filepath, strerror(errno));
		return -1;
	}

	if(fprintf(f, PA_STORE_BANNER) <= 0) {
		PA_WARNING("Error occurred while writing cache into %s: %s", store->filepath, strerror(errno));
		return -1;
	}

	struct pa_store_prefix *p;
	struct pa_store_link *link;
	char px[PA_PREFIX_STRLEN];
	int err = 0;

	if(fprintf(f, PA_STORE_WTOKEN" %"PRIu32"\n", store->token_count) < 0) {
		err = -3;
	}

	list_for_each_entry_reverse(p, &store->prefixes, in_store) {
		link = list_entry(p->in_link.next, struct pa_store_link, prefixes);
		if(!strlen(link->name))
			continue;

		if(!err) {
			if(fprintf(f, PA_STORE_PREFIX" %s %s\n",
					link->name,
					pa_prefix_tostring(px, &p->prefix, p->plen)) < 0)
				err = -2;
		}
		list_move(&p->in_link, &link->prefixes);
	}
	if(err)
		PA_WARNING("Error occurred while writing cache into %s: %s", store->filepath, strerror(errno));

	fclose(f);
	return err;
}

static void pa_save_to(struct uloop_timeout *to)
{
	struct pa_store *store = container_of(to, struct pa_store, save_timer);
	store->pending_changes = 0;
	store->token_count--;
	pa_store_save(store);
}

void pa_token_to(struct uloop_timeout *to)
{
	struct pa_store *store = container_of(to, struct pa_store, token_timer);
	if(store->token_count == PA_STORE_WTOKENS_MAX)
		return;

	store->token_count++;
	if(store->pending_changes)
		pa_store_updated(store);
	uloop_timeout_set(to, store->token_delay);
}

void pa_store_updated(struct pa_store *store)
{
	store->pending_changes = 1;
	if(store->filepath && store->token_count && !store->save_timer.pending) {
		uloop_timeout_set(&store->save_timer, store->save_delay);
	}
}

/* Only an empty private link can be destroyed */
static void pa_store_private_link_destroy(struct pa_store_link *l)
{
	list_del(&l->le);
	free(l);
}

static void pa_store_uncache(struct pa_store *store, struct pa_store_link *l, struct pa_store_prefix *p)
{
	list_del(&p->in_link);
	l->n_prefixes--;
	list_del(&p->in_store);
	store->n_prefixes--;
	if(!l->n_prefixes && !l->link)
		pa_store_private_link_destroy(l);

	free(p);
	pa_store_updated(store);
}

#define pa_store_uncache_last_from_link(store, l) \
			pa_store_uncache(store, l, list_entry((l)->prefixes.prev, struct pa_store_prefix, in_link))

static void pa_store_uncache_last_from_store(struct pa_store *store)
{
	struct pa_store_prefix *p = list_entry((store)->prefixes.prev, struct pa_store_prefix, in_store);
	struct pa_store_link *l =  list_entry(p->in_link.next, struct pa_store_link, prefixes);
	pa_store_uncache(store, l, p);
}

static int pa_store_cache(struct pa_store *store, struct pa_store_link *link, pa_prefix *prefix, pa_plen plen)
{
	PA_DEBUG("Caching %s %s", link->name, pa_prefix_repr(prefix, plen));
	struct pa_store_prefix *p;
	list_for_each_entry(p, &link->prefixes, in_link) {
		if(pa_prefix_equals(prefix, plen, &p->prefix, p->plen)) {
			//Put existing prefix at head
			list_move(&p->in_store, &store->prefixes);
			list_move(&p->in_link, &link->prefixes);
			pa_store_updated(store);
			return 0;
		}
	}
	if(!(p = malloc(sizeof(*p))))
		return -1;
	//Add the new prefix
	pa_prefix_cpy(prefix, plen, &p->prefix, p->plen);
	list_add(&p->in_link, &link->prefixes);
	link->n_prefixes++;
	list_add(&p->in_store, &store->prefixes);
	store->n_prefixes++;

	//If too many prefixes in the link, remove the last one
	if(link->max_prefixes && link->n_prefixes > link->max_prefixes)
		pa_store_uncache_last_from_link(store, link);

	//If too many prefixes in storage, remove the last one
	if(store->max_prefixes && store->n_prefixes > store->max_prefixes)
		pa_store_uncache_last_from_store(store);

	pa_store_updated(store);
	return 0;
}

static void pa_store_applied_cb(struct pa_user *user, struct pa_ldp *ldp)
{
	struct pa_store_bound *b = container_of(user, struct pa_store_bound, user);
	struct pa_store *store = b->store;
	if(!ldp->applied)
		return;

	struct pa_store_link *link;
	list_for_each_entry(link, &store->links, le) {
		if(link->link == ldp->link) {
			pa_store_cache(store, link, &ldp->prefix, ldp->plen);
			return;
		}
	}
}

void pa_store_link_add(struct pa_store *store, struct pa_store_link *link)
{
	struct pa_store_link *l;
	INIT_LIST_HEAD(&link->prefixes);
	link->n_prefixes = 0;
	if((l = pa_store_link_goc(store, link->name, 0))) {
		list_splice(&l->prefixes, &link->prefixes);
		link->n_prefixes = l->n_prefixes;
		if(!l->link)
			pa_store_private_link_destroy(l);

		if(link->max_prefixes)
			while(link->n_prefixes > link->max_prefixes)
				pa_store_uncache_last_from_link(store, link);
	}
	list_add(&link->le, &store->links);
	return;
}

void pa_store_link_remove(struct pa_store *store, struct pa_store_link *link)
{
	struct pa_store_link *l;
	list_del(&link->le);
	if(!link->n_prefixes)
		return;

	if(((strlen(link->name) && (l = pa_store_link_goc(store, link->name, 1))))) {
		list_splice(&link->prefixes, &l->prefixes); //Save prefixes in a private list
		l->n_prefixes = link->n_prefixes;

		if(l->max_prefixes)
			while(l->n_prefixes > l->max_prefixes)
				pa_store_uncache_last_from_link(store, l);
	} else {
		struct pa_store_prefix *p;
		list_for_each_entry(p, &link->prefixes, in_link) {
			list_del(&p->in_store);
			free(p);
		}
		pa_store_updated(store);
	}
	return;
}

void pa_store_term(struct pa_store *store)
{
	struct pa_store_prefix *p, *p2;
	list_for_each_entry_safe(p, p2, &store->prefixes, in_store) {
		free(p);
	}

	struct pa_store_link *l, *l2;
	list_for_each_entry_safe(l, l2, &store->links, le) {
		if(!l->link)
			free(l);
	}

	uloop_timeout_cancel(&store->save_timer);
	uloop_timeout_cancel(&store->token_timer);
}

int pa_store_set_file(struct pa_store *store, const char *filepath,
		uint32_t save_delay, uint32_t token_delay)
{
	int fd;
	uloop_timeout_cancel(&store->save_timer);
	uloop_timeout_cancel(&store->token_timer);
	if((fd = open(filepath, O_WRONLY | O_CREAT, 0664)) == -1) {
		PA_WARNING("Could not open file (Or incorrect authorizations) %s: %s", filepath, strerror(errno));
		store->filepath = NULL;
		return -1;
	}
	close(fd);

	uint32_t token_count = PA_STORE_WTOKENS_DEFAULT;
	/* The file is read once to get the token counter. */
	FILE *f;
	if(!(f = fopen(filepath, "r"))) {
		PA_WARNING("Cannot open file %s (read mode) - %s", filepath, strerror(errno));
		return -1;
	}
	char *line = NULL;
	ssize_t read;
	size_t len;
	while ((read = getline(&line, &len, f)) != -1) {
		char *words[2];
		pa_store_getwords(line, words, 2);
		if(words[0] && !strcmp(words[0], PA_STORE_WTOKEN)) {
			if(!words[1] || sscanf(words[1], "%"SCNu32, &token_count) != 1) {
				PA_WARNING("Malformed token entry in file");
				fclose(f);
				return -1;
			} else {
				store->token_count = token_count;
				break;
			}
		}
	}
	free(line);
	fclose(f);

	store->token_count = token_count;
	store->save_delay = save_delay;
	store->token_delay = token_delay;
	store->filepath = filepath;
	store->pending_changes = 0;
	uloop_timeout_set(&store->token_timer, store->token_delay);
	return 0;
}

void pa_store_init(struct pa_store *store, uint32_t max_prefixes)
{
	store->max_prefixes = max_prefixes;
	INIT_LIST_HEAD(&store->links);
	INIT_LIST_HEAD(&store->prefixes);
	store->filepath = NULL;
	store->n_prefixes = 0;
	store->pending_changes = 0;
	store->save_timer.pending = 0;
	store->save_timer.cb = pa_save_to;
	store->token_timer.pending = 0;
	store->token_timer.cb = pa_token_to;
	store->token_count = 0;
}

void pa_store_bind(struct pa_store *store, struct pa_core *core,
		struct pa_store_bound *bound)
{
	bound->store = store;
	bound->user.applied = pa_store_applied_cb;
	bound->user.assigned = NULL;
	bound->user.published = NULL;
	pa_user_register(core, &bound->user);
}

void pa_store_unbind(struct pa_store_bound *bound)
{
	pa_user_unregister(&bound->user);
}

pa_rule_priority pa_store_get_max_priority(struct pa_rule *rule, struct pa_ldp *ldp)
{
	if(ldp->best_assignment || ldp->published) //No override
		return 0;

	struct pa_store_rule *rule_s = container_of(rule, struct pa_store_rule, rule);
	struct pa_store *store = rule_s->store;
	struct pa_store_link *l;
	list_for_each_entry(l, &store->links, le) {
		if(l->link == ldp->link) {
			if(l->n_prefixes)
				return rule_s->rule_priority;
			else
				return 0;
		}
	}
	return 0;
}

enum pa_rule_target pa_store_match(struct pa_rule *rule, struct pa_ldp *ldp,
		__attribute__ ((unused)) pa_rule_priority best_match_priority,
		struct pa_rule_arg *pa_arg)
{
	struct pa_store_rule *rule_s = container_of(rule, struct pa_store_rule, rule);
	struct pa_store *store = rule_s->store;

	pa_arg->priority = rule_s->priority;
	pa_arg->rule_priority = rule_s->rule_priority;
	//No need to check the best_match_priority because the rule uses a unique rule priority

	/* We checked that there is a candidate during get_max_priority call */
	struct pa_store_link *l;
	list_for_each_entry(l, &store->links, le) {
		if(l->link == ldp->link) //Will happen
			break;
	}

	//Find a matching prefix
	struct pa_store_prefix *prefix;
	list_for_each_entry(prefix, &l->prefixes, in_link) {
		if(prefix->plen >= ldp->dp->plen &&
				pa_prefix_contains(&ldp->dp->prefix, ldp->dp->plen, &prefix->prefix) &&
				pa_rule_valid_assignment(ldp, &prefix->prefix, prefix->plen, 0, 0, 0)) {
			if(!ldp->backoff)
				return PA_RULE_BACKOFF; //Start or continue backoff timer.

			pa_prefix_cpy(&prefix->prefix, prefix->plen, &pa_arg->prefix, pa_arg->plen);
			return PA_RULE_PUBLISH;
		}
	}
	return PA_RULE_NO_MATCH;
}

void pa_store_rule_init(struct pa_store_rule *rule, struct pa_store *store)
{
	rule->store = store;
	rule->rule.filter_accept = NULL;
	rule->rule.get_max_priority = pa_store_get_max_priority;
	rule->rule.match = pa_store_match;
}
