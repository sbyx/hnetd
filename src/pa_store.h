/*
 * Author: Pierre Pfister <pierre pfister@darou.fr>
 *
 * Copyright (c) 2014 Cisco Systems, Inc.
 *
 * Prefix storing and caching module for the prefix assignment algorithm.
 *
 */

#ifndef PA_STORE_H_
#define PA_STORE_H_

#include <libubox/avl.h>
#include <libubox/uloop.h>
#include <string.h>

#include "pa_core.h"

/**
 * Maximum length of the link name, identifying the link in the stable storage
 * file.
 *
 * For example,
 *   DHCPv6 DUID is at most 20bytes (40 hex characters)
 *   On Linux IFNAMESIZ is 16 characters
 *
 * Some more space is required to differentiate different link types.
 */
#define PA_STORE_NAMELEN 50

/**
 * Prefix parsing function used by pa_store.
 *
 * pa_prefix_tostring is used to write prefixes.
 *
 * A written or read prefix must not include "# \t\n" characters.
 * Function prototype is:
 *    int pa_prefix_fromstring(const char *src, pa_prefix *addr, pa_plen *plen)
 *
 * The written prefix string length must be less than PA_PREFIX_STRLEN.
 *    (Mandatory when pa_store is enabled)
 */
#define pa_prefix_fromstring(buff, p, plen) \
		prefix_pton(buff, p, plen)

/* Each stored object has a type. */
#define PA_STORE_PREFIX "prefix"
#define PA_STORE_ADDR   "address"
#define PA_STORE_WTOKEN "write_tokens"
#define PA_STORE_ULA    "ula"

/* Banner displayed at the beginning of the file. */
#define PA_STORE_BANNER \
	"# Prefix Assignment Algorithm Storage Module File.\n"\
	"# This file was generated automatically.\n"\
	"# Do not modify unless you know what you are doing.\n"\
	"# Do not modify while the process is running as\n"\
	"# modifications will be overridden.\n\n"

/* Default number of write tokens when not specified in the storage file. */
#define PA_STORE_WTOKENS_DEFAULT 10

/* Maximum number of write tokens */
#define PA_STORE_WTOKENS_MAX     100

/**
 * PA storage main structure.
 */
struct pa_store {
	/**********************
	 * Related to caching *
	 **********************/

	/* Tree containing pa_store Links */
	struct list_head links;

	/* All cached prefixes */
	struct list_head prefixes;

	/* Maximum number of remembered prefixes. */
	uint32_t max_prefixes;

	/* Number of cached prefixes. */
	uint32_t n_prefixes;

	/**********************
	 * Related to storage *
	 **********************/

	/* Path of the file to be used for storage. */
	const char *filepath;

	/* Whether some changes should be written to stable storage. */
	uint8_t pending_changes;

	/* Delay between a change and the actual write to stable storage (if a token is available). */
	uint32_t save_delay;

	/* Delay cache write into the disk. */
	struct uloop_timeout save_timer;

	/* Write tokens count. */
	uint32_t token_count;

	/* Delay to wait before a write token can be added. */
	uint32_t token_delay;

	/* Counts time to add tokens. */
	struct uloop_timeout token_timer;
};

/**
 * Initializes the pa storage structure.
 *
 * @param store The storage structure to be initialized.
 * @param core The associated core structure.
 * @param max_prefixes Maximum number of cached prefixes.
 */
void pa_store_init(struct pa_store *store, uint32_t max_prefixes);

/**
 * Bound between a pa_store and a pa_core.
 * This allows using the same pa_store with different pa_core structures.
 */
struct pa_store_bound {
	struct pa_user user;
	struct pa_store *store;
};

void pa_store_bind(struct pa_store *store, struct pa_core *core,
		struct pa_store_bound *bound);

void pa_store_unbind(struct pa_store_bound *bound);

/**
 * Structure representing a given link used by PA store.
 * It is provided by the user, or created by pa_store when encountering unknown
 * links while reading the file.
 */
struct pa_store_link {

	/* The associated Link. */
	struct pa_link *link;

	/* The link name to be used in the storage.
	 *     (Must not contain "# \t\n" characters).
	 * When no name is specified (empty string), prefixes are cached but
	 * not stored. */
	char name[PA_STORE_NAMELEN];

	/* Maximum number of remembered prefixes for this Link. */
	uint32_t max_prefixes;

	/* PRIVATE to pa_store */
	struct list_head le;      /* Linked in pa_store. */
	struct list_head prefixes;/* List of pa_store entries. */
	uint32_t n_prefixes;      /* Number of entries currently stored for this Link. */
};

/**
 * Initializes a storage link structure.
 */
#define pa_store_link_init(store_link, pa_link, linkname, max_px) do { \
		(store_link)->link = pa_link; \
		(store_link)->max_prefixes = max_px; \
		strcpy((store_link)->name, linkname); \
	} while(0)

/**
 * Sets the file to be used for stable storage.
 *
 * The file must be writable and readable. If the file does not exists, it is
 * created.
 *
 * @param store The PA store structure.
 * @param filepath Path to the file being used.
 * @param save_delay Time before a modification is saved.
 * @param token_delay Time before an additional token is added.
 * @return 0 on success and -1 otherwise (errno is set).
 */
int pa_store_set_file(struct pa_store *, const char *filepath,
		uint32_t save_delay, uint32_t token_delay);

/**
 * Loads the file into the cache.
 *
 * The content is considered more recent than the cached information.
 *
 * @param store The PA store structure.
 * @param filepath Path to the file being read.
 * @return 0 on success, -1 otherwise.
 */
int pa_store_load(struct pa_store *store, const char *filepath);

/**
 * Manually triggers cache saving into the file.
 *
 * @param store The PA store structure.
 * @return 0 on success, -1 otherwise.
 */
int pa_store_save(struct pa_store *store);

/**
 * Notifies the desire to save the cached info into stable storage.
 *
 * It will be written after some delay and when a token is available.
 *
 * @param store The PA store structure.
 */
void pa_store_updated(struct pa_store *store);

/**
 * Free all memory and cache entries.
 *
 * Does not flush that state to the file.
 *
 * @param store The PA store structure.
 */
void pa_store_term(struct pa_store *store);



void pa_store_link_add(struct pa_store *, struct pa_store_link *);
void pa_store_link_remove(struct pa_store *, struct pa_store_link *);

/**
 * PA core caching based rule.
 *
 * When no prefix is assigned on the given link and for the given delegated
 * prefix, this rule will propose prefixes which were already applied to the
 * same Link.
 */
struct pa_store_rule {
	struct pa_rule rule;
	struct pa_store *store;
	pa_rule_priority rule_priority;
	pa_priority priority;
};

/**
 * Initializes a PA store rule.
 */
void pa_store_rule_init(struct pa_store_rule *rule, struct pa_store *store);




#endif /* PA_STORE_H_ */
