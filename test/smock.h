/*
 * $Id: smock.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013-2015 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 10:14:59 2013 mstenber
 * Last modified: Wed Mar 19 17:32:16 2014 mstenber
 * Edit time:     72 min
 *
 */

#ifndef SMOCK_H
#define SMOCK_H

#include <libubox/list.h>

#define SMOCK_QUEUE_NAME_LENGTH 64

/*
 * Simple mock library. Only dependency is libubox (for linked list)
 * and sput (for 'pretty' assertions).
 */

/* Basic idea: Structure code so that mocked parameters can be
 * guessed, or represented in some human-readable code within unit
 * tests. Then, actual use consists of:
 *
 * - In testcase, supplying mock arguments as needed (smock_push(q,
 * v)).
 *
 * - Add hooks to pull input parameters (to be checked on call) and
 * output parameters (to be stored in return values) within mock
 * functions (smock_pull(q)).
 *
 * - Finally, ensuring that everything's consumed every now and then
 * within the testcase (smock_empty()).
 */

/* This is where every queue is stored. */
static struct list_head *_smock_head;

typedef struct {
  /* within _smock_head */
  struct list_head lh;

  /* entries */
  struct list_head eh;
  char name[SMOCK_QUEUE_NAME_LENGTH];
} smock_queue_s, *smock_queue;


typedef struct {
  struct list_head lh;
  void *value;
} smock_entry_s, *smock_entry;

static inline smock_queue _smock_get_queue(const char *name, bool create)
{
  struct list_head *h;
  smock_queue q;

  if (!_smock_head)
    {
      if (!create)
        return NULL;
      /* Create new head. */
      _smock_head = malloc(sizeof(*_smock_head));
      if (!_smock_head)
        return NULL;
      INIT_LIST_HEAD(_smock_head);
    }
  if (strlen(name) >= SMOCK_QUEUE_NAME_LENGTH)
    return NULL;
  list_for_each(h, _smock_head)
    {
      q = container_of(h, smock_queue_s, lh);
      if (strcmp(name, q->name) == 0)
        return q;
    }
  if (!create)
    return NULL;
  q = calloc(1, sizeof(*q));
  if (!q)
    return NULL;
  strcpy(q->name, name);
  list_add(&q->lh, _smock_head);
  INIT_LIST_HEAD(&q->eh);
  return q;
}

static inline void smock_push(const char *name, void *value)
{
  smock_queue q = _smock_get_queue(name, true);
  smock_entry e = calloc(1, sizeof(*e));

  e->value = value;
  list_add_tail(&e->lh, &q->eh);
}

static inline void *smock_pull(const char *name)
{
  smock_queue q = _smock_get_queue(name, false);
  struct list_head *h;
  smock_entry e;
  void *r;

  sput_fail_unless(q, name);
  if (!q)
    {
      return NULL;
    }
  if (list_empty(&q->eh))
    {
      sput_fail_unless(!list_empty(&q->eh), "queue not empty ");
      return NULL;
    }
  h = q->eh.next;
  list_del(h);
  e = container_of(h, smock_entry_s, lh);
  r = e->value;
  free(e);
  if (list_empty(&q->eh))
    {
      /* Get rid of q */
      list_del(&q->lh);
      free(q);
      if (list_empty(_smock_head))
        {
          free(_smock_head);
          _smock_head = NULL;
        }
    }
  return r;
}

#define smock_empty() (_smock_head == NULL)

static inline void smock_is_empty()
{
  struct list_head *h;
  smock_queue q;
  if (!smock_empty()) {
    list_for_each(h, _smock_head)
      {
        q = container_of(h, smock_queue_s, lh);
        sput_fail_unless(!q, q->name);
      }
  }
}

#define smock_push_int(q,v) smock_push(q, (void *)((intptr_t) (v)))
#define smock_pull_int(q) ((intptr_t)smock_pull(q))

#define smock_push_dup(q,v,v_len)       \
do {                                    \
  void *p = malloc(v_len);              \
  memcpy(p, v, v_len);                  \
  smock_push(q, p);                     \
} while(0)

#define smock_push_blob(q,v) smock_push_dup(q,&v,sizeof(v))
#define smock_push_int64(q,v) smock_push_blob(q,v)

#define smock_push_bool(q,v) smock_push_int(q, (v) ? 1 : 0)
#define smock_pull_bool(q) (smock_pull_int(q) ? true : false)

/* Assertion-like utilities. */
#define smock_pull_int_is(q,v)                          \
do {                                                    \
  intptr_t _v = smock_pull_int(q);                      \
  sput_fail_unless(_v == (v), "int match " # q);        \
} while(0)

#define smock_pull_int64_is(q,v)                        \
do {                                                    \
  int64_t *_v = smock_pull(q);                          \
  sput_fail_unless(*_v == (v), "int64ptr match " # q);  \
  free(_v);                                             \
 } while(0)


#define smock_pull_bool_is(q,v)                         \
do {                                                    \
  bool _v = smock_pull_bool(q);                         \
  sput_fail_unless(_v == (v), "bool match " # q);       \
} while(0)

#define smock_pull_string_is(q, v)                      \
do {                                                    \
  char *_tmp = smock_pull(q);                           \
  sput_fail_unless(_tmp && strcmp(_tmp, (v)) == 0,      \
                   "smock string match " # q);          \
 } while(0)


#endif /* SMOCK_H */
