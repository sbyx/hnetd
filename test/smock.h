/*
 * $Id: smock.h $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Tue Nov 26 10:14:59 2013 mstenber
 * Last modified: Tue Nov 26 11:04:46 2013 mstenber
 * Edit time:     38 min
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

  sput_fail_unless(!list_empty(&q->eh), name);
  if (list_empty(&q->eh))
    {
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

static inline bool smock_empty()
{
  return _smock_head == NULL;
}

#define smock_push_int(q,v) smock_push(q, (void *)((intptr_t) v))
#define smock_pull_int(q) (intptr_t)smock_pull(q)

#endif /* SMOCK_H */
