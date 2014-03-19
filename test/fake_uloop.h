/*
 * $Id: fake_uloop.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 */

/* This is written with two potential applications in mind;

   [1] test applications that want to manage their own time (net_sim)

   and

   [2] test applications that want uloop to pretend that time moves
   for them (test_pa, test_iface).

   The code's based on bits and pieces from test_pa and net_sim,
   merged to keep it in one place and reusable elsewhere too. The main
   idea is that there's only ONE place where time and list of pending
   timeouts is kept, and that's here (just like in test_pa).

   As shared functionality, we provide replacement for hnetd_time(),
   as well as set_hnetd_time() utility call.

   For case [1] we provide fu_poll() which runs currently pending
   timeouts and provide fu_next_time() (returns the time of next event).

   For case [2] we provide uloop_run() which obeys also uloop_end().
*/

#ifndef FAKE_ULOOP_H
#define FAKE_ULOOP_H

#include <libubox/uloop.h>
#include <libubox/list_compat.h>

#include "sput.h"

#define hnetd_time() _fu_time
#define set_hnetd_time fu_set_hnetd_time
#define uloop_init() fu_init()
#define uloop_run() (void)fu_loop(-1)
#define uloop_end() do { _fu_loop_ended = true; } while(0)
#define uloop_timeout_set fu_timeout_set
#define uloop_timeout_cancel fu_timeout_cancel

static hnetd_time_t _fu_time;
LIST_HEAD(timeouts);

static inline void fu_init()
{
  /*      12345678901 (> MAXINT, but not much over) */
  _fu_time = 10000000000;
  INIT_LIST_HEAD(&timeouts);
}

static inline void fu_set_hnetd_time(hnetd_time_t v)
{
  sput_fail_unless(v >= _fu_time, "time cannot move to past");
  _fu_time = v;
}

static void _to_tv(hnetd_time_t t, struct timeval *tv)
{
  tv->tv_sec = t / HNETD_TIME_PER_SECOND;
  tv->tv_usec = t % HNETD_TIME_PER_SECOND;
}

static hnetd_time_t _to_time(struct timeval *tv)
{
  return (int64_t)tv->tv_sec * HNETD_TIME_PER_SECOND + tv->tv_usec;
}

static int fu_timeout_set(struct uloop_timeout *timeout, int ms)
{
  sput_fail_if(ms < 0, "Timeout delay is positive");
  hnetd_time_t v = hnetd_time() + ms;

  if(timeout->pending)
    list_remove(&timeout->list);
  else
    timeout->pending = true;

  _to_tv(v, &timeout->time);

  struct uloop_timeout *tp;
  list_for_each_entry(tp, &timeouts, list)
    {
      if (_to_time(&tp->time) > v)
        {
          list_add_before(&tp->list, &timeout->list);
          return 0;
        }
    }
  list_add_tail(&timeout->list, &timeouts);
  return 0;
}

static int fu_timeout_cancel(struct uloop_timeout *timeout)
{
#ifdef FU_PARANOID_TIMEOUT_CANCEL
  sput_fail_unless(timeout->pending, "Timeout pending in timeout_cancel");
#endif /* FU_PARANOID_TIMEOUT_CANCEL */
  if (timeout->pending)
    {
      list_remove(&timeout->list);
      timeout->pending = 0;
    }
  return 0;
}

static inline struct uloop_timeout *fu_next()
{
  if (list_is_empty(&timeouts))
    return NULL;
  return list_first_entry(&timeouts, struct uloop_timeout, list);
}

static inline hnetd_time_t fu_next_time()
{
  struct uloop_timeout *to = fu_next();
  return to && _to_time(&to->time) || 0;
}

static inline void fu_run_one(struct uloop_timeout *t)
{
  list_remove(&t->list);
  t->pending = false;
  if(t->cb)
    t->cb(t);
}

static bool _fu_loop_ended;
static inline int fu_loop(int rounds)
{
  struct uloop_timeout *to;

  _fu_loop_ended = false;
  while (!_fu_loop_ended && rounds != 0 && (to = fu_next()))
    {
      hnetd_time_t when = _to_time(&to->time);
      if (when >= hnetd_time())
        set_hnetd_time(when);
      fu_run_one(to);
      rounds--;
    }
  return rounds;
}

static inline int fu_poll(void)
{
  int ran = 0;
  hnetd_time_t now = hnetd_time();
  struct uloop_timeout *to;

  while ((to = fu_next()) && _to_time(&to->time) <= now)
    {
      fu_run_one(to);
      ran++;
    }
  return ran;
}


#endif /* FAKE_ULOOP_H */
