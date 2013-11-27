/*
 * $Id: test_hcp_net.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 27 10:41:56 2013 mstenber
 * Last modified: Wed Nov 27 12:02:40 2013 mstenber
 * Edit time:     31 min
 *
 */

/*
 * This is a variant of hcp test suite, which replaces the hcp_io code
 * with a fake network. The fake network can be dynamically
 * configured, and basically contains UNIDIRECTIONAL "propagate from X
 * to Y" configuration entries that can change dynamically over the
 * time of the testcase.
 */

#include "hnetd.h"
#define hnetd_time hnetd_time_mock
static hnetd_time_t hnetd_time_mock(void);
#include "hcp.c"
#include "hcp_recv.c"
#include "hcp_timeout.c"
#include "sput.h"

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/*********************************************** Fake network infrastructure */

typedef struct {
  struct list_head h;

  hcp_link l;
  struct in_addr dst;
  void *buf;
  size_t len;
} net_msg_s, *net_msg;

typedef struct {
  struct list_head h;

  hcp_link src;
  hcp_link dst;
} net_neigh_s, *net_neigh;

typedef struct {
  struct list_head h;

  hcp_s n;
} net_node_s, *net_node;

typedef struct {
  /* Initialized set of nodes. */
  struct list_head nodes;
  struct list_head neighs;
  struct list_head messages;
} net_sim_s, *net_sim;

void net_sim_init(net_sim s)
{
  INIT_LIST_HEAD(&s->nodes);
  INIT_LIST_HEAD(&s->neighs);
  INIT_LIST_HEAD(&s->messages);
}

void net_sim_uninit(net_sim s)
{
  struct list_head *p, *pn;

  list_for_each_safe(p, pn, &s->nodes)
    {
      net_node n = container_of(p, net_node_s, h);
      hcp_uninit(&n->n);
      free(n);
    }
  list_for_each_safe(p, pn, &s->neighs)
    {
      net_neigh n = container_of(p, net_neigh_s, h);
      free(n);
    }
  list_for_each_safe(p, pn, &s->messages)
    {
      net_msg m = container_of(p, net_msg_s, h);
      free(m->buf);
      free(m);
    }
}

/********************************************************* Mocked interfaces */

hnetd_time_t now_time;
hnetd_time_t next_time;

bool hcp_io_init(hcp o)
{
  return true;
}

void hcp_io_uninit(hcp o)
{
}

bool hcp_io_set_ifname_enabled(hcp o, const char *ifname, bool enabled)
{
  return true;
}

int hcp_io_get_hwaddr(const char *ifname, unsigned char *buf, int buf_left)
{
  return 0;
}

void hcp_io_schedule(hcp o, int msecs)
{
  if (!next_time || msecs < (next_time - now_time))
    next_time = now_time + msecs;
}

ssize_t hcp_io_recvfrom(hcp o, void *buf, size_t len,
                        char *ifname,
                        struct in6_addr *src,
                        struct in6_addr *dst)
{
  return -1;
}

ssize_t hcp_io_sendto(hcp o, void *buf, size_t len,
                      const char *ifname,
                      const struct in6_addr *dst)
{
  return -1;
}

static hnetd_time_t hnetd_time_mock(void)
{
  return now_time;
}

/**************************************************************** Test cases */

void hcp_two(void)
{
  /* XXX */
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hcp_net"); /* optional */
  sput_run_test(hcp_two);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
