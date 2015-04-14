/*
 * $Id: hncp_multicast.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 20:39:45 2015 mstenber
 * Last modified: Tue Mar 24 11:21:37 2015 mstenber
 * Edit time:     94 min
 *
 */

/* Multicast routing related support functionality.
 *
 * It handles 3 things (if enabled):
 * [1] interface state notifications
 * [2] advertising of border proxy address iff local DP present
 * ( + providing their deltas to the callback script )
 * [3] RP election using RPA TLV
 * ( + providing the result to the callback script )
 */

#include "hncp_multicast.h"
#include "dncp_i.h"
#include "iface.h"

#include <unistd.h>
#include <sys/wait.h>

/* No churn in local EC long -> publish TLV + declare us BP */
#define BP_UPDATE_TIMEOUT 1000

/* Timeout until we run election step + either add/remove ourselves (+
 * notify script if there is a change) */
#define RP_ELECTION_TIMEOUT 1000

struct hncp_multicast_struct
{
  /* Who are we attached to */
  dncp dncp;

  /* Creation-time parameters */
  hncp_multicast_params_s p;

  /* Timeouts that handle delayed behavior */
  struct uloop_timeout bp_timeout;
  struct uloop_timeout rp_timeout;

  struct in6_addr current_rpa;

  /* Callbacks from other modules */
  struct iface_user iface;
  dncp_subscriber_s subscriber;
};

/*
  TBD: platform_{call,exec} should be really made publicly visible
  utility functions. This Nth fork+exec+waitpid is .. excessive.
*/
/* Utility function glommed from platform-generic platform_exec/call. */
static void _fork_execv(char *argv[])
{
  pid_t pid = fork();

  if (pid == 0) {
    execv(argv[0], argv);
    _exit(128);
  }
  L_DEBUG("hncp_multicast calling %s", argv[0]);
  for (int i = 1 ; argv[i] ; i++)
    L_DEBUG(" %s", argv[i]);
  /* waitpid(pid, NULL, 0); - we do not really want to call these
   * synchronously, the script can do it's own locking if it wants
   * to..*/
}

static void _tlv_cb(dncp_subscriber s,
                    dncp_node n, struct tlv_attr *tlv, bool add)
{
  hncp_multicast m = container_of(s, hncp_multicast_s, subscriber);

  switch (tlv_id(tlv))
    {
    case HNCP_T_EXTERNAL_CONNECTION:
      if (n == m->dncp->own_node)
        uloop_timeout_set(&m->bp_timeout, BP_UPDATE_TIMEOUT);
      break;
    case HNCP_T_PIM_BORDER_PROXY:
      if (tlv_len(tlv) == 16)
        {
          char buf[256];
          if (!inet_ntop(AF_INET6, tlv_data(tlv),
                         buf, sizeof(buf)))
            return;
          char *argv[] = {(char *)m->p.multicast_script,
                          "bp",
                          add ? "add" : "remove",
                          n == m->dncp->own_node ? "local" : "remote",
                          buf, NULL};
          _fork_execv(argv);
        }
      break;
    case HNCP_T_PIM_RPA_CANDIDATE:
      uloop_timeout_set(&m->rp_timeout, RP_ELECTION_TIMEOUT);
      break;
    }
}

static void _cb_intiface(struct iface_user *u, const char *ifname, bool enabled)
{
  hncp_multicast m = container_of(u, hncp_multicast_s, iface);
  char *argv[] = { (char *)m->p.multicast_script,
                   "ifstate",
                   (char *)ifname,
                   enabled ? "int" : "ext",
                   NULL };
  _fork_execv(argv);
}


static void _notify_rp(hncp_multicast m, struct in6_addr *a, bool local)
{
  if (memcmp(a, &m->current_rpa, sizeof(*a)) == 0)
    return;
  char buf2[256];
  if (!inet_ntop(AF_INET6, &m->current_rpa, buf2, sizeof(buf2)))
    return;
  m->current_rpa = *a;
  char buf[256];
  if (!inet_ntop(AF_INET6, a, buf, sizeof(buf)))
    return;
  char *argv[] = {(char *)m->p.multicast_script,
                  "rpa", local ? "local" : "remote", buf, buf2, NULL};
  _fork_execv(argv);
}

static void _rp_timeout(struct uloop_timeout *t)
{
  hncp_multicast m = container_of(t, hncp_multicast_s, rp_timeout);

  dncp_node n, found_node = NULL;
  struct tlv_attr *a, *found = NULL;

  dncp_for_each_node(m->dncp, n)
    dncp_node_for_each_tlv_with_type(n, a, HNCP_T_PIM_RPA_CANDIDATE)
    {
      if (tlv_len(a) != sizeof(struct in6_addr))
        continue;
      if (!found || dncp_node_cmp(n, found_node) > 0)
        {
          found = a;
          found_node = n;
        }
    }
  if (found)
    {
      int ret = dncp_node_cmp(found_node, m->dncp->own_node);
      if (ret)
        {
          if (ret > 0)
            dncp_remove_tlvs_by_type(m->dncp, HNCP_T_PIM_RPA_CANDIDATE);
          _notify_rp(m, tlv_data(found), found_node == m->dncp->own_node);
          return;
        }
    }
  dncp_remove_tlvs_by_type(m->dncp, HNCP_T_PIM_RPA_CANDIDATE);
  /* Nothing found, have to announce it (just to remove it once all
   * but the fittest one is done. sigh.) */
  struct in6_addr addr;
  if (!dncp_get_ipv6_address(m->dncp, NULL, &addr))
    {
      L_DEBUG("_rp_timeout no IPv6 address at all");
      return;
    }
  dncp_add_tlv(m->dncp, HNCP_T_PIM_RPA_CANDIDATE, &addr, 16, 0);
  _notify_rp(m, &addr, true);
}

static void _bp_timeout(struct uloop_timeout *t)
{
  hncp_multicast m = container_of(t, hncp_multicast_s, bp_timeout);
  struct tlv_attr *a;

  dncp_remove_tlvs_by_type(m->dncp, HNCP_T_PIM_BORDER_PROXY);
  dncp_node_for_each_tlv_with_type(m->dncp->own_node, a,
                                   HNCP_T_EXTERNAL_CONNECTION)
    {
      struct in6_addr addr;
      if (!dncp_get_ipv6_address(m->dncp, NULL, &addr))
        {
          L_DEBUG("_bp_timeout no IPv6 address at all");
          return;
        }
      dncp_add_tlv(m->dncp, HNCP_T_PIM_BORDER_PROXY, &addr, 16, 0);
      return;
    }
}


static void _cb_intaddr(struct iface_user *u, __unused const char *ifname,
                        __unused const struct prefix *addr6,
                        __unused const struct prefix *addr4)
{
  hncp_multicast m = container_of(u, hncp_multicast_s, iface);

  /* If addresses change, it may invalidate both TLVs. Start timeouts
   * just in case. */
  uloop_timeout_set(&m->rp_timeout, RP_ELECTION_TIMEOUT);
  uloop_timeout_set(&m->bp_timeout, BP_UPDATE_TIMEOUT);

}


hncp_multicast hncp_multicast_create(dncp h, hncp_multicast_params p)
{
  hncp_multicast m = calloc(1, sizeof(*m));

  if (!m)
    return NULL;

  m->dncp = h;

  m->p = *p;

  m->bp_timeout.cb = _bp_timeout;
  m->rp_timeout.cb = _rp_timeout;

  m->subscriber.tlv_change_callback = _tlv_cb;
  dncp_subscribe(h, &m->subscriber);

  m->iface.cb_intiface = _cb_intiface;
  m->iface.cb_intaddr = _cb_intaddr;
  iface_register_user(&m->iface);

  /* Even if we're alone, we may want to be RP. */
  uloop_timeout_set(&m->rp_timeout, RP_ELECTION_TIMEOUT);

  return m;
}

void hncp_multicast_destroy(hncp_multicast m)
{
  iface_unregister_user(&m->iface);
  dncp_unsubscribe(m->dncp, &m->subscriber);
  dncp_remove_tlvs_by_type(m->dncp, HNCP_T_PIM_RPA_CANDIDATE);
  dncp_remove_tlvs_by_type(m->dncp, HNCP_T_PIM_BORDER_PROXY);
  uloop_timeout_cancel(&m->bp_timeout);
  uloop_timeout_cancel(&m->rp_timeout);
  free(m);
}

bool hncp_multicast_busy(hncp_multicast m)
{
  return m->rp_timeout.pending || m->bp_timeout.pending;
}
