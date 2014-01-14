/*
 * $Id: hcp_sd.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 14:04:22 2014 mstenber
 * Last modified: Tue Jan 14 21:54:43 2014 mstenber
 * Edit time:     84 min
 *
 */

/* This module implements the HCP-based service discovery support.
 *
 * By default, if this isn't enabled, _normal_ DNS based activity
 * across a network should still work (thanks to DNS servers being
 * transmitted as part of prefix options for delegated prefixes and
 * configured appropriately to the clients), but this module provides
 * two extra 'features':
 *
 * - dns-sd configuration for dnsmasq (both records and remote servers)
 *
 * - maintenance of running hybrid proxy on the desired interfaces
 *
 */

#include <unistd.h>

#include "hcp_sd.h"
#include "hcp_i.h"
#include "dns_util.h"

#define LOCAL_OHP_ADDRESS "127.0.0.2"
#define OHP_ARGS_MAX_LEN 512
#define OHP_ARGS_MAX_COUNT 64

struct hcp_sd_struct
{
  hcp h;

  /* What we were given as router name base (or just 'r' by default). */
  char router_name_base[DNS_MAX_ESCAPED_L_LEN];
  char router_name[DNS_MAX_ESCAPED_L_LEN];
  /* how many iterations we've added to routername to get our current one. */
  int router_name_iteration;

  char domain[DNS_MAX_ESCAPED_LEN];
  char *dnsmasq_script;
  char *dnsmasq_bonus_file;
  char *ohp_script;
};


/* Utility function glommed from platform-generic platform_exec/call. */
static void _fork_execv(char *argv[])
{
  pid_t pid = vfork();
  if (pid == 0) {
    execv(argv[0], argv);
    _exit(128);
  }
  waitpid(pid, NULL, 0);
}

bool hcp_sd_write_dnsmasq_conf(hcp_sd sd, const char *filename)
{
  char *args[] = { (char *)sd->dnsmasq_script, NULL};

  /* XXX */
  return false;
}

#define PUSH_ARG(s) do                                  \
{                                                       \
  int _arg = narg++;                                    \
  if (narg == OHP_ARGS_MAX_COUNT)                       \
  {                                                     \
    L_DEBUG("too many arguments");                      \
    return false;                                       \
  }                                                     \
  if (strlen(s) + 1 + c > (buf + OHP_ARGS_MAX_LEN))     \
    {                                                   \
      L_DEBUG("out of buffer");                         \
    }                                                   \
  args[_arg] = c;                                       \
  strcpy(c, s);                                         \
  c += strlen(s) + 1;                                   \
} while(0)

bool hcp_sd_reconfigure_ohp(hcp_sd sd)
{
  char buf[OHP_ARGS_MAX_LEN];
  char *c = buf;
  char *args[OHP_ARGS_MAX_COUNT];
  int narg = 0;
  uint32_t dumped_link_id = 0;
  hcp_t_assigned_prefix_header ah;
  char tbuf[DNS_MAX_ESCAPED_LEN];
  char link_name[10];

  struct tlv_attr *a;
  int i;

  if (!sd->ohp_script)
    {
      L_ERR("no ohp_script set yet hcp_sd_reconfigure_ohp called");
      return false;
    }
  PUSH_ARG(sd->ohp_script);

  /* We're responsible only for those interfaces that we have assigned
   * prefix for. */
  hcp_node_for_each_tlv_i(sd->h->own_node, a, i)
    if (tlv_id(a) == HCP_T_ASSIGNED_PREFIX)
      {
        ah = tlv_data(a);
        /* If we already dumped this link, no need to do it
         * again. (Data structure is sorted by link id -> we will get
         * them in order). */
        if (dumped_link_id == ah->link_id)
          continue;
        dumped_link_id = ah->link_id;
        /* XXX - what sort of naming scheme should we use for links? */
        sprintf(link_name, "i%d", be32_to_cpu(dumped_link_id));
        sprintf(tbuf, "%s.%s.%s", link_name, sd->router_name, sd->domain);
      }
  args[narg] = NULL;
  _fork_execv(args);
  return true;
}

static void
_set_router_name(hcp_sd sd, bool add)
{
  /* Set the current router name. */
  unsigned char buf[sizeof(struct tlv_attr) + DNS_MAX_ESCAPED_L_LEN + 5];
  struct tlv_attr *a = (struct tlv_attr *)buf;
  int flen = TLV_SIZE + strlen(sd->router_name);

  tlv_init(a, HCP_T_DNS_ROUTER_NAME, flen);
  memcpy(tlv_data(a), sd->router_name, strlen(sd->router_name));
  if (add)
    {
      if (!hcp_add_tlv(sd->h, a))
        L_ERR("failed to add router name TLV");
    }
  else
    {
      if (!hcp_remove_tlv(sd->h, a))
        L_ERR("failed to remove router name TLV");
    }
}

static hcp_node
_find_router_name(hcp_sd sd)
{
  hcp_node n;
  struct tlv_attr *a;
  int i;

  hcp_for_each_node(sd->h, n)
    hcp_node_for_each_tlv_i(n, a, i)
    if (tlv_id(a) == HCP_T_DNS_ROUTER_NAME)
      {
        if (tlv_len(a) == strlen(sd->router_name)
            && strncmp(tlv_data(a), sd->router_name, tlv_len(a)) == 0)
          return n;
      }
  return NULL;
}

static void
_change_router_name(hcp_sd sd)
{
  /* Remove the old name. */
  _set_router_name(sd, false);

  /* Try to look for new one. */
  while (1)
    {
      sprintf(sd->router_name, "%s-%d",
              sd->router_name_base, ++sd->router_name_iteration);
      if (!_find_router_name(sd))
        {
          _set_router_name(sd, true);
          return;
        }
    }
}

hcp_sd hcp_sd_create(hcp h,
                     const char *dnsmasq_script,
                     const char *dnsmasq_bonus_file,
                     const char *ohp_script,
                     const char *router_name)
{
  hcp_sd sd = calloc(1, sizeof(*sd));

  sd->h = h;
  if (!sd
      || !(sd->dnsmasq_script = strdup(dnsmasq_script))
      || !(sd->dnsmasq_bonus_file = strdup(dnsmasq_bonus_file))
      || !(sd->ohp_script = strdup(ohp_script)))
    abort();
  if (router_name)
    strcpy(sd->router_name_base, router_name);
  else
    strcpy(sd->router_name_base, "r");
  strcpy(sd->router_name, sd->router_name_base);
  /* XXX - handle some TLV for this. */
  strcpy(sd->domain, "home.");
  _set_router_name(sd, true);
  return sd;
}

void hcp_sd_destroy(hcp_sd sd)
{
  free(sd->dnsmasq_script);
  free(sd->dnsmasq_bonus_file);
  free(sd->ohp_script);
  free(sd);
}
