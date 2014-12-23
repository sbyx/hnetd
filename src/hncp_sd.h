/*
 * $Id: hncp_sd.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 20:09:23 2014 mstenber
 * Last modified: Tue Dec 23 18:48:01 2014 mstenber
 * Edit time:     7 min
 *
 */

#pragma once

#include "dncp.h"
#include "dncp_i.h"

typedef struct hncp_sd_struct hncp_sd_s, *hncp_sd;

/* These are the parameters SD code uses. The whole structure's memory
 * is owned by the external party, and is assumed to be valid from
 * sd_create to sd_destroy. */
typedef struct hncp_sd_params_struct
{
  /* Which script is used to prod at dnsmasq (required for SD) */
  const char *dnsmasq_script;

  /* And where to store the dnsmasq.conf (required for SD) */
  const char *dnsmasq_bonus_file;

  /* Which script is used to prod at ohybridproxy (required for SD) */
  const char *ohp_script;

  /* Which script is used to prod at minimalist-pcproxy (optional) */
  const char *pcp_script;

  /* Router name (if desired, optional) */
  const char *router_name;

  /* Domain name (if desired, optional, copied from others if set there) */
  const char *domain_name;
} hncp_sd_params_s, *hncp_sd_params;

hncp_sd hncp_sd_create(dncp h, hncp_sd_params p);

void hncp_sd_dump_link_fqdn(hncp_sd sd, dncp_link l,
                            char *buf, size_t buf_len);

void hncp_sd_destroy(hncp_sd sd);
