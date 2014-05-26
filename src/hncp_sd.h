/*
 * $Id: hncp_sd.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 20:09:23 2014 mstenber
 * Last modified: Thu May 22 13:02:32 2014 mstenber
 * Edit time:     4 min
 *
 */

#ifndef HNCP_SD_H
#define HNCP_SD_H

#include "hncp.h"

typedef struct hncp_sd_struct hncp_sd_s, *hncp_sd;

/* These are the parameters SD code uses. The whole structure's memory
 * is owned by the external party, and is assumed to be valid from
 * sd_create to sd_destroy. */
typedef struct hncp_sd_params_struct
{
  /* Which script is used to prod at dnsmasq */
  const char *dnsmasq_script;

  /* And where to store the dnsmasq.conf */
  const char *dnsmasq_bonus_file;

  /* Which script is used to prod at ohybridproxy */
  const char *ohp_script;

  /* Router name (if desired, optional) */
  const char *router_name;
  const char *domain_name;
} hncp_sd_params_s, *hncp_sd_params;

hncp_sd hncp_sd_create(hncp h, hncp_sd_params p);

void hncp_sd_destroy(hncp_sd sd);

#endif /* HNCP_SD_H */
