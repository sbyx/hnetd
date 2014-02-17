/*
 * $Id: hncp_sd.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 20:09:23 2014 mstenber
 * Last modified: Mon Feb 17 15:17:21 2014 mstenber
 * Edit time:     1 min
 *
 */

#ifndef HNCP_SD_H
#define HNCP_SD_H

#include "hncp.h"

typedef struct hncp_sd_struct hncp_sd_s, *hncp_sd;

hncp_sd hncp_sd_create(hncp h,
                       const char *dnsmasq_script,
                       const char *dnsmasq_bonus_file,
                       const char *ohp_script,
                       const char *router_name,
                       const char *domain_name);

void hncp_sd_destroy(hncp_sd sd);


#endif /* HNCP_SD_H */
