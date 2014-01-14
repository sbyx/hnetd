/*
 * $Id: hcp_sd.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Tue Jan 14 20:09:23 2014 mstenber
 * Last modified: Tue Jan 14 21:13:59 2014 mstenber
 * Edit time:     1 min
 *
 */

#ifndef HCP_SD_H
#define HCP_SD_H

#include "hcp.h"

typedef struct hcp_sd_struct hcp_sd_s, *hcp_sd;

hcp_sd hcp_sd_create(hcp h,
                     const char *dnsmasq_script,
                     const char *dnsmasq_bonus_file,
                     const char *ohp_script,
                     const char *router_name);

void hcp_sd_destroy(hcp_sd sd);


#endif /* HCP_SD_H */
