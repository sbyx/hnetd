/*
 * $Id: hncp_pa.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:34:12 2013 mstenber
 * Last modified: Mon Jun  2 12:44:35 2014 mstenber
 * Edit time:     4 min
 *
 */

#ifndef HNCP_PA_H
#define HNCP_PA_H

#include "hncp.h"
#include "pa_data.h"

#define HNCP_DELAY    3000
#define HNCP_DELAY_LL 500

typedef struct hncp_glue_struct hncp_glue_s, *hncp_glue;

/* Connect HNCP and PA together. For the time being, we don't even
 * assume that this binding can ever be done.
 *
 * @return the context that was created
 */
hncp_glue hncp_pa_glue_create(hncp o, struct pa_data *data);

void hncp_pa_glue_destroy(hncp_glue glue);

typedef enum { HNCP_PA_EXTDATA_IPV4=0,
               HNCP_PA_EXTDATA_IPV6=1,
               NUM_HNCP_PA_EXTDATA=2 } hncp_pa_extdata_type;

/* Callback to indicate that (some) iface dhcp{v6,}_data_in changed. */
void hncp_pa_set_external_link(hncp_glue glue, const char *ifname,
                               const void *data, size_t data_len,
                               hncp_pa_extdata_type index);

#endif /* HNCP_PA_H */
