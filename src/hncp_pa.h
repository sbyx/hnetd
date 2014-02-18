/*
 * $Id: hncp_pa.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:34:12 2013 mstenber
 * Last modified: Wed Feb 12 17:30:59 2014 mstenber
 * Edit time:     2 min
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

/* Callback to indicate that (some) iface dhcpv6_data_in changed. */
void hncp_pa_set_dhcpv6_data_in_dirty(hncp_glue glue);

#endif /* HNCP_PA_H */
