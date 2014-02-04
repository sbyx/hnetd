/*
 * $Id: hncp_pa.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:34:12 2013 mstenber
 * Last modified: Tue Feb  4 18:21:54 2014 mstenber
 * Edit time:     1 min
 *
 */

#ifndef HNCP_PA_H
#define HNCP_PA_H

#include "hncp.h"
#include "pa.h"

typedef struct hncp_glue_struct hncp_glue_s, *hncp_glue;

/* Connect HNCP and PA together. For the time being, we don't even
 * assume that this binding can ever be done.
 *
 * @return the context that was created
 */
hncp_glue hncp_pa_glue_create(hncp o, pa_t pa);

void hncp_pa_glue_destroy(hncp_glue glue);

#endif /* HNCP_PA_H */
