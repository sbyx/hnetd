/*
 * $Id: hcp_pa.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:34:12 2013 mstenber
 * Last modified: Thu Dec  5 11:48:39 2013 mstenber
 * Edit time:     1 min
 *
 */

#ifndef HCP_PA_H
#define HCP_PA_H

#include "hcp.h"
#include "pa.h"

typedef struct hcp_glue_struct hcp_glue_s, *hcp_glue;

/* Connect HCP and PA together. For the time being, we don't even
 * assume that this binding can ever be done.
 *
 * @return the context that was created
*/
hcp_glue hcp_pa_glue_create(hcp o, pa_t pa);

void hcp_pa_glue_destroy(hcp_glue glue);

#endif /* HCP_PA_H */
