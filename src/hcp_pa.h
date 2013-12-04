/*
 * $Id: hcp_pa.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 12:34:12 2013 mstenber
 * Last modified: Wed Dec  4 12:54:23 2013 mstenber
 * Edit time:     1 min
 *
 */

#ifndef HCP_PA_H
#define HCP_PA_H

#include "hcp.h"
#include "pa.h"

/* Connect HCP and PA together. For the time being, we don't even
 * assume that this binding can ever be done.
 *
 * @return true on success, false otherwise.
*/
bool hcp_connect_pa(hcp o, pa_t pa);

#endif /* HCP_PA_H */
