/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 */

#ifndef PD_H_
#define PD_H_

#include "pa_pd.h"

struct pd;
struct pd* pd_create(struct pa_pd *pa_pd, const char *path);
void pd_destroy(struct pd *pd);

#endif /* PD_H_ */
