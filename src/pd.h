/*
 * Author: Steven Barth <steven@midlink.org>
 *
 * Copyright (c) 2014-2015 cisco Systems, Inc.
 */

#ifndef PD_H_
#define PD_H_

#include "hncp_pa.h"

struct pd;
struct pd* pd_create(hncp_pa hncp_pa, const char *path);
void pd_destroy(struct pd *pd);

#endif /* PD_H_ */
