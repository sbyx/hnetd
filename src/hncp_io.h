/*
 * $Id: hncp_io.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Tue May 26 07:10:55 2015 mstenber
 * Last modified: Tue May 26 07:11:15 2015 mstenber
 * Edit time:     0 min
 *
 */

#pragma once
#include <libubox/uloop.h>
#include <netinet/in.h>
#include "dncp.h"

bool hncp_io_init(hncp h);
void hncp_io_uninit(hncp h);
