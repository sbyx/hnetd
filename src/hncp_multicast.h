/*
 * $Id: hncp_multicast.h $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2015 cisco Systems, Inc.
 *
 * Created:       Mon Feb 23 20:50:57 2015 mstenber
 * Last modified: Mon Feb 23 22:11:07 2015 mstenber
 * Edit time:     4 min
 *
 */

#pragma once

#include "dncp.h"

typedef struct hncp_multicast_struct hncp_multicast_s, *hncp_multicast;

typedef struct {
  /* For the time being, only real content. */
  const char *multicast_script;

  /* Eventually, could add e.g. support for choosing whether we can
   * even support being border proxy, or being RP.. */
} hncp_multicast_params_s, *hncp_multicast_params;

hncp_multicast hncp_multicast_create(dncp h, hncp_multicast_params p);

void hncp_multicast_destroy(hncp_multicast m);

bool hncp_multicast_busy(hncp_multicast m);

