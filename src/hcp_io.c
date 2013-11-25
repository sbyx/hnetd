/*
 * $Id: hcp_io.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Mon Nov 25 14:00:10 2013 mstenber
 * Last modified: Mon Nov 25 14:28:37 2013 mstenber
 * Edit time:     7 min
 *
 */

/* This module implements I/O needs of hcp. Notably, it has both
 * functionality that deals with sockets, and bit more abstract ones
 * that just deal with buffers for input and output (thereby
 * facilitating unit testing without using real sockets). */

#include "hcp_i.h"

bool hcp_io_init(hcp o __unused)
{
  return true;
}

void hcp_io_uninit(hcp o __unused)
{
}
