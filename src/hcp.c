/*
 * $Id: hcp.c $
 *
 * Author: Markus Stenberg <markus stenberg@iki.fi>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Nov 20 16:00:31 2013 mstenber
 * Last modified: Wed Nov 20 16:18:57 2013 mstenber
 * Edit time:     6 min
 *
 */

#include "hcp_i.h"

hcp hcp_create(void)
{
  hcp o;
  o = calloc(1, sizeof(*o));
  if (!o) return NULL;
  return o;
}

void hcp_destroy(hcp o)
{
  if (!o) return;
  /* XXX */
  free(o);
}

hcp_node hcp_get_first_node(hcp o)
{
  hcp_node n;
  return avl_first_element(&o->nodes.avl, n, in_nodes.avl);
}

void hcp_add_tlv(hcp o, struct tlv_attr *tlv)
{
}

void hcp_remove_tlv(hcp o, struct tlv_attr *tlv)
{
}

