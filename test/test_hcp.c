/*
 * $Id: test_hcp.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 13:26:21 2013 mstenber
 * Last modified: Mon Nov 25 19:03:12 2013 mstenber
 * Edit time:     20 min
 *
 */

#include "hcp.h"
#include "sput.h"

void hcp_ext(void)
{
  hcp o = hcp_create();
  hcp_node n;
  bool r;
  struct tlv_buf tb;
  struct tlv_attr *t, *t_data;

  sput_fail_if(!o, "create works");
  n = hcp_get_first_node(o);
  sput_fail_unless(n, "first node exists");

  sput_fail_unless(hcp_node_is_self(n), "self node");

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);
  t_data = tlv_put(&tb, 123, NULL, 0);

  /* Put the 123 type length = 0 TLV as TLV to hcp. */
  r = hcp_add_tlv(o, t_data);
  sput_fail_unless(r, "hcp_add_tlv ok (should work)");

  hcp_node_get_tlvs(n, &t);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs consistent");

  /* Should be able to enable it on a link. */
  r = hcp_set_link_enabled(o, "eth0", true);
  sput_fail_unless(r, "hcp_set_link_enabled eth0");

  r = hcp_set_link_enabled(o, "eth1", true);
  sput_fail_unless(r, "hcp_set_link_enabled eth1");

  r = hcp_set_link_enabled(o, "eth1", true);
  sput_fail_unless(!r, "hcp_set_link_enabled eth1 (2nd true)");

  hcp_node_get_tlvs(n, &t);
  sput_fail_unless(!tlv_attr_equal(t, tb.head), "tlvs should be different");

  r = hcp_set_link_enabled(o, "eth1", false);
  sput_fail_unless(r, "hcp_set_link_enabled eth1 (false)");

  r = hcp_set_link_enabled(o, "eth1", false);
  sput_fail_unless(!r, "hcp_set_link_enabled eth1 (2nd false)");

  hcp_node_get_tlvs(n, &t);
  sput_fail_unless(!tlv_attr_equal(t, tb.head), "tlvs should be different");

  /* Make sure run doesn't blow things up */
  hcp_run(o);

  r = hcp_remove_tlv(o, t_data);
  sput_fail_unless(r, "hcp_remove_tlv should work");

  r = hcp_remove_tlv(o, t_data);
  sput_fail_unless(!r, "hcp_remove_tlv should not work");

  n = hcp_node_get_next(n);
  sput_fail_unless(!n, "second node should not exist");

  hcp_destroy(o);

  tlv_buf_free(&tb);
}

#include "hcp_i.h"

void hcp_int(void)
{
}

int main(__unused int argc, __unused char **argv)
{
  sput_start_testing();
  sput_enter_suite("hcp"); /* optional */
  sput_run_test(hcp_ext);
  sput_run_test(hcp_int);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
