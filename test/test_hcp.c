/*
 * $Id: test_hcp.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 13:26:21 2013 mstenber
 * Last modified: Wed Dec  4 11:06:06 2013 mstenber
 * Edit time:     66 min
 *
 */

#include "hcp.h"
#include "sput.h"
#include "smock.h"

/**************************************************************** Test cases */

void tlv_iter(void)
{
  struct tlv_buf tb;
  struct tlv_attr *a, *a1, *a2, *a3;
  int c;
  unsigned int rem;
  void *tmp;

  /* Initialize test structure. */
  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);
  a1 = tlv_new(&tb, 1, 0);
  a2 = tlv_new(&tb, 2, 1);
  a3 = tlv_new(&tb, 3, 4);
  sput_fail_unless(a1 && a2 && a3, "a1-a3 create");

  /* Make sure iteration is sane. */
  c = 0;
  tlv_for_each_attr(a, tb.head, rem)
    c++;
  sput_fail_unless(c == 3, "right iter result 1");

  /* remove 3 bytes -> a3 header complete but not body. */
  tlv_init(tb.head, 0, tlv_raw_len(tb.head) - 3);
  c = 0;
  tlv_for_each_attr(a, tb.head, rem)
    c++;
  sput_fail_unless(c == 2, "right iter result 2");

  /* remove 2 bytes -> a3 header not complete (no body). */
  tlv_init(tb.head, 0, tlv_raw_len(tb.head) - 2);
  c = 0;
  tmp = malloc(tlv_raw_len(tb.head));
  memcpy(tmp, tb.head, tlv_raw_len(tb.head));
  tlv_for_each_attr(a, tmp, rem)
    c++;
  sput_fail_unless(c == 2, "right iter result 3");
  free(tmp);

  /* Free structures. */
  tlv_buf_free(&tb);
}

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

  t = hcp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs consistent");

  /* Should be able to enable it on a link. */
  r = hcp_set_link_enabled(o, "eth0", true);
  sput_fail_unless(r, "hcp_set_link_enabled eth0");

  r = hcp_set_link_enabled(o, "eth1", true);
  sput_fail_unless(r, "hcp_set_link_enabled eth1");

  r = hcp_set_link_enabled(o, "eth1", true);
  sput_fail_unless(!r, "hcp_set_link_enabled eth1 (2nd true)");

  t = hcp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  r = hcp_set_link_enabled(o, "eth1", false);
  sput_fail_unless(r, "hcp_set_link_enabled eth1 (false)");

  r = hcp_set_link_enabled(o, "eth1", false);
  sput_fail_unless(!r, "hcp_set_link_enabled eth1 (2nd false)");

  t = hcp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  /* Make sure run doesn't blow things up */
  hcp_run(o);

  /* Similarly, poll should also be nop (socket should be non-blocking). */
  hcp_poll(o);

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
  /* If we want to do bit more whitebox unit testing of the whole hcp,
   * do it here. */
  hcp_s s;
  hcp o = &s;
  unsigned char hwbuf[] = "foo";
  hcp_node n;
  hcp_link l;
  struct tlv_buf tb;
  struct tlv_attr *t1, *t2;

  hcp_init(o, hwbuf, strlen((char *)hwbuf));

  /* Make sure network hash is dirty. */
  sput_fail_unless(o->network_hash_dirty, "network hash should be dirty");

  /* Make sure we can add nodes if we feel like it. */
  hcp_hash_s h;
  hcp_calculate_hash("bar", 3, &h);
  n = hcp_find_node_by_hash(o, &h, false);
  sput_fail_unless(!n, "hcp_find_node_by_hash w/ create=false => none");
  n = hcp_find_node_by_hash(o, &h, true);
  sput_fail_unless(n, "hcp_find_node_by_hash w/ create=false => !none");
  sput_fail_unless(hcp_find_node_by_hash(o, &h, false), "should exist");
  sput_fail_unless(hcp_find_node_by_hash(o, &h, false) == n, "still same");

  n = hcp_get_first_node(o);
  sput_fail_unless(n, "hcp_get_first_node");
  n = hcp_node_get_next(n);
  sput_fail_unless(n, "hcp_node_get_next");

  /* Similarly, links */
  const char *ifn = "foo";
  l = hcp_find_link(o, ifn, false);
  sput_fail_unless(!l, "hcp_find_link w/ create=false => none");
  l = hcp_find_link(o, ifn, true);
  sput_fail_unless(l, "hcp_find_link w/ create=false => !none");
  sput_fail_unless(hcp_find_link(o, ifn, false) == l, "still same");

  /* Play with run; initially should increment update number */
  sput_fail_unless(o->own_node->update_number == 0, "update number ok");
  hcp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  /* but on second run, no */
  hcp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);
  t1 = tlv_put(&tb, 123, NULL, 0);
  t2 = tlv_put(&tb, 124, NULL, 0);
  hcp_add_tlv(o, t1);

  /* Added TLV should trigger new update */
  hcp_run(o);
  sput_fail_unless(o->own_node->update_number == 2, "update number ok");

  /* Adding/removing TLV should NOT trigger new update. */
  hcp_add_tlv(o, t2);
  hcp_remove_tlv(o, t2);
  hcp_run(o);
  sput_fail_unless(o->own_node->update_number == 2, "update number ok");
  
  hcp_uninit(o);
  tlv_buf_free(&tb);
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hcp", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hcp"); /* optional */
  sput_run_test(tlv_iter);
  sput_run_test(hcp_ext);
  sput_run_test(hcp_int);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
