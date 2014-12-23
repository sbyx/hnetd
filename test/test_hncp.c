/*
 * $Id: test_dncp.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 13:26:21 2013 mstenber
 * Last modified: Tue Dec 23 18:11:20 2014 mstenber
 * Edit time:     87 min
 *
 */

#include "hncp.h"
#include "hncp_proto.h"
#include "sput.h"
#include "smock.h"

int log_level = LOG_DEBUG;

/* Lots of stubs here, rather not put __unused all over the place. */
#pragma GCC diagnostic ignored "-Wunused-parameter"

/* Only 'internal' method we use from here; normally, it is possible
 * to get NULL tlvs right after setting, until timeout causes flush to
 * network. */
void hncp_self_flush(hncp_node n);


/* Fake structures to keep pa's default config happy. */
void *iface_register_user;
void *iface_unregister_user;

struct iface* iface_get(const char *ifname )
{
  return NULL;
}

void iface_all_set_dhcp_send(const void *dhcpv6_data, size_t dhcpv6_len,
                             const void *dhcp_data, size_t dhcp_len)
{
}

/**************************************************************** Test cases */

void hncp_ext(void)
{
  hncp o = hncp_create();
  hncp_node n;
  bool r;
  struct tlv_buf tb;
  struct tlv_attr *t, *v = NULL;

  sput_fail_if(!o, "create works");
  n = hncp_get_first_node(o);
  sput_fail_unless(n, "first node exists");

  sput_fail_unless(hncp_node_is_self(n), "self node");

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);

  hncp_self_flush(n);
  sput_fail_unless(hncp_node_get_tlvs(n), "should have tlvs");

  tlv_for_each_attr(v, hncp_node_get_tlvs(n))
    break;
  sput_fail_unless(v && tlv_id(v) == HNCP_T_VERSION, "no version tlv");

  tlv_put(&tb, HNCP_T_VERSION, tlv_data(v), tlv_len(v));
  tlv_put(&tb, 123, NULL, 0);

  /* Put the 123 type length = 0 TLV as TLV to hncp. */
  r = hncp_add_tlv(o, 123, NULL, 0, 0);
  sput_fail_unless(r, "hncp_add_tlv ok (should work)");

  hncp_self_flush(n);
  t = hncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs consistent");

  /* Should be able to enable it on a link. */
  r = hncp_if_set_enabled(o, "eth0", true);
  sput_fail_unless(r, "hncp_if_set_enabled eth0");

  r = hncp_if_set_enabled(o, "eth1", true);
  sput_fail_unless(r, "hncp_if_set_enabled eth1");

  r = hncp_if_set_enabled(o, "eth1", true);
  sput_fail_unless(!r, "hncp_if_set_enabled eth1 (2nd true)");

  hncp_self_flush(n);
  t = hncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  r = hncp_if_set_enabled(o, "eth1", false);
  sput_fail_unless(r, "hncp_if_set_enabled eth1 (false)");

  r = hncp_if_set_enabled(o, "eth1", false);
  sput_fail_unless(!r, "hncp_if_set_enabled eth1 (2nd false)");

  hncp_self_flush(n);
  t = hncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  /* Make sure run doesn't blow things up */
  hncp_run(o);

  /* Similarly, poll should also be nop (socket should be non-blocking). */
  hncp_poll(o);

  hncp_remove_tlv_matching(o, 123, NULL, 0);

  n = hncp_node_get_next(n);
  sput_fail_unless(!n, "second node should not exist");

  hncp_destroy(o);

  tlv_buf_free(&tb);
}

#include "dncp_i.h"

void hncp_int(void)
{
  /* If we want to do bit more whitebox unit testing of the whole hncp,
   * do it here. */
  hncp_s s;
  hncp o = &s;
  unsigned char hwbuf[] = "foo";
  hncp_node n;
  hncp_link l;

  hncp_init(o, hwbuf, strlen((char *)hwbuf));

  /* Make sure network hash is dirty. */
  sput_fail_unless(o->network_hash_dirty, "network hash should be dirty");

  /* Make sure we can add nodes if we feel like it. */
  hncp_hash_s h;
  hncp_calculate_hash("bar", 3, &h);
  hncp_node_identifier ni = (hncp_node_identifier)&h;

  n = hncp_find_node_by_node_identifier(o, ni, false);
  sput_fail_unless(!n, "hncp_find_node_by_hash w/ create=false => none");
  n = hncp_find_node_by_node_identifier(o, ni, true);
  sput_fail_unless(n, "hncp_find_node_by_hash w/ create=false => !none");
  sput_fail_unless(hncp_find_node_by_node_identifier(o, ni, false), "should exist");
  sput_fail_unless(hncp_find_node_by_node_identifier(o, ni, false) == n, "still same");

  n = hncp_get_first_node(o);
  sput_fail_unless(n, "hncp_get_first_node");
  n = hncp_node_get_next(n);
  sput_fail_unless(!n, "hncp_node_get_next [before prune]");

  /* Play with run; initially should increment update number */
  sput_fail_unless(o->own_node->update_number == 0, "update number ok");
  hncp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  n = hncp_get_first_node(o);
  sput_fail_unless(n, "hncp_get_first_node");
  n = hncp_node_get_next(n);
  sput_fail_unless(!n, "hncp_node_get_next [after prune]");

  /* Similarly, links */
  const char *ifn = "foo";
  l = hncp_find_link_by_name(o, ifn, false);
  sput_fail_unless(!l, "hncp_find_link_by_name w/ create=false => none");
  l = hncp_find_link_by_name(o, ifn, true);
  sput_fail_unless(l, "hncp_find_link_by_name w/ create=false => !none");
  sput_fail_unless(hncp_find_link_by_name(o, ifn, false) == l, "still same");

  /* but on second run, no */
  hncp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  hncp_add_tlv(o, 123, NULL, 0, 0);

  /* Added TLV should trigger new update */
  hncp_run(o);
  sput_fail_unless(o->own_node->update_number == 2, "update number ok");

  /* Adding/removing TLV should NOT trigger new update. */
  hncp_tlv t2 = hncp_add_tlv(o, 124, NULL, 0, 0);
  sput_fail_unless(t2, "hncp_add_tlv failed");

  hncp_remove_tlv(o, t2);
  hncp_run(o);
  sput_fail_unless(o->own_node->update_number == 2, "update number ok");

  hncp_uninit(o);
}

int main(int argc, char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_hncp", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("hncp"); /* optional */
  sput_run_test(hncp_ext);
  sput_run_test(hncp_int);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
