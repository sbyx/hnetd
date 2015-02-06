/*
 * $Id: test_dncp.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Thu Nov 21 13:26:21 2013 mstenber
 * Last modified: Mon Jan 19 14:52:01 2015 mstenber
 * Edit time:     94 min
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
void dncp_self_flush(dncp_node n);


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

int iface_get_preferred_address(struct in6_addr *foo, bool v4)
{
  return -1;
}

int platform_rpc_register(struct platform_rpc_method *m)
{
	return 0;
}

int platform_rpc_cli(const char *method, struct blob_attr *in)
{
	return 0;
}

/**************************************************************** Test cases */

void hncp_ext(void)
{
  dncp o = hncp_create();
  dncp_node n;
  bool r;
  struct tlv_buf tb;
  struct tlv_attr *t;

  sput_fail_if(!o, "create works");
  n = dncp_get_first_node(o);
  sput_fail_unless(n, "first node exists");

  sput_fail_unless(dncp_node_is_self(n), "self node");

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);

  dncp_self_flush(n);
  sput_fail_unless(dncp_node_get_tlvs(n), "should have tlvs");

  tlv_put(&tb, 123, NULL, 0);

  /* Put the 123 type length = 0 TLV as TLV to hncp. */
  r = dncp_add_tlv(o, 123, NULL, 0, 0);
  sput_fail_unless(r, "dncp_add_tlv ok (should work)");

  dncp_self_flush(n);
  t = dncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs consistent");

  /* Should be able to enable it on a link. */
  r = dncp_if_set_enabled(o, "eth0", true);
  sput_fail_unless(r, "dncp_if_set_enabled eth0");

  r = dncp_if_set_enabled(o, "eth1", true);
  sput_fail_unless(r, "dncp_if_set_enabled eth1");

  r = dncp_if_set_enabled(o, "eth1", true);
  sput_fail_unless(!r, "dncp_if_set_enabled eth1 (2nd true)");

  dncp_self_flush(n);
  t = dncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  r = dncp_if_set_enabled(o, "eth1", false);
  sput_fail_unless(r, "dncp_if_set_enabled eth1 (false)");

  r = dncp_if_set_enabled(o, "eth1", false);
  sput_fail_unless(!r, "dncp_if_set_enabled eth1 (2nd false)");

  dncp_self_flush(n);
  t = dncp_node_get_tlvs(n);
  sput_fail_unless(tlv_attr_equal(t, tb.head), "tlvs should be same");

  /* Make sure run doesn't blow things up */
  dncp_run(o);

  /* Similarly, poll should also be nop (socket should be non-blocking). */
  dncp_poll(o);

  dncp_remove_tlv_matching(o, 123, NULL, 0);

  n = dncp_node_get_next(n);
  sput_fail_unless(!n, "second node should not exist");

  dncp_destroy(o);

  tlv_buf_free(&tb);
}

#include "dncp_i.h"

void hncp_int(void)
{
  /* If we want to do bit more whitebox unit testing of the whole hncp,
   * do it here. */
  dncp_s s;
  dncp o = &s;
  unsigned char hwbuf[] = "foo";
  dncp_node n;
  dncp_link l;

  hncp_init(o, hwbuf, strlen((char *)hwbuf));

  /* Make sure network hash is dirty. */
  sput_fail_unless(o->network_hash_dirty, "network hash should be dirty");

  /* Make sure we can add nodes if we feel like it. */
  dncp_hash_s h;
  dncp_calculate_hash("bar", 3, &h);
  dncp_node_identifier ni = (dncp_node_identifier)&h;

  n = dncp_find_node_by_node_identifier(o, ni, false);
  sput_fail_unless(!n, "dncp_find_node_by_hash w/ create=false => none");
  n = dncp_find_node_by_node_identifier(o, ni, true);
  sput_fail_unless(n, "dncp_find_node_by_hash w/ create=false => !none");
  sput_fail_unless(dncp_find_node_by_node_identifier(o, ni, false), "should exist");
  sput_fail_unless(dncp_find_node_by_node_identifier(o, ni, false) == n, "still same");

  n = dncp_get_first_node(o);
  sput_fail_unless(n, "dncp_get_first_node");
  n = dncp_node_get_next(n);
  sput_fail_unless(!n, "dncp_node_get_next [before prune]");

  /* Play with run; initially should increment update number */
  sput_fail_unless(o->own_node->update_number == 0, "update number ok");
  dncp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  n = dncp_get_first_node(o);
  sput_fail_unless(n, "dncp_get_first_node");
  n = dncp_node_get_next(n);
  sput_fail_unless(!n, "dncp_node_get_next [after prune]");

  /* Similarly, links */
  const char *ifn = "foo";
  l = dncp_find_link_by_name(o, ifn, false);
  sput_fail_unless(!l, "dncp_find_link_by_name w/ create=false => none");
  l = dncp_find_link_by_name(o, ifn, true);
  sput_fail_unless(l, "dncp_find_link_by_name w/ create=false => !none");
  sput_fail_unless(dncp_find_link_by_name(o, ifn, false) == l, "still same");

  /* but on second run, no */
  dncp_run(o);
  sput_fail_unless(o->own_node->update_number == 1, "update number ok");

  dncp_add_tlv(o, 123, NULL, 0, 0);

  /* Added TLV should trigger new update */
  dncp_run(o);
  sput_fail_unless(o->own_node->update_number == 2, "update number ok");

  /* Adding/removing TLV should NOT trigger new update. */
  dncp_tlv t2 = dncp_add_tlv(o, 124, NULL, 0, 0);
  sput_fail_unless(t2, "dncp_add_tlv failed");

  dncp_remove_tlv(o, t2);
  dncp_run(o);
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
