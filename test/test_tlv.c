/*
 * $Id: test_tlv.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2013 cisco Systems, Inc.
 *
 * Created:       Wed Dec  4 11:53:11 2013 mstenber
 * Last modified: Wed Feb 12 22:10:50 2014 mstenber
 * Edit time:     44 min
 *
 */

#include "hnetd.h"
#include "tlv.h"
#include "sput.h"

/* Ensure that tlv stuff we add works. Note that some of the failures
 * are obvious only on valgrind (e.g. wrong accesses in tlv_iter). */

/************************************************************* Test cases */ 


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

#define MAX_TLVS 10

#define TLV_NEXT()                                                      \
do {                                                                    \
  if (a)                                                                \
    ptr += tlv_pad_len(a);                                              \
  sput_fail_unless(first_free < MAX_TLVS, "enough space for tlvs");     \
  a = tlvs[first_free++] = ptr;                                         \
 } while(0)

void tlv_cmp(void)
{
  /* Raw memory blob in which we have our fake TLVs. */
  unsigned char buf[1000];
  void *ptr = buf;
  struct tlv_attr *tlvs[MAX_TLVS], *a = NULL;
  int i, j, first_free = 0;

  memset(buf, 0, sizeof(buf));

  /* We _know_ the order. So we insert things here in the order which
   * the tlv_attr_cmp should sort them. */

  /* TLV w/o content - before one with */
  TLV_NEXT();
  tlv_init(a, 24, 4);

  /* TLV with _one_ content > 0s */
  TLV_NEXT();
  tlv_init(a, 24, 5);
  *((char *)tlv_data(a)) = 'x';

  /* TLV with content of 0s */
  TLV_NEXT();
  tlv_init(a, 24, 8);

  /* TLV with content > 0s */
  TLV_NEXT();
  tlv_init(a, 24, 8);
  *((char *)tlv_data(a)) = 'x';

  /* ID with greater ID */
  TLV_NEXT();
  tlv_init(a, 25, 4);

  /* ID with 16 bit ID */
  TLV_NEXT();
  tlv_init(a, 0x4242, 4);

  for (i = 0 ; i < first_free ; i++)
    for (j = 0 ; j < first_free ; j++)
      {
        int r = tlv_attr_cmp(tlvs[i], tlvs[j]);
        bool eq = tlv_attr_equal(tlvs[i], tlvs[j]);

        L_NOTICE("comparing %s, %s",
                 TLV_REPR(tlvs[i]), TLV_REPR(tlvs[j]));
        sput_fail_unless(!eq == !(i == j),
                         "tlv_attr_equal on board");
        if (i == j)
          sput_fail_unless(r == 0, "not matching own");
        else if (i < j)
          sput_fail_unless(r < 0, "lesser");
        else
          sput_fail_unless(r > 0, "greater");
      }
}

void tlv_nest()
{
  struct tlv_buf tb;
  void *cookie;
  int c, d;
  struct tlv_attr *a, *a2;
  unsigned int rem;
  int cs = 0;
  int ds = 0;

  memset(&tb, 0, sizeof(tb));
  /* Produce test data - one 'container' TLV, with fixed
   * TLV_ATTR_ALIGN sized header, and then two sub-TLVs. */
  tlv_buf_init(&tb, 0);
  cookie = tlv_nest_start(&tb, 33, TLV_ATTR_ALIGN * 2);
  memset(tlv_data(tb.head), 42, TLV_ATTR_ALIGN * 2);
  tlv_new(&tb, 34, 0);
  a = tlv_new(&tb, 35, 1);
  *((unsigned char*)tlv_data(a)) = 0x42;
  tlv_nest_end(&tb, cookie);
  cookie = tlv_nest_start(&tb, 36, TLV_ATTR_ALIGN);
  memset(tlv_data(tb.head), 66, TLV_ATTR_ALIGN);
  tlv_new(&tb, 37, 0);
  tlv_nest_end(&tb, cookie);

  /* Make sure what we produced looks sane. */
  c = 0;
  tlv_for_each_attr(a, tb.head, rem)
    c++;
  L_DEBUG("# of root attrs:%d", c);
  sput_fail_unless(c == 2, "should be just 2 root attr");

  c = 0;
  d = 0;
  tlv_for_each_attr(a, tb.head, rem)
    {
      cs += tlv_id(a);
      void *base = tlv_data(a);
      base += (2 - c) * TLV_ATTR_ALIGN;
      void *end = tlv_data(a) + tlv_len(a);
      c++;
      tlv_for_each_in_buf(a2, base, end-base)
        {
          ds += tlv_id(a2);
          d++;
        }
    }
  sput_fail_unless(cs == 33 + 36, "cs correct");
  sput_fail_unless(ds == 34 + 35 + 37, "ds correct");
  sput_fail_unless(d == 3, "should be 3 nested attrs");

  L_DEBUG("nested tlv:%s", TLV_REPR(tb.head));
  sput_fail_unless(tlv_len(tb.head) ==
                   4 * TLV_ATTR_ALIGN +
                   5 * sizeof(struct tlv_attr) , "right nested whole size");

}


void test_tlv_sort()
{
  struct tlv_buf tb;
  struct tlv_attr *a;
  unsigned int rem;

  memset(&tb, 0, sizeof(tb));
  tlv_buf_init(&tb, 0);
  tlv_new(&tb, 2, 0);
  tlv_new(&tb, 3, 0);
  tlv_new(&tb, 1, 0);
  tlv_new(&tb, 42, 0);

  /* Sort the TLVs */
  tlv_sort(tlv_data(tb.head), tlv_len(tb.head));

  /* Make sure they come out in ascending order. */
  int last = -1;
  int c = 0;
  tlv_for_each_attr(a, tb.head, rem)
    {
      int nid = tlv_id(a);
      L_DEBUG("last:%d id:%d", last, nid);
      sput_fail_unless(last < nid, "last < id");
      last = nid;
      c++;
    }
  sput_fail_unless(c == 4, "should be 4 attrs");
}

int main(__unused int argc, __unused char **argv)
{
  setbuf(stdout, NULL); /* so that it's in sync with stderr when redirected */
  openlog("test_tlv", LOG_CONS | LOG_PERROR, LOG_DAEMON);
  sput_start_testing();
  sput_enter_suite("tlv"); /* optional */
  sput_run_test(tlv_iter);
  sput_run_test(tlv_cmp);
  sput_run_test(tlv_nest);
  sput_run_test(test_tlv_sort);
  sput_leave_suite(); /* optional */
  sput_finish_testing();
  return sput_get_return_value();
}
