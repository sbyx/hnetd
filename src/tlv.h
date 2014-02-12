/*
 * tlv - library for generating/parsing tagged binary data
 *
 * Copyright (C) 2010 Felix Fietkau <nbd@openwrt.org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _TLV_H__
#define _TLV_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <libubox/utils.h>

#define TLV_COOKIE		0x01234567
#define TLV_ATTR_ID_MASK  0xffff0000
#define TLV_ATTR_ID_SHIFT 16
#define TLV_ATTR_LEN_MASK 0x0000ffff
#define TLV_ATTR_ALIGN    4

struct tlv_attr {
	uint32_t id_len;
	char data[];
} __packed;

struct tlv_attr_info {
	unsigned int type;
	unsigned int minlen;
	unsigned int maxlen;
	bool (*validate)(const struct tlv_attr_info *, struct tlv_attr *);
};

struct tlv_buf {
	struct tlv_attr *head;
	bool (*grow)(struct tlv_buf *buf, int minlen);
	int buflen;
	void *buf;
};

/*
 * tlv_data: returns the data pointer for an attribute
 */
static inline void *
tlv_data(const struct tlv_attr *attr)
{
	return (void *) attr->data;
}

/*
 * tlv_id: returns the id of an attribute
 */
static inline unsigned int
tlv_id(const struct tlv_attr *attr)
{
	int id = (be32_to_cpu(attr->id_len) & TLV_ATTR_ID_MASK) >> TLV_ATTR_ID_SHIFT;
	return id;
}

/*
 * tlv_len: returns the length of the attribute's payload
 */
static inline unsigned int
tlv_len(const struct tlv_attr *attr)
{
	return (be32_to_cpu(attr->id_len) & TLV_ATTR_LEN_MASK) - sizeof(struct tlv_attr);
}

/*
 * tlv_raw_len: returns the complete length of an attribute (including the header)
 */
static inline unsigned int
tlv_raw_len(const struct tlv_attr *attr)
{
	return tlv_len(attr) + sizeof(struct tlv_attr);
}

/*
 * tlv_pad_len: returns the padded length of an attribute (including the header)
 */
static inline unsigned int
tlv_pad_len(const struct tlv_attr *attr)
{
	int len = tlv_raw_len(attr);
	len = (len + TLV_ATTR_ALIGN - 1) & ~(TLV_ATTR_ALIGN - 1);
	return len;
}

static inline struct tlv_attr *
tlv_next(const struct tlv_attr *attr)
{
	return (struct tlv_attr *) ((char *) attr + tlv_pad_len(attr));
}

extern void tlv_init(struct tlv_attr *attr, int id, unsigned int len);
extern void tlv_fill_pad(struct tlv_attr *attr);
extern void tlv_set_raw_len(struct tlv_attr *attr, unsigned int len);
extern bool tlv_attr_equal(const struct tlv_attr *a1, const struct tlv_attr *a2);
extern int tlv_attr_cmp(const struct tlv_attr *a1, const struct tlv_attr *a2);
extern int tlv_buf_init(struct tlv_buf *buf, int id);
extern void tlv_buf_free(struct tlv_buf *buf);
extern void tlv_buf_grow(struct tlv_buf *buf, int required);
extern struct tlv_attr *tlv_new(struct tlv_buf *buf, int id, int payload);
extern void *tlv_nest_start(struct tlv_buf *buf, int id, int len);
extern void tlv_nest_end(struct tlv_buf *buf, void *cookie);
extern struct tlv_attr *tlv_put(struct tlv_buf *buf, int id, const void *ptr, int len);
extern struct tlv_attr *tlv_memdup(struct tlv_attr *attr);
extern struct tlv_attr *tlv_put_raw(struct tlv_buf *buf, const void *ptr, int len);
extern bool tlv_sort(void *buf, int len);

/* Paranoid version: Have faith only in the caller providing correct
 * buf + len; pos is used to maintain the current position within buf. */
#define tlv_for_each_in_buf(pos, buf, len)                              \
  for (pos = (void *)(buf);                                             \
       (void *)pos + sizeof(struct tlv_attr) <= (void *)(buf) + (len)   \
         && tlv_raw_len(pos) >= sizeof(struct tlv_attr)                 \
         && (void *)pos + tlv_raw_len(pos) <= (void *)(buf) + (len);    \
       pos = tlv_next(pos))

/* Assume the root 'attr' is trusted. The rest may contain garbage and
 * we should still not blow up. */
#define tlv_for_each_attr(pos, attr) \
  tlv_for_each_in_buf(pos, tlv_data(attr), (attr) ? tlv_len(attr) : 0)

static inline const char *hex_repr(char *buf, const void *data, int len)
{
  char *r = buf;

  if (!len)
    {
      *r = 0;
      return r;
    }
  while (len--)
    {
      sprintf(buf, "%02X", (int) *((unsigned char *)data));
      buf += 2;
      data++;
    }
  return r;
}

#define HEX_REPR(buf, len) hex_repr(alloca((len) * 2 + 1), buf, len)

static inline const char *
tlv_repr(struct tlv_attr *a, char *buf, int buf_len)
{
  snprintf(buf, buf_len, "<TLV id=%d,len=%d: %s>",
           tlv_id(a), tlv_len(a),
           HEX_REPR(tlv_data(a), tlv_len(a)));
  return buf;
}

#define TLV_REPR_LEN(a) (32 + 2 * tlv_len(a))
#define TLV_REPR(a) tlv_repr(a, alloca(TLV_REPR_LEN(a)), TLV_REPR_LEN(a))

#endif
