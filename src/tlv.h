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

enum {
	TLV_ATTR_UNSPEC,
	TLV_ATTR_NESTED,
	TLV_ATTR_BINARY,
	TLV_ATTR_STRING,
	TLV_ATTR_INT8,
	TLV_ATTR_INT16,
	TLV_ATTR_INT32,
	TLV_ATTR_INT64,
	TLV_ATTR_LAST
};

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

static inline uint8_t
tlv_get_u8(const struct tlv_attr *attr)
{
	return *((uint8_t *) attr->data);
}

static inline uint16_t
tlv_get_u16(const struct tlv_attr *attr)
{
	uint16_t *tmp = (uint16_t*)attr->data;
	return be16_to_cpu(*tmp);
}

static inline uint32_t
tlv_get_u32(const struct tlv_attr *attr)
{
	uint32_t *tmp = (uint32_t*)attr->data;
	return be32_to_cpu(*tmp);
}

static inline uint64_t
tlv_get_u64(const struct tlv_attr *attr)
{
	uint32_t *ptr = tlv_data(attr);
	uint64_t tmp = ((uint64_t) be32_to_cpu(ptr[0])) << 32;
	tmp |= be32_to_cpu(ptr[1]);
	return tmp;
}

static inline int8_t
tlv_get_int8(const struct tlv_attr *attr)
{
	return tlv_get_u8(attr);
}

static inline int16_t
tlv_get_int16(const struct tlv_attr *attr)
{
	return tlv_get_u16(attr);
}

static inline int32_t
tlv_get_int32(const struct tlv_attr *attr)
{
	return tlv_get_u32(attr);
}

static inline int64_t
tlv_get_int64(const struct tlv_attr *attr)
{
	return tlv_get_u64(attr);
}

static inline const char *
tlv_get_string(const struct tlv_attr *attr)
{
	return attr->data;
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
extern int tlv_buf_init(struct tlv_buf *buf, int id);
extern void tlv_buf_free(struct tlv_buf *buf);
extern void tlv_buf_grow(struct tlv_buf *buf, int required);
extern struct tlv_attr *tlv_new(struct tlv_buf *buf, int id, int payload);
extern void *tlv_nest_start(struct tlv_buf *buf, int id);
extern void tlv_nest_end(struct tlv_buf *buf, void *cookie);
extern struct tlv_attr *tlv_put(struct tlv_buf *buf, int id, const void *ptr, int len);
extern bool tlv_check_type(const void *ptr, int len, int type);
extern int tlv_parse(struct tlv_attr *attr, struct tlv_attr **data, const struct tlv_attr_info *info, int max);
extern struct tlv_attr *tlv_memdup(struct tlv_attr *attr);
extern struct tlv_attr *tlv_put_raw(struct tlv_buf *buf, const void *ptr, int len);

static inline struct tlv_attr *
tlv_put_string(struct tlv_buf *buf, int id, const char *str)
{
	return tlv_put(buf, id, str, strlen(str) + 1);
}

static inline struct tlv_attr *
tlv_put_u8(struct tlv_buf *buf, int id, uint8_t val)
{
	return tlv_put(buf, id, &val, sizeof(val));
}

static inline struct tlv_attr *
tlv_put_u16(struct tlv_buf *buf, int id, uint16_t val)
{
	val = cpu_to_be16(val);
	return tlv_put(buf, id, &val, sizeof(val));
}

static inline struct tlv_attr *
tlv_put_u32(struct tlv_buf *buf, int id, uint32_t val)
{
	val = cpu_to_be32(val);
	return tlv_put(buf, id, &val, sizeof(val));
}

static inline struct tlv_attr *
tlv_put_u64(struct tlv_buf *buf, int id, uint64_t val)
{
	val = cpu_to_be64(val);
	return tlv_put(buf, id, &val, sizeof(val));
}

#define tlv_put_int8	tlv_put_u8
#define tlv_put_int16	tlv_put_u16
#define tlv_put_int32	tlv_put_u32
#define tlv_put_int64	tlv_put_u64

#define __tlv_for_each_attr(pos, attr, rem) \
	for (pos = (void *) attr; \
	     rem > 0 && (tlv_pad_len(pos) <= rem) && \
	     (tlv_pad_len(pos) >= sizeof(struct tlv_attr)); \
	     rem -= tlv_pad_len(pos), pos = tlv_next(pos))


#define tlv_for_each_attr(pos, attr, rem) \
	for (rem = attr ? tlv_len(attr) : 0, \
	     pos = attr ? tlv_data(attr) : 0; \
	     rem > 0 && (tlv_pad_len(pos) <= rem) && \
	     (tlv_pad_len(pos) >= sizeof(struct tlv_attr)); \
	     rem -= tlv_pad_len(pos), pos = tlv_next(pos))


#endif
