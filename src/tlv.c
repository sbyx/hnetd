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

#include "tlv.h"

static bool
tlv_buffer_grow(struct tlv_buf *buf, int minlen)
{
	int delta = ((minlen / 256) + 1) * 256;
	buf->buflen += delta;
	buf->buf = realloc(buf->buf, buf->buflen);
	if (buf->buf)
		memset(buf->buf + buf->buflen - delta, 0, delta);
	return !!buf->buf;
}

void
tlv_init(struct tlv_attr *attr, int id, unsigned int len)
{
	len &= TLV_ATTR_LEN_MASK;
	len |= (id << TLV_ATTR_ID_SHIFT) & TLV_ATTR_ID_MASK;
	attr->id_len = cpu_to_be32(len);
}

static inline struct tlv_attr *
offset_to_attr(struct tlv_buf *buf, int offset)
{
	void *ptr = (char *)buf->buf + offset - TLV_COOKIE;
	return ptr;
}

static inline int
attr_to_offset(struct tlv_buf *buf, struct tlv_attr *attr)
{
	return (char *)attr - (char *) buf->buf + TLV_COOKIE;
}

void
tlv_buf_grow(struct tlv_buf *buf, int required)
{
	int offset_head = attr_to_offset(buf, buf->head);

	if (!buf->grow || !buf->grow(buf, required))
		return;

	buf->head = offset_to_attr(buf, offset_head);
}

static struct tlv_attr *
tlv_add(struct tlv_buf *buf, struct tlv_attr *pos, int id, int payload)
{
	int offset = attr_to_offset(buf, pos);
	int required = (offset - TLV_COOKIE + sizeof(struct tlv_attr) + payload) - buf->buflen;
	struct tlv_attr *attr;

	if (required > 0) {
		tlv_buf_grow(buf, required);
		attr = offset_to_attr(buf, offset);
	} else {
		attr = pos;
	}

	tlv_init(attr, id, payload + sizeof(struct tlv_attr));
	tlv_fill_pad(attr);
	return attr;
}

int
tlv_buf_init(struct tlv_buf *buf, int id)
{
	if (!buf->grow)
		buf->grow = tlv_buffer_grow;

	buf->head = buf->buf;
	if (tlv_add(buf, buf->buf, id, 0) == NULL)
		return -ENOMEM;

	return 0;
}

void
tlv_buf_free(struct tlv_buf *buf)
{
	free(buf->buf);
	buf->buf = NULL;
	buf->buflen = 0;
}

void
tlv_fill_pad(struct tlv_attr *attr)
{
	char *buf = (char *) attr;
	int len = tlv_pad_len(attr);
	int delta = len - tlv_raw_len(attr);

	if (delta > 0)
		memset(buf + len - delta, 0, delta);
}

void
tlv_set_raw_len(struct tlv_attr *attr, unsigned int len)
{
	int id = tlv_id(attr);
	len &= TLV_ATTR_LEN_MASK;
	len |= (id << TLV_ATTR_ID_SHIFT) & TLV_ATTR_ID_MASK;
	attr->id_len = cpu_to_be32(len);
}

struct tlv_attr *
tlv_new(struct tlv_buf *buf, int id, int payload)
{
	struct tlv_attr *attr;

	attr = tlv_add(buf, tlv_next(buf->head), id, payload);
	if (!attr)
		return NULL;

	tlv_set_raw_len(buf->head, tlv_pad_len(buf->head) + tlv_pad_len(attr));
	return attr;
}

struct tlv_attr *
tlv_put_raw(struct tlv_buf *buf, const void *ptr, int len)
{
	struct tlv_attr *attr;

	if (len < (int)sizeof(struct tlv_attr) || !ptr)
		return NULL;

	attr = tlv_add(buf, tlv_next(buf->head), 0, len - sizeof(struct tlv_attr));
	tlv_set_raw_len(buf->head, tlv_pad_len(buf->head) + len);
	memcpy(attr, ptr, len);
	return attr;
}

struct tlv_attr *
tlv_put(struct tlv_buf *buf, int id, const void *ptr, int len)
{
	struct tlv_attr *attr;

	attr = tlv_new(buf, id, len);
	if (!attr)
		return NULL;

	if (ptr)
		memcpy(tlv_data(attr), ptr, len);
	return attr;
}

void *
tlv_nest_start(struct tlv_buf *buf, int id, int len)
{
	unsigned long offset = attr_to_offset(buf, buf->head);
	buf->head = tlv_new(buf, id, len);
	return (void *) offset;
}

void
tlv_nest_end(struct tlv_buf *buf, void *cookie)
{
	struct tlv_attr *attr = offset_to_attr(buf, (unsigned long) cookie);
	tlv_set_raw_len(attr, tlv_pad_len(attr) + tlv_len(buf->head));
	buf->head = attr;
}

bool
tlv_attr_equal(const struct tlv_attr *a1, const struct tlv_attr *a2)
{
	if (!a1 && !a2)
		return true;

	if (!a1 || !a2)
		return false;

	if (tlv_pad_len(a1) != tlv_pad_len(a2))
		return false;

	return !memcmp(a1, a2, tlv_pad_len(a1));
}

/* Note: This is on-the-wire cmp operation. Therefore, the ids (where
 * endianness matters) may not behave quite as expected on
 * wrong-endian hosts. */
int
tlv_attr_cmp(const struct tlv_attr *a1, const struct tlv_attr *a2)
{
	int r;

	if (!a1 && !a2)
		return 0;
	/* NULL attribute is always 'first', being empty. */
	if (!a1)
		return -1;
	if (!a2)
		return 1;
	r = memcmp(a1, a2, sizeof(*a1));
	if (r)
		return r;
	/* Padding we ignore */
	return memcmp(a1, a2, tlv_raw_len(a1));
}

struct tlv_attr *
tlv_memdup(struct tlv_attr *attr)
{
	struct tlv_attr *ret;
	int size = tlv_pad_len(attr);

	ret = malloc(size);
	if (!ret)
		return NULL;

	memcpy(ret, attr, size);
	return ret;
}

static int
_qsort_tlv_cmp(const void *t1, const void *t2)
{
	const struct tlv_attr **aa1 = (void *)t1, **aa2 = (void *)t2;
	return tlv_attr_cmp(*aa1, *aa2);
}

bool tlv_sort(void *data, int len)
{
	void *tmp = malloc(len), *t = tmp;
	struct tlv_attr *a, **al;
	int c = 0, i;

	if (!tmp)
		return false;
	tlv_for_each_in_buf(a, data, len)
		c++;
	if (c <= 1)
		return true;
	al = alloca(sizeof(struct tlv_attr *) * c);
	if (!al)
		return false;
	c = 0;
	tlv_for_each_in_buf(a, data, len)
		al[c++] = a;
	qsort(al, c, sizeof(al[0]), _qsort_tlv_cmp);
	for (i = 0 ; i < c ; i++) {
		int l = tlv_pad_len(al[i]);
		memcpy(t, al[i], l);
		t += l;
	}
	memcpy(data, tmp, len);
	free(tmp);
	return true;
}
