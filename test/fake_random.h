/*
 * Author: Pierre Pfister
 *
 * Fakes random and md5 functions used in various places in hnetd.
 *
 * It was put in a separate file because both test_pa and test_pa_pd use it.
 *
 */

#ifndef FAKE_RANDOM_H_
#define FAKE_RANDOM_H_

#include "sput.h"
#include "smock.h"

/* RANDOM */

#include <stdlib.h>
#define FR_RANDOM_QUEUE "fu_random"
bool fr_mask_random = false;

static long int fr_random() {
	long int res;
	if(fr_mask_random) {
		res = smock_pull_int(FR_RANDOM_QUEUE);
	} else {
		res = random();
	}
	return res;
}

static void fr_random_push(long int i) {
	smock_push_int64(FR_RANDOM_QUEUE, i);
}

#define random fr_random


/* MD5 */

#include <libubox/md5.h>
#define FR_MD5_QUEUE "fu_random"
bool fr_mask_md5 = false;

static void fr_md5begin(md5_ctx_t *ctx)
{
	if(!fr_mask_md5)
		md5_begin(ctx);
}
static void fr_md5hash(const void *data, size_t length, md5_ctx_t *ctx)
{
	if(!fr_mask_md5)
		md5_hash(data, length, ctx);
}

static void fr_md5end(void *resbuf, md5_ctx_t *ctx)
{
	void *buff;
	if(!fr_mask_md5) {
		md5_end(resbuf, ctx);
		return;
	}

	buff = smock_pull(FR_MD5_QUEUE);
	memcpy(resbuf, buff, 16);
	free(buff);
}

static void fr_md5_push(const void *buff)
{
	void *b = malloc(16);
	sput_fail_unless(b, "Can't allocate md5 result");
	if(!b)
		return;

	memcpy(b, buff, 16);
	smock_push(FR_MD5_QUEUE, b);
}

#define fr_md5_push_prefix(p) fr_md5_push((void *) &(p)->prefix)

#define md5_begin fr_md5begin
#define md5_hash fr_md5hash
#define md5_end fr_md5end

#endif /* FAKE_RANDOM_H_ */
