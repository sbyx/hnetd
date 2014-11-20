/*
 * $Id: hncp_trust.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Nov 19 17:34:25 2014 mstenber
 * Last modified: Thu Nov 20 14:59:19 2014 mstenber
 * Edit time:     154 min
 *
 */

/*
 * This module is responsible for maintaining local HNCP trust
 * relationship towards (hashes of) particular certificates.
 *
 * Notably,  it provides functionality to
 *
 * - handle DTLS certificate callback which asks for verdict (which
 * implicitly also forwards query onward if not already present),
 *
 * - set verdict for particular hash (user configuration),
 *
 * and behind the scenes it also handles offline caching of the trust
 * (in a flat file).
 *
 * Trust itself is of 3 different degrees:
 *
 * - neutral (unknown)
 *
 * - cached (from flat file; at some point someone else was configured
 *   to trust it)
 *
 * - configured (someone currently present is configured to trust it,
 *   or locally configured to trust)
 *
 * The authorization derived from trust can be negative or
 * positive. Negative has higher precedence than positive, so in
 * presence of both negative and positive verdict of same degree,
 * negative wins.
 *
 * TBD: think if using temporary files actually is worth here (and in
 * pa_store) or not. This write is not atomic, nor does it handle
 * errors gracefully..
 *
 * TBD: add cap to # of neutral verdicts we publish
 *
 * TBD: unit tests
 *
 * TBD: hnetd.c argument to enable this + some command-line way to
 * manipulate configured trust
 */

#include "hncp_trust.h"
#include "hncp_i.h"

#include <libubox/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

/* in milliseconds, how long we have to be quiet before save */
#define SAVE_INTERVAL 1000

/* version schema; if content of hncp_trust_stored_s
 * (=hncp_t_trust_verdict_s + cname) changes, change this.
 */
#define SAVE_VERSION 1

struct hncp_trust_struct {
  hncp hncp;

  /* Store filename */
  char *filename;

  /* # of iterations the trust TLVs have changed - used for checking
   * if verdicts are still valid. */
  int generation;

  /* Hash of the content already persisted. We guarantee not to
   * rewrite unless something _does_ change.*/
  hncp_hash_s file_hash;

  /* Verdict store (both cached and configured ones) */
  struct vlist_tree tree;

  /* Change notification subscription for the hncp_trust module */
  hncp_subscriber_s subscriber;

  /* Timeout to write changes to disk. */
  struct uloop_timeout timeout;
} ;

typedef struct __packed {
  hncp_t_trust_verdict_s tlv;
  char cname[64];
} hncp_trust_stored_s, *hncp_trust_stored;

typedef struct __packed {
  struct vlist_node in_tree;

  hncp_trust_stored_s stored;

  /* What is the verdict we have from HNCP cloud */
  hncp_trust_verdict remote_verdict;
  hncp_node remote_node;
  int verdict_generation;

  /* Associated locally published HNCP TLV, if any */
  struct tlv_attr *a;

  /* When was the TLV published */
  hnetd_time_t a_time;
} hncp_trust_node_s, *hncp_trust_node;

static void _trust_calculate_hash(hncp_trust t, hncp_hash h)
{
  md5_ctx_t ctx;
  hncp_trust_node tn;

  md5_begin(&ctx);
  vlist_for_each_element(&t->tree, tn, in_tree)
    {
      if (tn->stored.tlv.verdict == HNCP_VERDICT_NEUTRAL)
        continue;
      md5_hash(&tn->stored, sizeof(tn->stored), &ctx);
    }
  md5_end(h, &ctx);
}

static void _trust_load(hncp_trust t)
{
  if (!t->filename)
    return;
  FILE *f = fopen(t->filename, "rb");
  if (!f)
    {
      L_ERR("trust load failed to open %s", t->filename);
      return;
    }
  char buf[sizeof(hncp_trust_stored_s)];
  int r;

  r = fread(buf, 1, 1, f);
  if (r != 1)
    {
      L_ERR("trust load - immediate eof");
      goto done;
    }
  if (buf[0] != SAVE_VERSION)
    {
      L_INFO("wrong version # -> skipping");
      goto done;
    }
  while ((r = fread(buf, sizeof(buf), 1, f)))
    {
      if (r != sizeof(buf))
        {
          L_ERR("trust load - partial read of record");
          break;
        }
      hncp_trust_node tn = calloc(1, sizeof(*tn));
      if (!tn)
        {
          L_ERR("trust load - eom");
          break;
        }
      memcpy(&tn->stored, buf, sizeof(buf));
      vlist_add(&t->tree, &tn->in_tree, tn);
    }
 done:
  fclose(f);
}

static void _trust_save(hncp_trust t)
{
  if (!t->filename)
    {
      L_DEBUG("trust save skipped, no filename");
      return;
    }
  hncp_hash_s oh = t->file_hash;
  _trust_calculate_hash(t, &t->file_hash);
  if (memcmp(&oh, &t->file_hash, sizeof(oh)) == 0)
    {
      L_DEBUG("trust save skipped, hash identical");
      return;
    }
  FILE *f = fopen(t->filename, "wb");
  if (!f)
    {
      L_ERR("trust save - error opening %s", t->filename);
      return;
    }
  hncp_trust_node tn;
  char version = SAVE_VERSION;
  if (fwrite(&version, 1, 1, f) != 1)
    {
      L_ERR("trust save - error writing version");
      goto done;
    }
  vlist_for_each_element(&t->tree, tn, in_tree)
    {
      if (tn->stored.tlv.verdict == HNCP_VERDICT_NEUTRAL)
        continue;
      if (fwrite(&tn->stored, sizeof(tn->stored), 1, f) != sizeof(tn->stored))
        {
          L_ERR("trust save - error writing block");
          goto done;
        }
    }
 done:
  fclose(f);
}

static void _trust_write_cb(struct uloop_timeout *to)
{
  hncp_trust t = container_of(to, hncp_trust_s, timeout);
  _trust_save(t);
}

static int
_compare_trust_node(const void *a, const void *b, void *ptr __unused)
{
  hncp_trust_node n1 = (hncp_trust_node) a;
  hncp_trust_node n2 = (hncp_trust_node) b;

  return memcmp(&n1->stored.tlv.sha256_hash,
                &n2->stored.tlv.sha256_hash,
                sizeof(n2->stored.tlv.sha256_hash));
}

static int _trust_node_remote_verdict(hncp_trust t, hncp_trust_node n)
{
  if (t->generation == n->verdict_generation)
    return n->remote_verdict;

  int remote_verdict = -1;
  hncp_node remote_node = NULL;
  hncp_node node;
  struct tlv_attr *a;
  hncp_t_trust_verdict tv;
  hncp o = t->hncp;

  hncp_for_each_node(o, node)
    if (node != o->own_node)
      hncp_node_for_each_tlv_with_type(node, a, HNCP_T_TRUST_VERDICT)
        if ((tv = hncp_tlv_trust_verdict(a)))
          {
            if (memcmp(&tv->sha256_hash, &n->stored.tlv.sha256_hash,
                       sizeof(n->stored.tlv.sha256_hash)) == 0)
              {
                if (tv->verdict > remote_verdict)
                  {
                    remote_verdict = tv->verdict;
                    remote_node = node;
                  }
              }
          }
  n->remote_verdict = remote_verdict;
  n->remote_node = remote_node;
  n->verdict_generation = t->generation;
  return n->remote_verdict;
}

static int _trust_node_verdict(hncp_trust t, hncp_trust_node tn)
{
  int verdict = _trust_node_remote_verdict(t, tn);
  int verdict2 = tn->stored.tlv.verdict;
  return verdict > verdict2 ? verdict : verdict2;
}

static hncp_trust_node _trust_node_find(hncp_trust t,
                                        hncp_sha256 hash)
{
  hncp_trust_node cn = container_of(hash,
                                    hncp_trust_node_s,
                                    stored.tlv.sha256_hash);
  return vlist_find(&t->tree, cn, cn, in_tree);
}

static int _hash_verdict(hncp_trust t, hncp_sha256 h)
{
  hncp_trust_node tn = _trust_node_find(t, h);
  return tn ? _trust_node_verdict(t, tn) : HNCP_VERDICT_NONE;
}

static void _trust_publish_maybe(hncp_trust t, hncp_trust_node n)
{
  int len = sizeof(n->stored.tlv) + strlen(n->stored.cname) + 1;
  int remote_verdict = _trust_node_remote_verdict(t, n);

  if (n->a)
    {
      hncp_remove_tlv(t->hncp, n->a);
      n->a = NULL;
    }
  /*
   * Either our idea is _better_, or it is _same_ and our router id is
   * higher.
   */
  if (remote_verdict > n->stored.tlv.verdict
      || (remote_verdict == n->stored.tlv.verdict
          && (hncp_node_cmp(n->remote_node, t->hncp->own_node) > 0)))
    {
      n->a = hncp_add_tlv_raw(t->hncp, HNCP_T_TRUST_VERDICT, &n->stored, len);
      n->a_time = hnetd_time();
    }
}

static void _update_trust_node(struct vlist_tree *tr,
                               struct vlist_node *node_new,
                               struct vlist_node *node_old)
{
  hncp_trust t = container_of(tr, hncp_trust_s, tree);
  hncp_trust_node t_old = container_of(node_old, hncp_trust_node_s, in_tree);
  hncp_trust_node t_new = container_of(node_new, hncp_trust_node_s, in_tree);

  if (t_old)
    {
      if (t_old->a)
        {
          hncp_remove_tlv(t->hncp, t_old->a);
          t_old->a = NULL;
        }
      if (t_old != t_new)
        free(t_old);
    }
  if (t_new)
    _trust_publish_maybe(t, t_new);
  uloop_timeout_set(&t->timeout, SAVE_INTERVAL);
}

static int _remote_to_local_verdict(int v)
{
  switch (v)
    {
    case HNCP_VERDICT_CACHED_POSITIVE: /* TBD - valid? */
    case HNCP_VERDICT_CONFIGURED_POSITIVE:
      return HNCP_VERDICT_CACHED_POSITIVE;
    case HNCP_VERDICT_CACHED_NEGATIVE: /* TBD - valid? */
    case HNCP_VERDICT_CONFIGURED_NEGATIVE:
      return HNCP_VERDICT_CACHED_NEGATIVE;
    default:
      return HNCP_VERDICT_NONE;
    }
}

static void _tlv_cb(hncp_subscriber s,
                    hncp_node n, struct tlv_attr *tlv, bool add __unused)
{
  hncp_trust t = container_of(s, hncp_trust_s, subscriber);
  hncp_t_trust_verdict tv = hncp_tlv_trust_verdict(tlv);

  /* We are only interested about trust verdicts */
  if (!tv)
    return;
  /* Local changes are not interesting */
  if (n == t->hncp->own_node)
    return;
  /* Remote change can cause two different things:
   * - withdrawing of local publishing (add, higher priority)
   * - local publishing (remove, we have higher priority)
   */
  hncp_trust_node tn = _trust_node_find(t, &tv->sha256_hash);
  int local_verdict = _remote_to_local_verdict(tv->verdict);
  if (!tn)
    {
      if (local_verdict == HNCP_VERDICT_NONE)
        return;
      hncp_trust_set(t,
                     &tv->sha256_hash,
                     local_verdict,
                     &tv->cname[0]);
    }
  else if (tn->stored.tlv.verdict < local_verdict)
    {
      hncp_trust_set(t,
                     &tn->stored.tlv.sha256_hash,
                     local_verdict,
                     tn->stored.cname);
    }
  t->generation++;
}

void hncp_trust_set(hncp_trust t, const hncp_sha256 h,
                    uint8_t verdict, const char *cname)
{
  hncp_trust_node tn = _trust_node_find(t, h);

  if (tn)
    {
      if (tn->stored.tlv.verdict == verdict
          && (cname == tn->stored.cname
              || strcmp(tn->stored.cname, cname) == 0))
        return;
      tn->stored.tlv.verdict = verdict;
      if (cname != tn->stored.cname)
        strcpy(tn->stored.cname, cname);
      uloop_timeout_set(&t->timeout, SAVE_INTERVAL);
      _trust_publish_maybe(t, tn);
      return;
    }
  tn = calloc(1, sizeof(*tn));
  if (!tn)
    {
      L_ERR("oom when creating new trust node");
      return;
    }
  tn->stored.tlv.sha256_hash = *h;
  tn->stored.tlv.verdict = verdict;
  strcpy(tn->stored.cname, cname);
  vlist_add(&t->tree, &tn->in_tree, tn);
}

static bool _dtls_unknown_callback(dtls d __unused,
                                   dtls_cert cert, void *context)
{
  hncp_trust t = context;
  unsigned char buf[2048];
  int r = dtls_cert_to_der_buf(cert, buf, sizeof(buf));

  if (r <= 0 || r >= (int)sizeof(buf))
    {
      L_ERR("too huge DER output?!?");
      return false;
    }
  hncp_sha256_s h;

  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, buf, r);
  SHA256_Final(h.buf, &ctx);

  int verdict = _hash_verdict(t, &h);
  if (verdict >= 0)
    return verdict == HNCP_VERDICT_CACHED_POSITIVE ||
      verdict == HNCP_VERDICT_CONFIGURED_POSITIVE;
  char cbuf[HNCP_T_TRUST_VERDICT_CNAME_LEN];
  X509_NAME_oneline(X509_get_subject_name(cert),
                    cbuf,
                    sizeof(cbuf));
  hncp_trust_set(t, &h, HNCP_VERDICT_NEUTRAL, cbuf);
  return false;
}

hncp_trust hncp_trust_create(hncp o, const char *filename)
{
  hncp_trust t = calloc(1, sizeof(*t));

  if (!t)
    return NULL;
  t->hncp = o;
  vlist_init(&t->tree, _compare_trust_node, _update_trust_node);
  t->tree.keep_old = true;
  t->timeout.cb = _trust_write_cb;
  t->generation = 0;
  t->subscriber.tlv_change_callback = _tlv_cb;
  if (filename)
    t->filename = strdup(filename);
  _trust_load(t);
  _trust_calculate_hash(t, &t->file_hash);
  hncp_subscribe(o, &t->subscriber);
  if (o->d)
    dtls_set_unknown_cert_callback(o->d, _dtls_unknown_callback, t);
  return t;
}

void hncp_trust_destroy(hncp_trust t)
{
  hncp o = t->hncp;

  if (o->d)
    dtls_set_unknown_cert_callback(o->d, NULL, NULL);
  _trust_save(t);
  hncp_unsubscribe(o, &t->subscriber);
  vlist_flush_all(&t->tree);
  uloop_timeout_cancel(&t->timeout);
  if (t->filename)
    free(t->filename);
  free(t);
}
