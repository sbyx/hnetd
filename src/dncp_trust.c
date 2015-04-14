/*
 * $Id: dncp_trust.c $
 *
 * Author: Markus Stenberg <mstenber@cisco.com>
 *
 * Copyright (c) 2014 cisco Systems, Inc.
 *
 * Created:       Wed Nov 19 17:34:25 2014 mstenber
 * Last modified: Tue Feb  3 19:58:06 2015 mstenber
 * Edit time:     235 min
 *
 */

/*
 * This module is responsible for maintaining local DNCP trust
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
 * TBD: hnetd.c argument to enable this + some command-line way to
 * manipulate configured trust
 *
 * TBD: make CA hierarchy work too; now this deals with just
 * (self-signed/user) certs
 *
 * TBD: make sure 'neutral' remotely received state is purged
 * eventually.
 */

#include "dncp_trust.h"
#include "dncp_i.h"

#include <libubox/md5.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

/* in milliseconds, how long we have to be quiet before save */
#define SAVE_INTERVAL 1000

/* maximum # of neutral verdicts */
#define NEUTRAL_MAXIMUM 10

/* version schema; if content of dncp_trust_stored_s
 * (=dncp_t_trust_verdict_s + cname) changes, change this.
 */
#define SAVE_VERSION 1

struct dncp_trust_struct {
  dncp dncp;

  /* Store filename */
  char *filename;

  /* Hash of the content already persisted. We guarantee not to
   * rewrite unless something _does_ change.*/
  dncp_hash_s file_hash;

  /* Verdict store (both cached and configured ones) */
  struct vlist_tree tree;

  /* Change notification subscription for the dncp_trust module */
  dncp_subscriber_s subscriber;

  /* Timeout to write changes to disk. */
  struct uloop_timeout timeout;

  /* Number of neutral verdicts we have published. */
  int num_neutral;

  /* Until what point in time default verdict is configured-positive. */
  hnetd_time_t trust_until;

  /* RPC methods */
  struct platform_rpc_method rpc_trust_list;
  struct platform_rpc_method rpc_trust_set;
  struct platform_rpc_method rpc_trust_set_timer;
};

typedef struct __packed {
  dncp_t_trust_verdict_s tlv;
  char cname[64];
} dncp_trust_stored_s, *dncp_trust_stored;

typedef struct __packed {
  struct vlist_node in_tree;

  dncp_trust_stored_s stored;

} dncp_trust_node_s, *dncp_trust_node;

typedef struct {
  /* When was the TLV published */
  hnetd_time_t tlv_time;
} dncp_local_tlv_extra_s, *dncp_local_tlv_extra;

static void _trust_publish_maybe(dncp_trust t, dncp_trust_node n);

static void _trust_calculate_hash(dncp_trust t, dncp_hash h)
{
  md5_ctx_t ctx;
  dncp_trust_node tn;

  md5_begin(&ctx);
  vlist_for_each_element(&t->tree, tn, in_tree)
    {
      if (tn->stored.tlv.verdict == DNCP_VERDICT_NEUTRAL)
        continue;
      md5_hash(&tn->stored, sizeof(tn->stored), &ctx);
    }
  dncp_md5_end(h, &ctx);
}

static void _trust_load(dncp_trust t)
{
  if (!t->filename)
    return;
  FILE *f = fopen(t->filename, "rb");
  if (!f)
    {
      L_ERR("trust load failed to open %s", t->filename);
      return;
    }
  char buf[sizeof(dncp_trust_stored_s)];
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
  while ((r = fread(buf, 1, sizeof(buf), f)))
    {
      if (r != sizeof(buf))
        {
          L_ERR("trust load - partial read of record");
          break;
        }
      dncp_trust_node tn = calloc(1, sizeof(*tn));
      if (!tn)
        {
          L_ERR("trust load - eom");
          break;
        }
      memcpy(&tn->stored, buf, sizeof(buf));
      vlist_add(&t->tree, &tn->in_tree, tn);
      _trust_publish_maybe(t, tn);
    }
 done:
  fclose(f);
}

static void _trust_save(dncp_trust t)
{
  if (!t->filename)
    {
      L_DEBUG("trust save skipped, no filename");
      return;
    }
  dncp_hash_s oh = t->file_hash;
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
  dncp_trust_node tn;
  char version = SAVE_VERSION;
  if (fwrite(&version, 1, 1, f) != 1)
    {
      L_ERR("trust save - error writing version");
      goto done;
    }
  vlist_for_each_element(&t->tree, tn, in_tree)
    {
      if (tn->stored.tlv.verdict == DNCP_VERDICT_NEUTRAL)
        continue;
      if (fwrite(&tn->stored, 1, sizeof(tn->stored), f) != sizeof(tn->stored))
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
  dncp_trust t = container_of(to, dncp_trust_s, timeout);
  _trust_save(t);
}

static int
_compare_trust_node(const void *a, const void *b, void *ptr __unused)
{
  dncp_trust_node n1 = (dncp_trust_node) a;
  dncp_trust_node n2 = (dncp_trust_node) b;

  return memcmp(&n1->stored.tlv.sha256_hash,
                &n2->stored.tlv.sha256_hash,
                sizeof(n2->stored.tlv.sha256_hash));
}

static int _trust_get_remote_verdict(dncp_trust t, dncp_sha256 h,
                                     dncp_node *remote_node_return,
                                     char *cname)
{
  int remote_verdict = DNCP_VERDICT_NONE;
  dncp_node remote_node = NULL;
  dncp_node node;
  struct tlv_attr *a;
  dncp_t_trust_verdict tv;
  dncp o = t->dncp;

  if (cname)
    *cname = 0;
  dncp_for_each_node(o, node)
    if (node != o->own_node)
      dncp_node_for_each_tlv_with_type(node, a, DNCP_T_TRUST_VERDICT)
        if ((tv = dncp_tlv_trust_verdict(a)))
          {
            if (memcmp(&tv->sha256_hash, h, sizeof(*h)) == 0)
              {
                if (tv->verdict > remote_verdict)
                  {
                    remote_verdict = tv->verdict;
                    remote_node = node;
                    if (cname)
                      strcpy(cname, tv->cname);
                  }
              }
          }
  if (remote_node_return)
    *remote_node_return = remote_node;
  return remote_verdict;
}

static dncp_trust_node _trust_node_find(dncp_trust t,
                                        dncp_sha256 hash)
{
  dncp_trust_node cn = container_of(hash,
                                    dncp_trust_node_s,
                                    stored.tlv.sha256_hash);
  return vlist_find(&t->tree, cn, cn, in_tree);
}

int dncp_trust_get_verdict(dncp_trust t, const dncp_sha256 h, char *cname)
{
  dncp_trust_node tn = _trust_node_find(t, h);
  int verdict2 = tn ? tn->stored.tlv.verdict : DNCP_VERDICT_NONE;
  int verdict = _trust_get_remote_verdict(t, h, NULL, cname);
  if (verdict > verdict2)
    return verdict;
  if (tn && cname)
    strcpy(cname, tn->stored.tlv.cname);
  return verdict2;
}

static dncp_tlv _find_local_tlv(dncp d, dncp_sha256 hash)
{
  dncp_tlv tlv;
  dncp_t_trust_verdict tv;

  dncp_for_each_local_tlv(d, tlv)
    if ((tv = dncp_tlv_trust_verdict(&tlv->tlv)))
      {
        if (memcmp(hash, &tv->sha256_hash, sizeof(*hash)) == 0)
          return tlv;
      }
  return NULL;
}

static void _trust_publish_maybe(dncp_trust t, dncp_trust_node n)
{
  int len = sizeof(n->stored.tlv) + strlen(n->stored.cname) + 1;
  dncp_node rn;
  int remote_verdict =
    _trust_get_remote_verdict(t, &n->stored.tlv.sha256_hash, &rn, NULL);
  dncp_tlv tlv = _find_local_tlv(t->dncp, &n->stored.tlv.sha256_hash);

  /*
   * Either our verdict is _better_, or it is _same_ and our router id
   * is higher.
   */
  if (remote_verdict < n->stored.tlv.verdict
      || (remote_verdict == n->stored.tlv.verdict
          && (dncp_node_cmp(t->dncp->own_node, rn) > 0)))
    {
      if (tlv)
        {
          dncp_t_trust_verdict tv = dncp_tlv_trust_verdict(&tlv->tlv);
          if (tv->verdict == n->stored.tlv.verdict)
            return;
          dncp_remove_tlv(t->dncp, tlv);
        }
      dncp_local_tlv_extra le;
      int elen = sizeof(*le);
      tlv = dncp_add_tlv(t->dncp, DNCP_T_TRUST_VERDICT, &n->stored, len, elen);
      le = dncp_tlv_get_extra(tlv);
      le->tlv_time = hnetd_time();
    }
  else
    {
      /* Or it is not worth keeping published at all.. */
      if (tlv)
        dncp_remove_tlv(t->dncp, tlv);
    }
}

static void _update_trust_node(struct vlist_tree *tr,
                               struct vlist_node *node_new,
                               struct vlist_node *node_old)
{
  dncp_trust t = container_of(tr, dncp_trust_s, tree);
  dncp_trust_node t_old = container_of(node_old, dncp_trust_node_s, in_tree);
  dncp_trust_node t_new = container_of(node_new, dncp_trust_node_s, in_tree);

  if (t_old == t_new)
    return;
  if (t_old)
    {
      int len = sizeof(t_old->stored.tlv) + strlen(t_old->stored.cname) + 1;
      dncp_remove_tlv_matching(t->dncp,
                               DNCP_T_TRUST_VERDICT, &t_old->stored, len);
      if (t_old->stored.tlv.verdict == DNCP_VERDICT_NEUTRAL)
        t->num_neutral--;
      free(t_old);
    }
}

static bool _trust_set(dncp_trust t, const dncp_sha256 h,
                       uint8_t verdict, const char *cname)
{
  dncp_trust_node tn = _trust_node_find(t, h);
  static char empty[1] = {0};

  if (!cname)
    cname = empty;
  if (tn)
    {
      if (tn->stored.tlv.verdict == verdict
          && (cname == tn->stored.cname
              || strcmp(tn->stored.cname, cname) == 0
              || !*cname))
        return false;
      if (tn->stored.tlv.verdict == DNCP_VERDICT_NEUTRAL)
        t->num_neutral--;
    }
  else
    {
      tn = calloc(1, sizeof(*tn));
      if (!tn)
        {
          L_ERR("oom when creating new trust node");
          return false;
        }
      tn->stored.tlv.sha256_hash = *h;
      vlist_add(&t->tree, &tn->in_tree, tn);
    }
  tn->stored.tlv.verdict = verdict;
  if (verdict == DNCP_VERDICT_NEUTRAL)
    t->num_neutral++;
  if (*cname)
    strcpy(tn->stored.cname, cname);
  uloop_timeout_set(&t->timeout, SAVE_INTERVAL);
  return true;
}


static void _tlv_cb(dncp_subscriber s,
                    dncp_node n, struct tlv_attr *tlv, bool add __unused)
{
  dncp_trust t = container_of(s, dncp_trust_s, subscriber);
  dncp_t_trust_verdict tv = dncp_tlv_trust_verdict(tlv);

  /* We are only interested about trust verdicts */
  if (!tv)
    return;
  /* Local changes are not interesting */
  if (n == t->dncp->own_node)
    return;
  dncp_trust_node tn = _trust_node_find(t, &tv->sha256_hash);
  int local_verdict = DNCP_VERDICT_NEUTRAL;
  if (tv->verdict == DNCP_VERDICT_CONFIGURED_POSITIVE)
    local_verdict = DNCP_VERDICT_CACHED_POSITIVE;
  else if (tv->verdict == DNCP_VERDICT_CONFIGURED_NEGATIVE)
    local_verdict = DNCP_VERDICT_CACHED_NEGATIVE;

  /* Either no local state, or local state strictly inferior. */
  if (!tn || tn->stored.tlv.verdict < local_verdict)
    {
      if (!_trust_set(t,
                      &tv->sha256_hash,
                      local_verdict,
                      tv->cname))
        return;
      if (local_verdict == DNCP_VERDICT_NEUTRAL)
        return;
      if (!tn)
        tn = _trust_node_find(t, &tv->sha256_hash);
    }

  _trust_publish_maybe(t, tn);
}

void dncp_trust_set(dncp_trust t, const dncp_sha256 h,
                    uint8_t verdict, const char *cname)
{
  L_DEBUG("dncp_trust_set %s/%s %d",
          HEX_REPR(h, sizeof(*h)), cname ? cname : "-", (int)verdict);
  if (!_trust_set(t, h, verdict, cname))
    {
      L_DEBUG(" already set");
      return;
    }
  dncp_trust_node tn = _trust_node_find(t, h);
  _trust_publish_maybe(t, tn);
}

static int _trust_get_cert_verdict(dncp_trust t, dtls_cert cert)
{
  unsigned char buf[2048];
  int r = dtls_cert_to_der_buf(cert, buf, sizeof(buf));

  if (r <= 0 || r >= (int)sizeof(buf))
    {
      L_ERR("too huge DER output?!?");
      return DNCP_VERDICT_NONE;
    }
  dncp_sha256_s h;
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, buf, r);
  SHA256_Final(h.buf, &ctx);

  int verdict = dncp_trust_get_verdict(t, &h, NULL);

  char cbuf[DNCP_T_TRUST_VERDICT_CNAME_LEN];
  X509_NAME_oneline(X509_get_subject_name(cert),
                    cbuf,
                    sizeof(cbuf));

  if (verdict < DNCP_VERDICT_CONFIGURED_POSITIVE
      && hnetd_time() <= t->trust_until)
    {
      dncp_trust_set(t, &h, DNCP_VERDICT_CONFIGURED_POSITIVE, cbuf);
      verdict = DNCP_VERDICT_CONFIGURED_POSITIVE;
    }

  if (verdict != DNCP_VERDICT_NONE)
    {
      L_DEBUG("_trust_get_cert_verdict got %d verdict", verdict);
      return verdict;
    }

  L_DEBUG("_trust_get_cert_verdict requesting verdict");
  dncp_trust_request_verdict(t, &h, cbuf);
  return DNCP_VERDICT_NEUTRAL;
}

void dncp_trust_request_verdict(dncp_trust t,
                                const dncp_sha256 h,
                                const char *cname)
{
  if (dncp_trust_get_verdict(t, h, NULL) > DNCP_VERDICT_NEUTRAL)
    return;
  dncp_trust_set(t, h, DNCP_VERDICT_NEUTRAL, cname);
  while (t->num_neutral > NEUTRAL_MAXIMUM)
    {
      /* Get rid of the oldest one */
      dncp_trust_node tn, otn = NULL;
      dncp_local_tlv_extra le, ole = NULL;

      vlist_for_each_element(&t->tree, tn, in_tree)
        {
          /* We should not store neutral entries by others. So
           * anything with stored neutral verdict is valid target for
           * us. */
          if (tn->stored.tlv.verdict != DNCP_VERDICT_NEUTRAL)
            continue;
          dncp_tlv tlv = _find_local_tlv(t->dncp, &tn->stored.tlv.sha256_hash);
          if (tlv)
            {
              le = dncp_tlv_get_extra(tlv);
              if (!ole || ole->tlv_time > le->tlv_time)
                {
                  ole = le;
                  otn = tn;
                }
            }
        }
      if (!otn)
        {
          L_ERR("no neutral verdicts left yet num_neutral = %d",
                t->num_neutral);
          break;
        }
      vlist_delete(&t->tree, &otn->in_tree);
    }
}

static bool _dtls_unknown_callback(dtls d __unused,
                                   dtls_cert cert, void *context)
{
  dncp_trust t = context;
  int verdict = _trust_get_cert_verdict(t, cert);

  return verdict == DNCP_VERDICT_CACHED_POSITIVE ||
    verdict == DNCP_VERDICT_CONFIGURED_POSITIVE;
}

#define T_A(x) if (!(x)) return -ENOMEM

int _rpc_list(struct platform_rpc_method *m, __unused const struct blob_attr *in, struct blob_buf *b)
{
  /* Make blob_buf dict, with keys the hashes, and the values verdict
   * + cname. */
  dncp_trust o = container_of(m, dncp_trust_s, rpc_trust_list);
  dncp_sha256 h;
  char cname[DNCP_T_TRUST_VERDICT_CNAME_LEN];

  dncp_trust_for_each_hash(o, h)
    {
      int v = dncp_trust_get_verdict(o, h, cname);
      char buf[sizeof(*h)*2+1];
      void *t;
      T_A((t=blobmsg_open_table(b, hexlify(buf, (uint8_t *)h, sizeof(*h)))));
      if (*cname)
        T_A(!blobmsg_add_string(b, "cname", cname));
      T_A(!blobmsg_add_string(b, "verdict", dncp_trust_verdict_to_string(v)));
      blobmsg_close_table(b, t);
    }
  return 1;
}

int _rpc_set_timer(struct platform_rpc_method *m, const struct blob_attr *in, __unused struct blob_buf *out)
{
  dncp_trust t = container_of(m, dncp_trust_s, rpc_trust_set_timer);
  uint32_t seconds = 0;

  struct blob_attr *a;
  unsigned rem;
  blobmsg_for_each_attr(a, in, rem)
	  if (blobmsg_type(a) == BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(a), "timer_value"))
		  seconds = blobmsg_get_u32(a);

  t->trust_until = hnetd_time() + seconds * HNETD_TIME_PER_SECOND;
  return 0;
}

int _rpc_set(struct platform_rpc_method *m, const struct blob_attr *in, __unused struct blob_buf *out)
{
  dncp_trust t = container_of(m, dncp_trust_s, rpc_trust_set);
  const char *hs = NULL;
  int verdict = -1;

  struct blob_attr *a;
  unsigned rem;
  blobmsg_for_each_attr(a, in, rem) {
	  if (blobmsg_type(a) == BLOBMSG_TYPE_STRING && !strcmp(blobmsg_name(a), "hash"))
		  hs = blobmsg_get_string(a);
	  else if (blobmsg_type(a) == BLOBMSG_TYPE_INT32 && !strcmp(blobmsg_name(a), "verdict"))
		  verdict = blobmsg_get_u32(a);
  }

  if (!hs || verdict < 0)
	  return -EINVAL;

  dncp_sha256_s h;
  if (unhexlify((uint8_t *)&h, sizeof(h), hs) == sizeof(h)) {
    dncp_trust_set(t, &h, verdict, NULL);
  } else {
    L_ERR("invalid hash: %s", hs);
    return -EINVAL;
  }

  return 0;
}

dncp_trust dncp_trust_create(dncp o, const char *filename)
{
  dncp_trust t = calloc(1, sizeof(*t));

  if (!t)
    return NULL;
  t->dncp = o;
  vlist_init(&t->tree, _compare_trust_node, _update_trust_node);
  t->tree.keep_old = true;
  t->timeout.cb = _trust_write_cb;
  t->subscriber.tlv_change_callback = _tlv_cb;
  if (filename)
    t->filename = strdup(filename);
  _trust_load(t);
  _trust_calculate_hash(t, &t->file_hash);
  dncp_subscribe(o, &t->subscriber);
  /* TBD - refactor profile_data reference from common code? */
  if (o->profile_data.d)
    {
      L_DEBUG("dncp_trust_create setting unknown_cert_callback");
      dtls_set_unknown_cert_callback(o->profile_data.d,
                                     _dtls_unknown_callback, t);
    }

  t->rpc_trust_set_timer.cb = _rpc_set_timer;
  t->rpc_trust_set_timer.name = "trust-set-timer";
  t->rpc_trust_list.cb = _rpc_list;
  t->rpc_trust_list.name = "trust-list";
  t->rpc_trust_set.cb = _rpc_set;
  t->rpc_trust_set.name = "trust-set";

  platform_rpc_register(&t->rpc_trust_set_timer);
  platform_rpc_register(&t->rpc_trust_list);
  platform_rpc_register(&t->rpc_trust_set);
  return t;
}

void dncp_trust_destroy(dncp_trust t)
{
  dncp o = t->dncp;

  /* TBD - refactor profile_data reference from common code? */
  if (o->profile_data.d)
    {
      L_DEBUG("dncp_trust_destroy clearing unknown_cert_callback");
      dtls_set_unknown_cert_callback(o->profile_data.d, NULL, NULL);
    }
  if (t->filename)
    {
      /* Save the data if and only if it has changed (reduce writes..) */
      if (t->timeout.pending)
        _trust_save(t);
      free(t->filename);
    }
  dncp_unsubscribe(o, &t->subscriber);
  vlist_flush_all(&t->tree);
  uloop_timeout_cancel(&t->timeout);
  free(t);
}

dncp_sha256 dncp_trust_next_hash(dncp_trust t, const dncp_sha256 prev)
{
  dncp_trust_node n;

  if (!prev)
    {
      if (avl_is_empty(&t->tree.avl))
        return NULL;
      n = avl_first_element(&t->tree.avl, n, in_tree.avl);
    }
  else
    {
      dncp_trust_node last = avl_last_element(&t->tree.avl, n, in_tree.avl);
      n = _trust_node_find(t, prev);
      if (n == last || !n)
        return NULL;
      n = avl_next_element(n, in_tree.avl);
    }
  return &n->stored.tlv.sha256_hash;
}

const char *dncp_trust_verdict_to_string(dncp_trust_verdict verdict)
{
  switch (verdict)
    {
    case DNCP_VERDICT_NONE:
      return "none";
    case DNCP_VERDICT_NEUTRAL:
      return "neutral";
    case DNCP_VERDICT_CACHED_POSITIVE:
      return "cached-positive";
    case DNCP_VERDICT_CACHED_NEGATIVE:
      return "cached-negative";
    case DNCP_VERDICT_CONFIGURED_POSITIVE:
      return "positive";
    case DNCP_VERDICT_CONFIGURED_NEGATIVE:
      return "negative";
    default:
      return "unknown";
    }
}

dncp_trust_verdict dncp_trust_verdict_from_string(const char *verdict)
{
  /* Convenience - 1 = trust, 0 = no trust */
  if (strcmp(verdict, "1")==0)
    return DNCP_VERDICT_CONFIGURED_POSITIVE;
  if (strcmp(verdict, "0")==0)
    return DNCP_VERDICT_CONFIGURED_NEGATIVE;
  /* Allow direct use of returned strings too. */
  int i;
  for (i = -1 ; i < NUM_DNCP_VERDICT ; i++)
    if (strcmp(verdict, dncp_trust_verdict_to_string(i))==0)
      return i;
  return DNCP_VERDICT_NONE;
}


static int _trust_help(const char *prog)
{
	fprintf(stderr, "usage:\n");
	fprintf(stderr, "\t%s\n", prog);
	fprintf(stderr, "\t\tlist\n");
	fprintf(stderr, "\t\tset <hash> <value>\n");
	fprintf(stderr, "\t\tset-trust-timer <value-in-seconds>\n");
	return 1;
}

static int _trust_multicall(__unused struct platform_rpc_method *m, int argc, char* const argv[])
{
	struct blob_buf b = {NULL, NULL, 0, NULL};

	if (argc > 1) {
		if (strcmp(argv[1], "list") == 0) {
			return platform_rpc_cli("trust-list", NULL);
		} else if (strcmp(argv[1], "set") == 0) {
			if (argc != 4)
				return _trust_help(argv[0]);
			blob_buf_init(&b, 0);
			blobmsg_add_string(&b, "hash", argv[2]);
			int verdict = dncp_trust_verdict_from_string(argv[3]);
			if (verdict < 0) {
				L_ERR("invalid verdict: %s"
				      " (try e.g. 0, 1 or returned values)",
				      argv[3]);
			} else {
				blobmsg_add_u32(&b, "verdict", verdict);
				return platform_rpc_cli("trust-set", b.head);
			}
		} else if (strcmp(argv[1], "set-trust-timer") == 0) {
			if (argc == 3) {
				int value = atoi(argv[2]);
				if (value >= 0) {
					blob_buf_init(&b, 0);
					blobmsg_add_u32(&b, "timer_value", value);
					return platform_rpc_cli("trust-set-timer", b.head);
				}
			}
		}
	}

	return _trust_help(argv[0]);
}

static struct platform_rpc_method _trust_multicall_method = {
	.name = "trust", .main = _trust_multicall
};

void dncp_trust_register_multicall(void)
{
	platform_rpc_register(&_trust_multicall_method);
}
