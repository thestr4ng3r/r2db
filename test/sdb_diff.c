
#include "sdb_diff.h"
#include <r_util.h>

typedef struct sdb_diff_ctx_t {
	Sdb *a;
	Sdb *b;
	bool equal;
	RStrBuf *buf;
	SdbList *path;
} SdbDiffCtx;

#define DIFF(ctx, c, ret) do { \
	(ctx)->equal = false; \
	if ((ctx)->buf) { \
		c \
	} else { \
		/* we already know it's not equal and don't care about the rest of the diff */ \
		return ret; \
	} \
} while(0)

#define PREFIX_EXTRA_NS "NS"
#define PREFIX_EXTRA_KV "  "

static void sdb_diff_dump_path(SdbDiffCtx *ctx) {
	SdbListIter *it;
	const char *str;
	ls_foreach (ctx->path, it, str) {
		r_strbuf_appendf (ctx->buf, "%s/", str);
	}
}

static void sdb_diff_dump_ns(SdbDiffCtx *ctx, SdbNs *ns, bool add) {
	r_strbuf_appendf (ctx->buf, "%c"PREFIX_EXTRA_NS" ", add ? '+' : '-');
	sdb_diff_dump_path (ctx);
	r_strbuf_appendf (ctx->buf, "%s\n", ns->name);
}

static void sdb_diff_dump_kv(SdbDiffCtx *ctx, const char *k, const char *v, bool add) {
	r_strbuf_appendf (ctx->buf, "%c"PREFIX_EXTRA_KV" ", add ? '+' : '-');
	sdb_diff_dump_path (ctx);
	r_strbuf_appendf (ctx->buf, "%s=%s\n", k, v);
}

typedef struct sdb_diff_dump_kv_cb_ctx {
	SdbDiffCtx *ctx;
	bool add;
} SdbDiffKVCbCtx;

static int sdb_diff_dump_kv_cb(void *user, const char *k, const char *v) {
	const SdbDiffKVCbCtx *ctx = user;
	sdb_diff_dump_kv (ctx->ctx, k, v, ctx->add);
	return true;
}

/**
 * just print everything from sdb to buf with prefix
 */
static void sdb_diff_dump(SdbDiffCtx *ctx, Sdb *sdb, bool add) {
	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (sdb->ns, it, ns) {
		sdb_diff_dump_ns (ctx, ns, add);
		ls_push (ctx->path, ns->name);
		sdb_diff_dump (ctx, ns->sdb, add);
		ls_pop (ctx->path);
	}
	SdbDiffKVCbCtx cb_ctx = { ctx, add };
	sdb_foreach (sdb, sdb_diff_dump_kv_cb, &cb_ctx);
}

static int sdb_diff_kv_cb(void *user, const char *k, const char *v) {
	const SdbDiffKVCbCtx *ctx = user;
	Sdb *other = ctx->add ? ctx->ctx->a : ctx->ctx->b;
	const char *other_val = sdb_get (other, k, NULL);
	if (!other_val || !*other_val) {
		DIFF (ctx->ctx,
			sdb_diff_dump_kv (ctx->ctx, k, v, ctx->add);
		, false);
	} else if (!ctx->add && strcmp (v, other_val) != 0) {
		DIFF (ctx->ctx,
			sdb_diff_dump_kv (ctx->ctx, k, v, false);
			sdb_diff_dump_kv (ctx->ctx, k, other_val, true);
		, false);
	}
	return true;
}

static void sdb_diff_ctx(SdbDiffCtx *ctx) {
	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (ctx->a->ns, it, ns) {
		Sdb *b_ns = sdb_ns (ctx->b, ns->name, false);
		if (!b_ns) {
			DIFF (ctx,
				sdb_diff_dump_ns (ctx, ns, false);
				ls_push (ctx->path, ns->name);
				sdb_diff_dump (ctx, ns->sdb, false);
				ls_pop (ctx->path);
			,);
			continue;
		}
		Sdb *a = ctx->a;
		Sdb *b = ctx->b;
		ctx->a = ns->sdb;
		ctx->b = b_ns;
		sdb_diff_ctx (ctx);
		ctx->a = a;
		ctx->b = b;
	}
	ls_foreach (ctx->b->ns, it, ns) {
		if (!sdb_ns (ctx->a, ns->name, false)) {
			DIFF (ctx,
				sdb_diff_dump_ns (ctx, ns, true);
				ls_push (ctx->path, ns->name);
				sdb_diff_dump (ctx, ns->sdb, true);
				ls_pop (ctx->path);
			,);
		}
	}
	SdbDiffKVCbCtx kv_ctx = { ctx, false };
	if (!sdb_foreach (ctx->a, sdb_diff_kv_cb, &kv_ctx)) {
		return;
	}
	kv_ctx.add = true;
	sdb_foreach (ctx->a, sdb_diff_kv_cb, &kv_ctx);
}

SDB_API bool sdb_diff(Sdb *a, Sdb *b, char **diff) {
	SdbDiffCtx ctx;
	ctx.a = a;
	ctx.b = b;
	ctx.equal = true;
	ctx.buf = diff ? r_strbuf_new (NULL) : NULL;
	if (diff && !ctx.buf) {
		return false;
	}
	ctx.path = ls_new ();
	if (!ctx.path) {
		r_strbuf_free (ctx.buf);
		return false;
	}
	sdb_diff_ctx (&ctx);
	if (diff) {
		*diff = r_strbuf_drain (ctx.buf);
	}
	ls_free (ctx.path);
	return ctx.equal;
}
