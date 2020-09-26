/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"
#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /files
 *     <fd>={perm:<int>, uri:<str>, name:<str>, referer?:<str>}
 *     /pcache
 *       <fd>.<ut64>={cached:<ut64>, data:<base64>}
 */


typedef struct {
	int fd;
	int perm;
	char *uri;
	char *name;
	char *referer;
	HtUP *cache;
	void *data;
	struct r_io_plugin_t *plugin;
	RIO *io;
} RIODescasd;

typedef struct {
	int fd;
	Sdb *db;
} PCacheSaveCtx;

static bool pcache_save_cb(void *user, const ut64 k, const void *v) {
	PCacheSaveCtx *ctx = user;
	const RIODescCache *cache = v;
	char key[0x30];
	if (snprintf (key, sizeof (key), "%d.0x%"PFMT64x, ctx->fd, k) < 0) {
		return false;
	}
	char val[R_IO_DESC_CACHE_SIZE * 4 + 1];
	r_base64_encode (val, cache->cdata, R_IO_DESC_CACHE_SIZE);
	return true;
}

static bool file_save_cb(void *user, void *data, ut32 id) {
	Sdb *db = user;
	RIODesc *desc = (RIODesc *)data;

	char key[0x20];
	if (snprintf (key, sizeof (key), "%d", desc->fd) < 0) {
		return false;
	}

	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_o (j);

	pj_ki (j, "perm", desc->perm);
	// obsz is irrelevant (never written, always 0)
	pj_ks (j, "uri", desc->uri);
	pj_ks (j, "name", desc->name);
	if (desc->referer) {
		pj_ks (j, "referer", desc->referer);
	}
	// TODO: plugin

	pj_end (j);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);

	if (desc->cache->count) {
		PCacheSaveCtx ctx = {
			.fd = desc->fd,
			.db = sdb_ns (db, "pcache", true)
		};
		ht_up_foreach (desc->cache, pcache_save_cb, &ctx);
	}
	return true;
}

R_API void r_serialize_io_files_save(R_NONNULL Sdb *db, R_NONNULL RIO *io) {
	sdb_ns (db, "pcache", true);
	r_id_storage_foreach (io->files, file_save_cb, db);
}

R_API bool r_serialize_io_files_load(R_NONNULL Sdb *db, R_NONNULL RIO *io, R_NULLABLE RSerializeResultInfo *res) {
	return true;
}

R_API void r_serialize_io_save(R_NONNULL Sdb *db, R_NONNULL RIO *io) {
	r_serialize_io_files_save (sdb_ns (db, "files", true), io);
}

R_API bool r_serialize_io_load(R_NONNULL Sdb *db, R_NONNULL RIO *io, R_NULLABLE RSerializeResultInfo *res) {
	// TODO: purge RIO?
	bool ret = false;
	Sdb *subdb;
#define SUB(ns, call) SUB_DO(ns, call, goto beach;)
	SUB ("files", r_serialize_io_files_load (subdb, io, res));
#undef SUB
	ret = true;
beach:
	return true;
}
