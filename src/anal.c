/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, traced?:true, folded?:true, colorize?:<ut32>,
 *               fingerprint?:"<base64>", diff?: <RAnalDiff>}
 *     ...
 *
 *
 * RAnalDiff JSON:
 * {type?:"m"|"u", addr:<ut64>, dist:<double>, name?:<str>, size:<ut32>}
 *
 */

static void diff_save(R_NONNULL PJ *j, RAnalDiff *diff) {
	pj_o (j);
	switch (diff->type) {
	case R_ANAL_DIFF_TYPE_MATCH:
		pj_ks (j, "type", "m");
		break;
	case R_ANAL_DIFF_TYPE_UNMATCH:
		pj_ks (j, "type", "u");
		break;
	}
	pj_kn (j, "addr", diff->addr);
	pj_kd (j, "dist", diff->dist);
	if (diff->name) {
		pj_ks (j, "name", diff->name);
	}
	pj_kn (j, "size", (ut64)diff->size);
	pj_end (j);
}

static void block_store(R_NONNULL Sdb *db, const char *key, RAnalBlock *block) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_o (j);

	pj_kn (j, "size", block->size);
	if (block->jump != UT64_MAX) {
		pj_kn (j, "jump", block->jump);
	}
	if (block->fail != UT64_MAX) {
		pj_kn (j, "fail", block->fail);
	}
	if (block->traced) {
		pj_kb (j, "traced", true);
	}
	if (block->folded) {
		pj_kb (j, "folded", true);
	}
	if (block->colorize) {
		pj_kn (j, "colorize", (ut64)block->colorize);
	}
	if (block->fingerprint) {
		char *b64 = r_base64_encode_dyn ((const char *)block->fingerprint, block->size);
		if (b64) {
			pj_ks (j, "fingerprint", b64);
			free (b64);
		}
	}
	if (block->diff) {
		pj_k (j, "diff");
		diff_save (j, block->diff);
	}

	// TODO: cond?

	// TODO: rest

	pj_end (j);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
}

R_API void r_serialize_anal_blocks_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	RBIter iter;
	RAnalBlock *block;
	RStrBuf key = { 0 };
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		r_strbuf_setf (&key, "0x%"PFMT64x, block->addr);
		block_store (db, r_strbuf_get (&key), block);
	}
	r_strbuf_fini (&key);
}

R_API void r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {

}


R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {

}

R_API void r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {

}
