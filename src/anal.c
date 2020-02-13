/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, type:<int>}
 *     ...
 *
 */

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
	pj_ki (j, "type", block->type);

	//int traced;
	//ut32 colorize;
	//char *label;
	//ut8 *fingerprint;
	//RAnalDiff *diff;
	//RAnalCond *cond;
	//RAnalSwitchOp *switch_op;
//
	//int ninstr;
	//// offsets of instructions in this block
	//ut16 *op_pos;
	//// size of the op_pos array
	//int op_pos_size;
	//ut8 *op_bytes;
//
	//ut8 op_sz;
	///* these are used also in pdr: */
	//RAnalBlock *prev;
	//RAnalBlock *failbb;
	//RAnalBlock *jumpbb;
	//RList /*struct r_anal_bb_t*/ *cases;
	//ut8 *parent_reg_arena;
	//int stackptr;
	//int parent_stackptr;
	//bool folded;
	//ut64 cmpval;
	//const char *cmpreg;

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
