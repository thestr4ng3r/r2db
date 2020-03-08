/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>
#include <nxjson.h>
#include "serialize_util.h"

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, traced?:true, folded?:true, colorize?:<ut32>,
 *               fingerprint?:"<base64>", diff?: <RAnalDiff>, switch_op?:<RAnalSwitchOp>,
 *               ninstr:<int>, op_pos?:[<ut16>], stackptr:<int>, parent_stackptr:<int>,
 *               cmpval:<ut64>, cmpreg?:<str>}
 *     ...
 *
 *
 * RAnalDiff JSON:
 * {type?:"m"|"u", addr:<ut64>, dist:<double>, name?:<str>, size:<ut32>}
 *
 * RAnalSwitchOp JSON:
 * {addr:<ut64>, min:<ut64>, max:<ut64>, def:<ut64>, cases:[<RAnalCaseOp>]}
 *
 * RAnalCaseOp JSON:
 * {addr:<ut64>, jump:<ut64>, value:<ut64>}
 *
 */

R_API void r_serialize_anal_diff_save(R_NONNULL PJ *j, R_NONNULL RAnalDiff *diff) {
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

R_API void r_serialize_anal_case_op_save(R_NONNULL PJ *j, R_NONNULL RAnalCaseOp *op) {
	pj_o (j);
	pj_kn (j, "addr", op->addr);
	pj_kn (j, "jump", op->jump);
	pj_kn (j, "value", op->value);
	pj_end (j);
}

R_API void r_serialize_anal_switch_op_save(R_NONNULL PJ *j, R_NONNULL RAnalSwitchOp *op) {
	pj_o (j);
	pj_kn (j, "addr", op->addr);
	pj_kn (j, "min", op->min_val);
	pj_kn (j, "max", op->max_val);
	pj_kn (j, "def", op->def_val);
	pj_k (j, "cases");
	pj_a (j);
	RListIter *it;
	RAnalCaseOp *cop;
	r_list_foreach (op->cases, it, cop) {
		r_serialize_anal_case_op_save (j, cop);
	}
	pj_end (j);
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
		r_serialize_anal_diff_save (j, block->diff);
	}

	// TODO: cond? It's used nowhere...

	if (block->switch_op) {
		pj_k (j, "switch_op");
		r_serialize_anal_switch_op_save (j, block->switch_op);
	}

	pj_ki (j, "ninstr", block->ninstr);
	if (block->op_pos && block->ninstr > 1) {
		pj_k (j, "op_pos");
		pj_a (j);
		size_t i;
		for (i = 0; i < block->ninstr - 1; i++) {
			pj_n (j, block->op_pos[i]);
		}
		pj_end (j);
	}

	// op_bytes is only java, never set
	// parent_reg_arena is never set

	pj_ki (j, "stackptr", block->stackptr);
	pj_ki (j, "parent_stackptr", block->parent_stackptr);
	pj_kn (j, "cmpval", block->cmpval);
	if (block->cmpreg) {
		pj_ks (j, "cmpreg", block->cmpreg);
	}

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

enum {
	BLOCK_FIELD_SIZE,
	BLOCK_FIELD_JUMP,
	BLOCK_FIELD_TRACED,
	BLOCK_FIELD_FOLDED,
	BLOCK_FIELD_COLORIZE,
	BLOCK_FIELD_FINGERPRINT,
	BLOCK_FIELD_DIFF,
	BLOCK_FIELD_SWITCH_OP,
	BLOCK_FIELD_NINSTR,
	BLOCK_FIELD_OP_POS,
	BLOCK_FIELD_STACKPTR,
	BLOCK_FIELD_PARENT_STACKPTR,
	BLOCK_FIELD_CMPVAL,
	BLOCK_FIELD_CMPREG
};

typedef struct {
	RAnal *anal;
	KeyParser *parser;
} BlockLoadCtx;

static int block_load_cb(void *user, const char *k, const char *v) {
	BlockLoadCtx *ctx = user;

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	const nx_json *json = nx_json_parse_utf8 (json_str);
	if (!json || json->type != NX_JSON_OBJECT) {
		free (json_str);
		return false;
	}

	RAnalBlock proto = { 0 };
	size_t fingerprint_size;
	KEY_PARSER_JSON (ctx->parser, json, child, {
		case BLOCK_FIELD_SIZE:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.size = child->num.u_value;
			break;
		case BLOCK_FIELD_JUMP:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.jump = child->num.u_value;
			break;
		case BLOCK_FIELD_TRACED:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			proto.traced = child->num.u_value;
			break;
		case BLOCK_FIELD_FOLDED:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			proto.folded = child->num.u_value;
			break;
		case BLOCK_FIELD_COLORIZE:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.colorize = (ut32)child->num.u_value;
			break;
		case BLOCK_FIELD_FINGERPRINT: {
			if (child->type != NX_JSON_STRING) {
				break;
			}
			if (proto.fingerprint) {
				free (proto.fingerprint);
				proto.fingerprint = NULL;
			}
			fingerprint_size = strlen (child->text_value);
			if (!fingerprint_size) {
				break;
			}
			proto.fingerprint = malloc (fingerprint_size);
			if (!proto.fingerprint) {
				break;
			}
			int decsz = r_base64_decode (proto.fingerprint, child->text_value, fingerprint_size);
			if (decsz <= 0) {
				free (proto.fingerprint);
				proto.fingerprint = NULL;
			} else if (decsz < fingerprint_size) {
				ut8 *n = realloc (proto.fingerprint, (size_t)decsz);
				if (n) {
					proto.fingerprint = n;
				}
			}
			break;
		}

		// TODO: all these fields
		case BLOCK_FIELD_DIFF:
			break;
		case BLOCK_FIELD_SWITCH_OP:
			break;
		case BLOCK_FIELD_NINSTR:
			break;
		case BLOCK_FIELD_OP_POS:
			break;
		case BLOCK_FIELD_STACKPTR:
			break;
		case BLOCK_FIELD_PARENT_STACKPTR:
			break;
		case BLOCK_FIELD_CMPVAL:
			break;
		case BLOCK_FIELD_CMPREG:
			break;
		default:
			break;
	})

	ut64 addr = strtoull (k, NULL, 0);

	// TODO: create bb and apply data from proto

	return true;
}

R_API void r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	BlockLoadCtx ctx = { anal, key_parser_new () };
	if (!ctx.parser) {
		return;
	}
	key_parser_add (ctx.parser, "size", BLOCK_FIELD_SIZE);
	key_parser_add (ctx.parser, "jump", BLOCK_FIELD_JUMP);
	key_parser_add (ctx.parser, "traced", BLOCK_FIELD_TRACED);
	key_parser_add (ctx.parser, "folded", BLOCK_FIELD_FOLDED);
	key_parser_add (ctx.parser, "colorize", BLOCK_FIELD_COLORIZE);
	key_parser_add (ctx.parser, "fingerprint", BLOCK_FIELD_FINGERPRINT);
	key_parser_add (ctx.parser, "diff", BLOCK_FIELD_DIFF);
	key_parser_add (ctx.parser, "switch_op", BLOCK_FIELD_SWITCH_OP);
	key_parser_add (ctx.parser, "ninstr", BLOCK_FIELD_NINSTR);
	key_parser_add (ctx.parser, "op_pos", BLOCK_FIELD_OP_POS);
	key_parser_add (ctx.parser, "stackptr", BLOCK_FIELD_STACKPTR);
	key_parser_add (ctx.parser, "parent_stackptr", BLOCK_FIELD_PARENT_STACKPTR);
	key_parser_add (ctx.parser, "cmpval", BLOCK_FIELD_CMPVAL);
	key_parser_add (ctx.parser, "cmpreg", BLOCK_FIELD_CMPREG);
	sdb_foreach (db, block_load_cb, &ctx);
	key_parser_free (ctx.parser);
}


R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {

}

R_API void r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {

}
