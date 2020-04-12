/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>
#include <nxjson.h>
#include "serialize_util.h"
#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /blocks
 *     0x<addr>={size:<ut64>, jump?:<ut64>, fail?:<ut64>, traced?:true, folded?:true, colorize?:<ut32>,
 *               fingerprint?:"<base64>", diff?: <RAnalDiff>, switch_op?:<RAnalSwitchOp>,
 *               ninstr:<int>, op_pos?:[<ut16>], stackptr:<int>, parent_stackptr:<int>,
 *               cmpval:<ut64>, cmpreg?:<str>}
 *   /functions
 *     0x<addr>={name:<str>, bits?:<int>, type:<int>, cc?:<str>, stack:<int>, maxstack:<int>,
 *               ninstr:<int>, folded?:<bool>, pure?:<bool>, bp_frame?:<bool>, noreturn?:<bool>,
 *               fingerprint?:"<base64>", diff?:<RAnalDiff>, bbs:[<ut64>], imports?:[<str>]}
 *   /xrefs
 *     0x<addr>=[{to:<ut64>, type?:"c"|"C"|"d"|"s"}]
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
	if (diff->addr != UT64_MAX) {
		pj_kn (j, "addr", diff->addr);
	}
	if (diff->dist != 0.0) {
		pj_kd (j, "dist", diff->dist);
	}
	if (diff->name) {
		pj_ks (j, "name", diff->name);
	}
	if (diff->size) {
		pj_kn (j, "size", (ut64)diff->size);
	}
	pj_end (j);
}

enum {
	DIFF_FIELD_TYPE,
	DIFF_FIELD_ADDR,
	DIFF_FIELD_DIST,
	DIFF_FIELD_NAME,
	DIFF_FIELD_SIZE
};

R_API RSerializeAnalDiffParser r_serialize_anal_diff_parser_new() {
	RSerializeAnalDiffParser parser = key_parser_new ();
	if (!parser) {
		return NULL;
	}
	key_parser_add (parser, "type", DIFF_FIELD_TYPE);
	key_parser_add (parser, "addr", DIFF_FIELD_ADDR);
	key_parser_add (parser, "dist", DIFF_FIELD_DIST);
	key_parser_add (parser, "name", DIFF_FIELD_NAME);
	key_parser_add (parser, "size", DIFF_FIELD_SIZE);
	return parser;
}

R_API void r_serialize_anal_diff_parser_free(RSerializeAnalDiffParser parser) {
	key_parser_free (parser);
}

R_API R_NULLABLE RAnalDiff *r_serialize_anal_diff_load(R_NONNULL RSerializeAnalDiffParser parser, R_NONNULL const nx_json *json) {
	if (json->type != NX_JSON_OBJECT) {
		return NULL;
	}
	RAnalDiff *diff = r_anal_diff_new ();
	if (!diff) {
		return NULL;
	}
	KEY_PARSER_JSON (parser, json, child, {
		case DIFF_FIELD_TYPE:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			if (strcmp (child->text_value, "m") == 0) {
				diff->type = R_ANAL_DIFF_TYPE_MATCH;
			} else if (strcmp (child->text_value, "u") == 0) {
				diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			}
			break;
		case DIFF_FIELD_ADDR:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			diff->addr = child->num.u_value;
			break;
		case DIFF_FIELD_DIST:
			if (child->type == NX_JSON_INTEGER) {
				diff->dist = child->num.u_value;
			} else if (child->type == NX_JSON_DOUBLE) {
				diff->dist = child->num.dbl_value;
			}
			break;
		case DIFF_FIELD_NAME:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			free (diff->name);
			diff->name = strdup (child->text_value);
			break;
		case DIFF_FIELD_SIZE:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			diff->size = child->num.u_value;
			break;
		default:
			break;
	})
	return diff;
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

R_API RAnalSwitchOp *r_serialize_anal_switch_op_load(R_NONNULL const nx_json *json) {
	if (json->type != NX_JSON_OBJECT) {
		return NULL;
	}
	RAnalSwitchOp *sop = r_anal_switch_op_new (0, 0, 0, 0);
	if (!sop) {
		return NULL;
	}
	nx_json *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type == NX_JSON_INTEGER) {
			if (strcmp (child->key, "addr") == 0) {
				sop->addr = child->num.u_value;
			} else if (strcmp (child->key, "min") == 0) {
				sop->min_val = child->num.u_value;
			} else if (strcmp (child->key, "max") == 0) {
				sop->max_val = child->num.u_value;
			} else if (strcmp (child->key, "def") == 0) {
				sop->def_val = child->num.u_value;
			}
		} else if (child->type == NX_JSON_ARRAY && strcmp (child->key, "cases") == 0) {
			nx_json *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != NX_JSON_OBJECT) {
					continue;
				}
				ut64 addr = UT64_MAX;
				ut64 jump = UT64_MAX;
				ut64 value = UT64_MAX;
				nx_json *semen;
				for (semen = baby->children.first; semen; semen = semen->next) {
					if (semen->type != NX_JSON_INTEGER) {
						continue;
					}
					if (strcmp (semen->key, "addr") == 0) {
						addr = semen->num.u_value;
					} else if (strcmp (semen->key, "jump") == 0) {
						jump = semen->num.u_value;
					} else if (strcmp (semen->key, "value") == 0) {
						value = semen->num.u_value;
					}
				}
				r_anal_switch_op_add_case (sop, addr, value, jump);
			}
		}
	}
	return sop;
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

	if (block->ninstr) {
		pj_ki (j, "ninstr", block->ninstr);
	}
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

	if (block->stackptr) {
		pj_ki (j, "stackptr", block->stackptr);
	}
	if (block->parent_stackptr != INT_MAX) {
		pj_ki (j, "parent_stackptr", block->parent_stackptr);
	}
	if (block->cmpval != UT64_MAX) {
		pj_kn (j, "cmpval", block->cmpval);
	}
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
	BLOCK_FIELD_FAIL,
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
	RSerializeAnalDiffParser diff_parser;
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
	proto.jump = UT64_MAX;
	proto.fail = UT64_MAX;
	proto.size = UT64_MAX;
	proto.parent_stackptr = INT_MAX;
	proto.cmpval = UT64_MAX;
	size_t fingerprint_size = SIZE_MAX;
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
		case BLOCK_FIELD_FAIL:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.fail = child->num.u_value;
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
				fingerprint_size = 0;
			} else if (decsz < fingerprint_size) {
				ut8 *n = realloc (proto.fingerprint, (size_t)decsz);
				if (n) {
					proto.fingerprint = n;
					fingerprint_size = decsz;
				}
			}
			break;
		}
		case BLOCK_FIELD_DIFF:
			r_anal_diff_free (proto.diff);
			proto.diff = r_serialize_anal_diff_load (ctx->diff_parser, child);
			break;
		case BLOCK_FIELD_SWITCH_OP:
			r_anal_switch_op_free (proto.switch_op);
			proto.switch_op = r_serialize_anal_switch_op_load (child);
			break;
		case BLOCK_FIELD_NINSTR:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.ninstr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_OP_POS: {
			if (child->type != NX_JSON_ARRAY) {
				break;
			}
			if (proto.op_pos) {
				free (proto.op_pos);
				proto.op_pos = NULL;
			}
			proto.op_pos = calloc (child->children.length, sizeof (ut16));
			proto.op_pos_size = 0;
			nx_json *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != NX_JSON_INTEGER) {
					free (proto.op_pos);
					proto.op_pos = NULL;
					proto.op_pos_size = 0;
					break;
				}
				proto.op_pos[proto.op_pos_size++] = (ut16)baby->num.u_value;
			}
			break;
		}
		case BLOCK_FIELD_STACKPTR:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_PARENT_STACKPTR:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.parent_stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_CMPVAL:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			proto.cmpval = child->num.u_value;
			break;
		case BLOCK_FIELD_CMPREG:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			proto.cmpreg = r_str_constpool_get (&ctx->anal->constpool, child->text_value);
			break;
		default:
			break;
	})
	nx_json_free (json);
	free (json_str);

	errno = 0;
	ut64 addr = strtoull (k, NULL, 0);
	if (errno || proto.size == UT64_MAX
		|| (fingerprint_size != SIZE_MAX && fingerprint_size != proto.size)
		|| (proto.op_pos && proto.op_pos_size != proto.ninstr - 1)) { // op_pos_size > ninstr - 1 is legal but we require the format to be like this.
		goto error;
	}

	RAnalBlock *block = r_anal_create_block (ctx->anal, addr, proto.size);
	if (!block) {
		goto error;
	}
	block->jump = proto.jump;
	block->fail = proto.fail;
	block->traced = proto.traced;
	block->folded = proto.folded;
	block->colorize = proto.colorize;
	block->fingerprint = proto.fingerprint;
	block->diff = proto.diff;
	block->switch_op = proto.switch_op;
	block->ninstr = proto.ninstr;
	if (proto.op_pos) {
		free (block->op_pos);
		block->op_pos = proto.op_pos;
		block->op_pos_size = proto.op_pos_size;
	}
	block->stackptr = proto.stackptr;
	block->parent_stackptr = proto.parent_stackptr;
	block->cmpval = proto.cmpval;
	block->cmpreg = proto.cmpreg;

	return true;
error:
	free (proto.fingerprint);
	r_anal_diff_free (proto.diff);
	r_anal_switch_op_free (proto.switch_op);
	free (proto.op_pos);
	return false;
}

R_API bool r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE char **err) {
	BlockLoadCtx ctx = { anal, key_parser_new (), diff_parser };
	if (!ctx.parser) {
		SERIALIZE_ERR ("parser init failed");
		return false;
	}
	key_parser_add (ctx.parser, "size", BLOCK_FIELD_SIZE);
	key_parser_add (ctx.parser, "jump", BLOCK_FIELD_JUMP);
	key_parser_add (ctx.parser, "fail", BLOCK_FIELD_FAIL);
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
	bool ret = sdb_foreach (db, block_load_cb, &ctx);
	key_parser_free (ctx.parser);
	if (!ret) {
		SERIALIZE_ERR ("basic blocks parsing failed");
	}
	return ret;
}

static void function_store(R_NONNULL Sdb *db, const char *key, RAnalFunction *function) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_o (j);

	pj_ks (j, "name", function->name);
	if (function->bits) {
		pj_ki (j, "bits", function->bits);
	}
	pj_ki (j, "type", function->type);
	if (function->cc) {
		pj_ks (j, "cc", function->cc);
	}
	pj_ki (j, "stack", function->stack);
	pj_ki (j, "maxstack", function->maxstack);
	pj_ki (j, "ninstr", function->ninstr);
	if (function->folded) {
		pj_kb (j, "folded", true);
	}
	if (function->bp_frame) {
		pj_kb (j, "bp_frame", true);
	}
	if (function->is_pure) {
		pj_kb (j, "pure", true);
	}
	if (function->is_noreturn) {
		pj_kb (j, "noreturn", true);
	}
	if (function->fingerprint) {
		char *b64 = r_base64_encode_dyn ((const char *)function->fingerprint, function->fingerprint_size);
		if (b64) {
			pj_ks (j, "fingerprint", b64);
			free (b64);
		}
	}
	if (function->diff) {
		pj_k (j, "diff");
		r_serialize_anal_diff_save (j, function->diff);
	}

	pj_ka (j, "bbs");
	RListIter *it;
	RAnalBlock *block;
	r_list_foreach (function->bbs, it, block) {
		pj_n (j, block->addr);
	}
	pj_end (j);

	if (!r_list_empty (function->imports)) {
		pj_ka (j, "imports");
		const char *import;
		r_list_foreach (function->imports, it, import) {
			pj_s (j, import);
		}
		pj_end (j);
	}

	pj_end (j);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
}

R_API void r_serialize_anal_functions_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	RListIter *it;
	RAnalFunction *function;
	RStrBuf key;
	r_strbuf_init (&key);
	r_list_foreach (anal->fcns, it, function) {
		r_strbuf_setf (&key, "0x%"PFMT64x, function->addr);
		function_store (db, r_strbuf_get (&key), function);
	}
	r_strbuf_fini (&key);
}

enum {
	FUNCTION_FIELD_NAME,
	FUNCTION_FIELD_BITS,
	FUNCTION_FIELD_TYPE,
	FUNCTION_FIELD_CC,
	FUNCTION_FIELD_STACK,
	FUNCTION_FIELD_MAXSTACK,
	FUNCTION_FIELD_NINSTR,
	FUNCTION_FIELD_FOLDED,
	FUNCTION_FIELD_PURE,
	FUNCTION_FIELD_BP_FRAME,
	FUNCTION_FIELD_NORETURN,
	FUNCTION_FIELD_FINGERPRINT,
	FUNCTION_FIELD_DIFF,
	FUNCTION_FIELD_BBS,
	FUNCTION_FIELD_IMPORTS
};

typedef struct {
	RAnal *anal;
	KeyParser *parser;
	RSerializeAnalDiffParser diff_parser;
} FunctionLoadCtx;

static int function_load_cb(void *user, const char *k, const char *v) {
	FunctionLoadCtx *ctx = user;

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	const nx_json *json = nx_json_parse_utf8 (json_str);
	if (!json || json->type != NX_JSON_OBJECT) {
		free (json_str);
		return false;
	}

	RAnalFunction *function = r_anal_function_new (ctx->anal);
	function->bits = 0; // should be 0 if not specified
	function->bp_frame = false; // should be false if not specified
	bool noreturn = false;
	KEY_PARSER_JSON (ctx->parser, json, child, {
		case FUNCTION_FIELD_NAME:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			if (function->name) {
				free (function->name);
			}
			function->name = strdup (child->text_value);
			break;
		case FUNCTION_FIELD_BITS:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			function->bits = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_TYPE:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			function->type = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_CC:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			function->cc = r_str_constpool_get (&ctx->anal->constpool, child->text_value);
			break;
		case FUNCTION_FIELD_STACK:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			function->stack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_MAXSTACK:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			function->maxstack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_NINSTR:
			if (child->type != NX_JSON_INTEGER) {
				break;
			}
			function->ninstr = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_FOLDED:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			function->folded = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_PURE:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			function->is_pure = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_BP_FRAME:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			function->bp_frame = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_NORETURN:
			if (child->type != NX_JSON_BOOL) {
				break;
			}
			noreturn = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_FINGERPRINT:
			if (child->type != NX_JSON_STRING) {
				break;
			}
			if (function->fingerprint) {
				free (function->fingerprint);
				function->fingerprint = NULL;
			}
			function->fingerprint_size = strlen (child->text_value);
			if (!function->fingerprint_size) {
				break;
			}
			function->fingerprint = malloc (function->fingerprint_size);
			if (!function->fingerprint) {
				function->fingerprint_size = 0;
				break;
			}
			int decsz = r_base64_decode (function->fingerprint, child->text_value, function->fingerprint_size);
			if (decsz <= 0) {
				free (function->fingerprint);
				function->fingerprint = NULL;
				function->fingerprint_size = 0;
			} else if (decsz < function->fingerprint_size) {
				ut8 *n = realloc (function->fingerprint, (size_t)decsz);
				if (!n) {
					free (function->fingerprint);
					function->fingerprint = NULL;
					function->fingerprint_size = 0;
				}
				function->fingerprint = n;
				function->fingerprint_size = (size_t)decsz;
			}
			break;
		case FUNCTION_FIELD_DIFF:
			r_anal_diff_free (function->diff);
			function->diff = r_serialize_anal_diff_load (ctx->diff_parser, child);
			break;
		case FUNCTION_FIELD_BBS: {
			if (child->type != NX_JSON_ARRAY) {
				break;
			}
			nx_json *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != NX_JSON_INTEGER) {
					continue;
				}
				RAnalBlock *block = r_anal_get_block_at (ctx->anal, baby->num.u_value);
				if (!block) {
					continue;
				}
				r_anal_function_add_block (function, block);
			}
			break;
		}
		case FUNCTION_FIELD_IMPORTS: {
			if (child->type != NX_JSON_ARRAY) {
				break;
			}
			nx_json *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != NX_JSON_STRING) {
					continue;
				}
				char *import = strdup (baby->text_value);
				if (!import) {
					break;
				}
				if (!function->imports) {
					function->imports = r_list_newf ((RListFree)free);
					if (!function->imports) {
						free (import);
						break;
					}
				}
				r_list_push (function->imports, import);
			}
			break;
		}
		default:
			break;
	})
	nx_json_free (json);
	free (json_str);

	errno = 0;
	function->addr = strtoull (k, NULL, 0);
	if (errno || !function->name || !r_anal_add_function (ctx->anal, function)) {
		r_anal_function_free (function);
		return false;
	}
	function->is_noreturn = noreturn; // Can't set directly, r_anal_add_function() overwrites it

	return true;
}

R_API bool r_serialize_anal_functions_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE char **err) {
	BlockLoadCtx ctx = { anal, key_parser_new (), diff_parser };
	if (!ctx.parser) {
		SERIALIZE_ERR ("parser init failed");
		return false;
	}
	key_parser_add (ctx.parser, "name", FUNCTION_FIELD_NAME);
	key_parser_add (ctx.parser, "bits", FUNCTION_FIELD_BITS);
	key_parser_add (ctx.parser, "type", FUNCTION_FIELD_TYPE);
	key_parser_add (ctx.parser, "cc", FUNCTION_FIELD_CC);
	key_parser_add (ctx.parser, "stack", FUNCTION_FIELD_STACK);
	key_parser_add (ctx.parser, "maxstack", FUNCTION_FIELD_MAXSTACK);
	key_parser_add (ctx.parser, "ninstr", FUNCTION_FIELD_NINSTR);
	key_parser_add (ctx.parser, "folded", FUNCTION_FIELD_FOLDED);
	key_parser_add (ctx.parser, "pure", FUNCTION_FIELD_PURE);
	key_parser_add (ctx.parser, "bp_frame", FUNCTION_FIELD_BP_FRAME);
	key_parser_add (ctx.parser, "noreturn", FUNCTION_FIELD_NORETURN);
	key_parser_add (ctx.parser, "fingerprint", FUNCTION_FIELD_FINGERPRINT);
	key_parser_add (ctx.parser, "diff", FUNCTION_FIELD_DIFF);
	key_parser_add (ctx.parser, "bbs", FUNCTION_FIELD_BBS);
	key_parser_add (ctx.parser, "imports", FUNCTION_FIELD_IMPORTS);
	bool ret = sdb_foreach (db, function_load_cb, &ctx);
	key_parser_free (ctx.parser);
	if (!ret) {
		SERIALIZE_ERR ("functions parsing failed");
	}
	return ret;
}

static bool store_xref_cb(void *j, const ut64 k, const void *v) {
	const RAnalRef *xref = v;
	pj_o (j);
	pj_kn (j, "to", k);
	if (xref->type != R_ANAL_REF_TYPE_NULL) {
		char type[2] = { xref->type, '\0' };
		pj_ks (j, "type", type);
	}
	pj_end (j);
	return true;
}

static bool store_xrefs_list_cb(void *db, const ut64 k, const void *v) {
	char key[0x20];
	if (snprintf (key, sizeof (key), "0x%"PFMT64x, k) < 0) {
		return false;
	}
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);
	HtUP *ht = (HtUP *)v;
	ht_up_foreach (ht, store_xref_cb, j);
	pj_end (j);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
	return true;
}

R_API void r_serialize_anal_xrefs_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	ht_up_foreach (anal->dict_refs, store_xrefs_list_cb, db);
}

static int xrefs_load_cb(void *user, const char *k, const char *v) {
	RAnal *anal = user;

	errno = 0;
	ut64 from = strtoull (k, NULL, 0);;
	if (errno) {
		return false;
	}

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	const nx_json *json = nx_json_parse_utf8 (json_str);
	if (!json || json->type != NX_JSON_ARRAY) {
		free (json_str);
		return false;
	}

	const nx_json *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != NX_JSON_OBJECT) {
			goto error;
		}
		const nx_json *baby = nx_json_get (child, "to");
		if (!baby || baby->type != NX_JSON_INTEGER) {
			goto error;
		}
		ut64 to = baby->num.u_value;

		RAnalRefType type = R_ANAL_REF_TYPE_NULL;
		baby = nx_json_get (child, "type");
		if (baby) {
			// must be a 1-char string
			if (baby->type != NX_JSON_STRING || !baby->text_value[0] || baby->text_value[1]) {
				goto error;
			}
			switch (baby->text_value[0]) {
			case R_ANAL_REF_TYPE_CODE:
			case R_ANAL_REF_TYPE_CALL:
			case R_ANAL_REF_TYPE_DATA:
			case R_ANAL_REF_TYPE_STRING:
				type = baby->text_value[0];
				break;
			default:
				goto error;
			}
		}

		r_anal_xrefs_set (anal, from, to, type);
	}

	nx_json_free (json);
	free (json_str);

	return true;
error:
	nx_json_free (json);
	free (json_str);
	return false;
}

R_API bool r_serialize_anal_xrefs_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE char **err) {
	bool ret = sdb_foreach (db, xrefs_load_cb, anal);
	if (!ret && err) {
		SERIALIZE_ERR ("xrefs parsing failed");
	}
	return ret;
}

R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	r_serialize_anal_xrefs_save (sdb_ns (db, "xrefs", true), anal);
	r_serialize_anal_blocks_save (sdb_ns (db, "blocks", true), anal);
	r_serialize_anal_functions_save (sdb_ns (db, "functions", true), anal);
}

R_API bool r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE char **err) {
	bool ret = false;
	RSerializeAnalDiffParser diff_parser = r_serialize_anal_diff_parser_new ();
	if (!diff_parser) {
		goto beach;
	}

	r_anal_purge (anal);

	Sdb *subdb;
#define SUB(ns, call) SUB_DO(ns, call, goto beach;)
	SUB ("xrefs", r_serialize_anal_xrefs_load (subdb, anal, err));

	SUB ("blocks", r_serialize_anal_blocks_load (subdb, anal, diff_parser, err));
	// All bbs have ref=1 now
	SUB ("functions", r_serialize_anal_functions_load (subdb, anal, diff_parser, err));
	// BB's refs have increased if they are part of a function.
	// We must subtract from each to hold our invariant again.
	// If any block has ref=0 then, it should be deleted. But we can't do this while
	// iterating the RBTree, otherwise this will become a segfault cacophony, so we cache them.
	RPVector orphaned_bbs;
	r_pvector_init (&orphaned_bbs, (RPVectorFree)r_anal_block_unref);
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		if (block->ref <= 1) {
			r_pvector_push (&orphaned_bbs, block);
			continue;
		}
		r_anal_block_unref (block);
	}
	r_pvector_clear (&orphaned_bbs); // unrefs all

	ret = true;
beach:
	r_serialize_anal_diff_parser_free (diff_parser);
	return ret;
}
