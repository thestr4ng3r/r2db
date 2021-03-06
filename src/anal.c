/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>
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
 *               fingerprint?:"<base64>", diff?:<RAnalDiff>, bbs:[<ut64>], imports?:[<str>], vars?:[<RAnalVar>],
 *               labels?: {<str>:<ut64>}}
 *   /xrefs
 *     0x<addr>=[{to:<ut64>, type?:"c"|"C"|"d"|"s"}]
 *
 *   /meta
 *     0x<addr>=[{size?:<ut64, interpreted as 1 if not present>, type:<str>, subtype?:<int>, str?:<str>, space?:<str>}]
 *     /spaces
 *       see spaces.c
 *
 *   /hints
 *     0x<addr>={arch?:<str|null>,bits?:<int|null>,toff?:<string>,nword?:<int>,jump?:<ut64>,fail?:<ut64>,newbits?:<int>,
 *               immbase?:<int>,ptr?:<ut64>,ret?:<ut64>,syntax?:<str>,opcode?:<str>,esil?:<str>,optype?:<int>,
 *               size?:<ut64>,frame?:<ut64>,val?:<ut64>,high?:<bool>}
 *   /classes
 *     <direct dump of RAnal.sdb_classes>
 *     /attrs
 *       <direct dump of RAnal.sdb_classes_attrs>
 *
 *   /zigns
 *     <direct dump of RAnal.sdb_zigns>
 *     /spaces
 *       see spaces.c
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
 * RAnalVar JSON:
 * {name:<str>, type:<str>, kind:"s|b|r", arg?:<bool>, delta?:<st64>, reg?:<str>, cmt?:<str>,
 *   accs?: [{off:<st64>, type:"r|w|rw", reg:<str>, sp?:<st64>}], constrs?:[<int>,<ut64>,...]}
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

R_API R_NULLABLE RAnalDiff *r_serialize_anal_diff_load(R_NONNULL RSerializeAnalDiffParser parser, R_NONNULL const RJson *json) {
	if (json->type != R_JSON_OBJECT) {
		return NULL;
	}
	RAnalDiff *diff = r_anal_diff_new ();
	if (!diff) {
		return NULL;
	}
	KEY_PARSER_JSON (parser, json, child, {
		case DIFF_FIELD_TYPE:
			if (child->type != R_JSON_STRING) {
				break;
			}
			if (strcmp (child->str_value, "m") == 0) {
				diff->type = R_ANAL_DIFF_TYPE_MATCH;
			} else if (strcmp (child->str_value, "u") == 0) {
				diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			}
			break;
		case DIFF_FIELD_ADDR:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			diff->addr = child->num.u_value;
			break;
		case DIFF_FIELD_DIST:
			if (child->type == R_JSON_INTEGER) {
				diff->dist = child->num.u_value;
			} else if (child->type == R_JSON_DOUBLE) {
				diff->dist = child->num.dbl_value;
			}
			break;
		case DIFF_FIELD_NAME:
			if (child->type != R_JSON_STRING) {
				break;
			}
			free (diff->name);
			diff->name = strdup (child->str_value);
			break;
		case DIFF_FIELD_SIZE:
			if (child->type != R_JSON_INTEGER) {
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

R_API RAnalSwitchOp *r_serialize_anal_switch_op_load(R_NONNULL const RJson *json) {
	if (json->type != R_JSON_OBJECT) {
		return NULL;
	}
	RAnalSwitchOp *sop = r_anal_switch_op_new (0, 0, 0, 0);
	if (!sop) {
		return NULL;
	}
	RJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type == R_JSON_INTEGER) {
			if (strcmp (child->key, "addr") == 0) {
				sop->addr = child->num.u_value;
			} else if (strcmp (child->key, "min") == 0) {
				sop->min_val = child->num.u_value;
			} else if (strcmp (child->key, "max") == 0) {
				sop->max_val = child->num.u_value;
			} else if (strcmp (child->key, "def") == 0) {
				sop->def_val = child->num.u_value;
			}
		} else if (child->type == R_JSON_ARRAY && strcmp (child->key, "cases") == 0) {
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_OBJECT) {
					continue;
				}
				ut64 addr = UT64_MAX;
				ut64 jump = UT64_MAX;
				ut64 value = UT64_MAX;
				RJson *semen;
				for (semen = baby->children.first; semen; semen = semen->next) {
					if (semen->type != R_JSON_INTEGER) {
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

static bool block_load_cb(void *user, const char *k, const char *v) {
	BlockLoadCtx *ctx = user;

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_OBJECT) {
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
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.size = child->num.u_value;
			break;
		case BLOCK_FIELD_JUMP:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.jump = child->num.u_value;
			break;
		case BLOCK_FIELD_FAIL:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.fail = child->num.u_value;
			break;
		case BLOCK_FIELD_TRACED:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			proto.traced = child->num.u_value;
			break;
		case BLOCK_FIELD_FOLDED:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			proto.folded = child->num.u_value;
			break;
		case BLOCK_FIELD_COLORIZE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.colorize = (ut32)child->num.u_value;
			break;
		case BLOCK_FIELD_FINGERPRINT: {
			if (child->type != R_JSON_STRING) {
				break;
			}
			if (proto.fingerprint) {
				free (proto.fingerprint);
				proto.fingerprint = NULL;
			}
			fingerprint_size = strlen (child->str_value);
			if (!fingerprint_size) {
				break;
			}
			proto.fingerprint = malloc (fingerprint_size);
			if (!proto.fingerprint) {
				break;
			}
			int decsz = r_base64_decode (proto.fingerprint, child->str_value, fingerprint_size);
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
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.ninstr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_OP_POS: {
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			if (proto.op_pos) {
				free (proto.op_pos);
				proto.op_pos = NULL;
			}
			proto.op_pos = calloc (child->children.count, sizeof (ut16));
			proto.op_pos_size = 0;
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_INTEGER) {
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
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_PARENT_STACKPTR:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.parent_stackptr = (int)child->num.s_value;
			break;
		case BLOCK_FIELD_CMPVAL:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.cmpval = child->num.u_value;
			break;
		case BLOCK_FIELD_CMPREG:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.cmpreg = r_str_constpool_get (&ctx->anal->constpool, child->str_value);
			break;
		default:
			break;
	})
	r_json_free (json);
	free (json_str);

	errno = 0;
	ut64 addr = strtoull (k, NULL, 0);
	if (errno || proto.size == UT64_MAX
		|| (fingerprint_size != SIZE_MAX && fingerprint_size != proto.size)
		|| (proto.op_pos && proto.op_pos_size != proto.ninstr - 1)) { // op_pos_size > ninstr - 1 is legal but we require the format to be like this.
		goto resor;
	}

	RAnalBlock *block = r_anal_create_block (ctx->anal, addr, proto.size);
	if (!block) {
		goto resor;
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
resor:
	free (proto.fingerprint);
	r_anal_diff_free (proto.diff);
	r_anal_switch_op_free (proto.switch_op);
	free (proto.op_pos);
	return false;
}

R_API bool r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE RSerializeResultInfo *res) {
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

R_API void r_serialize_anal_var_save(R_NONNULL PJ *j, R_NONNULL RAnalVar *var) {
	pj_o (j);
	pj_ks (j, "name", var->name);
	pj_ks (j, "type", var->type);
	switch (var->kind) {
	case R_ANAL_VAR_KIND_REG:
		pj_ks (j, "kind", "r");
		break;
	case R_ANAL_VAR_KIND_SPV:
		pj_ks (j, "kind", "s");
		break;
	case R_ANAL_VAR_KIND_BPV:
		pj_ks (j, "kind", "b");
		break;
	}
	if (var->kind != R_ANAL_VAR_KIND_REG) {
		pj_kN (j, "delta", var->delta);
	}
	if (var->regname) {
		pj_ks (j, "reg", var->regname);
	}
	if (var->isarg) {
		pj_kb (j, "arg", true);
	}
	if (var->comment) {
		pj_ks (j, "cmt", var->comment);
	}
	if (!r_vector_empty (&var->accesses)) {
		pj_ka (j, "accs");
		RAnalVarAccess *acc;
		r_vector_foreach (&var->accesses, acc) {
			pj_o (j);
			pj_kn (j, "off", acc->offset);
			switch (acc->type) {
			case R_ANAL_VAR_ACCESS_TYPE_READ:
				pj_ks (j, "type", "r");
				break;
			case R_ANAL_VAR_ACCESS_TYPE_WRITE:
				pj_ks (j, "type", "w");
				break;
			case R_ANAL_VAR_ACCESS_TYPE_READ | R_ANAL_VAR_ACCESS_TYPE_WRITE:
				pj_ks (j, "type", "rw");
				break;
			}
			if (acc->stackptr) {
				pj_kn (j, "sp", acc->stackptr);
			}
			if (acc->reg) {
				pj_ks (j, "reg", acc->reg);
			} else {
				r_warn_if_reached();
			}
			pj_end (j);
		}
		pj_end (j);
	}
	if (!r_vector_empty (&var->constraints)) {
		pj_ka (j, "constrs");
		RAnalVarConstraint *constr;
		r_vector_foreach (&var->constraints, constr) {
			pj_i (j, (int)constr->cond);
			pj_n (j, constr->val);
		}
		pj_end (j);
	}
	pj_end (j);
}

enum {
	VAR_FIELD_NAME,
	VAR_FIELD_TYPE,
	VAR_FIELD_KIND,
	VAR_FIELD_ARG,
	VAR_FIELD_DELTA,
	VAR_FIELD_REG,
	VAR_FIELD_COMMENT,
	VAR_FIELD_ACCS,
	VAR_FIELD_CONSTRS
};

R_API RSerializeAnalVarParser r_serialize_anal_var_parser_new() {
	RSerializeAnalDiffParser parser = key_parser_new ();
	if (!parser) {
		return NULL;
	}
	key_parser_add (parser, "name", VAR_FIELD_NAME);
	key_parser_add (parser, "type", VAR_FIELD_TYPE);
	key_parser_add (parser, "kind", VAR_FIELD_KIND);
	key_parser_add (parser, "arg", VAR_FIELD_ARG);
	key_parser_add (parser, "delta", VAR_FIELD_DELTA);
	key_parser_add (parser, "reg", VAR_FIELD_REG);
	key_parser_add (parser, "cmt", VAR_FIELD_COMMENT);
	key_parser_add (parser, "accs", VAR_FIELD_ACCS);
	key_parser_add (parser, "constrs", VAR_FIELD_CONSTRS);
	return parser;
}

R_API void r_serialize_anal_var_parser_free(RSerializeAnalVarParser parser) {
	key_parser_free (parser);
}

R_API R_NULLABLE RAnalVar *r_serialize_anal_var_load(R_NONNULL RAnalFunction *fcn, R_NONNULL RSerializeAnalVarParser parser, R_NONNULL const RJson *json) {
	if (json->type != R_JSON_OBJECT) {
		return NULL;
	}
	const char *name = NULL;
	const char *type = NULL;
	RAnalVarKind kind = -1;
	bool arg = false;
	st64 delta = ST64_MAX;
	const char *regname = NULL;
	const char *comment = NULL;
	RVector accesses;
	r_vector_init (&accesses, sizeof (RAnalVarAccess), NULL, NULL);
	RVector constraints;
	r_vector_init (&constraints, sizeof (RAnalVarConstraint), NULL, NULL);

	RAnalVar *ret = NULL;

	KEY_PARSER_JSON (parser, json, child, {
		case VAR_FIELD_NAME:
			if (child->type != R_JSON_STRING) {
				break;
			}
			name = child->str_value;
			break;
		case VAR_FIELD_TYPE:
			if (child->type != R_JSON_STRING) {
				break;
			}
			type = child->str_value;
			break;
		case VAR_FIELD_KIND:
			if (child->type != R_JSON_STRING || !*child->str_value || child->str_value[1]) {
				// must be a string of exactly 1 char
				break;
			}
			switch (*child->str_value) {
			case 'r':
				kind = R_ANAL_VAR_KIND_REG;
				break;
			case 's':
				kind = R_ANAL_VAR_KIND_SPV;
				break;
			case 'b':
				kind = R_ANAL_VAR_KIND_BPV;
				break;
			default:
				break;
			}
			break;
		case VAR_FIELD_ARG:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			arg = child->num.u_value ? true : false;
			break;
		case VAR_FIELD_DELTA:
			if (child->type != R_JSON_INTEGER) {
				eprintf ("delta nop\n");
				break;
			}
			delta = child->num.s_value;
			break;
		case VAR_FIELD_REG:
			if (child->type != R_JSON_STRING) {
				break;
			}
			regname = child->str_value;
			break;
		case VAR_FIELD_COMMENT:
			if (child->type != R_JSON_STRING) {
				break;
			}
			comment = child->str_value;
			break;
		case VAR_FIELD_ACCS: {
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_OBJECT) {
					continue;
				}
				// {off:<st64>, type:"r|w|rw", sp?:<st64>}
				const RJson *offv = r_json_get (baby, "off");
				if (!offv || offv->type != R_JSON_INTEGER) {
					continue;
				}
				const RJson *typev = r_json_get (baby, "type");
				if (!typev || typev->type != R_JSON_STRING) {
					continue;
				}
				const char *acctype_str = typev->str_value;
				const RJson *spv = r_json_get (baby, "sp");
				if (spv && spv->type != R_JSON_INTEGER) {
					continue;
				}
				const RJson *regv = r_json_get (baby, "reg");
				if (!regv || regv->type != R_JSON_STRING) {
					continue;
				}

				ut64 acctype;
				// parse "r", "w" or "rw" and reject everything else
				if (acctype_str[0] == 'r') {
					if (acctype_str[1] == 'w') {
						acctype = R_ANAL_VAR_ACCESS_TYPE_READ | R_ANAL_VAR_ACCESS_TYPE_WRITE;
					} else if (!acctype_str[1]) {
						acctype = R_ANAL_VAR_ACCESS_TYPE_READ;
					} else {
						continue;
					}
				} else if (acctype_str[0] == 'w' && !acctype_str[1]) {
					acctype = R_ANAL_VAR_ACCESS_TYPE_WRITE;
				} else {
					continue;
				}

				RAnalVarAccess *acc = r_vector_push (&accesses, NULL);
				acc->offset = offv->num.s_value;
				acc->type = acctype;
				acc->stackptr = spv ? spv->num.s_value : 0;
				acc->reg = regv->str_value;
			}
			break;
		}
		case VAR_FIELD_CONSTRS: {
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_INTEGER) {
					break;
				}
				RJson *sibling = baby->next;
				if (!sibling || sibling->type != R_JSON_INTEGER) {
					break;
				}
				RAnalVarConstraint constr;
				constr.cond = (_RAnalCond)baby->num.s_value;
				constr.val = sibling->num.u_value;
				if (constr.cond < R_ANAL_COND_AL || constr.cond > R_ANAL_COND_LS) {
					baby = sibling;
					continue;
				}
				r_vector_push (&constraints, &constr);
				baby = sibling;
			}
			break;
		}
		default:
			break;
	})

	if (kind == R_ANAL_VAR_KIND_REG) {
		if (!regname) {
			goto beach;
		}
		RRegItem *reg = r_reg_get (fcn->anal->reg, regname, -1);
		if (!reg) {
			goto beach;
		}
		delta = reg->index;
	}
	if (!name || !type || kind == -1 || delta == ST64_MAX) {
		goto beach;
	}
	ret = r_anal_function_set_var (fcn, delta, kind, type, 0, arg, name);
	if (!ret) {
		goto beach;
	}
	if (comment) {
		free (ret->comment);
		ret->comment = strdup (comment);
	}
	RAnalVarAccess *acc;
	r_vector_foreach (&accesses, acc) {
		r_anal_var_set_access (ret, acc->reg, fcn->addr + acc->offset, acc->type, acc->stackptr);
	}
	RAnalVarConstraint *constr;
	r_vector_foreach (&constraints, constr) {
		r_anal_var_add_constraint (ret, constr);
	}

beach:
	r_vector_fini (&accesses);
	r_vector_fini (&constraints);
	return ret;
}

static bool store_label_cb(void *j, const ut64 k, const void *v) {
	pj_kn (j, v, k);
	return true;
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

	if (!r_pvector_empty (&function->vars)) {
		pj_ka (j, "vars");
		void **vit;
		r_pvector_foreach (&function->vars, vit) {
			RAnalVar *var = *vit;
			r_serialize_anal_var_save (j, var);
		}
		pj_end (j);
	}

	if (function->labels->count) {
		pj_ko (j, "labels");
		ht_up_foreach (function->labels, store_label_cb, j);
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
	FUNCTION_FIELD_IMPORTS,
	FUNCTION_FIELD_VARS,
	FUNCTION_FIELD_LABELS
};

typedef struct {
	RAnal *anal;
	KeyParser *parser;
	RSerializeAnalDiffParser diff_parser;
	RSerializeAnalVarParser var_parser;
} FunctionLoadCtx;

static bool function_load_cb(void *user, const char *k, const char *v) {
	FunctionLoadCtx *ctx = user;

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_OBJECT) {
		free (json_str);
		return false;
	}

	RAnalFunction *function = r_anal_function_new (ctx->anal);
	function->bits = 0; // should be 0 if not specified
	function->bp_frame = false; // should be false if not specified
	bool noreturn = false;
	RJson *vars_json = NULL;
	KEY_PARSER_JSON (ctx->parser, json, child, {
		case FUNCTION_FIELD_NAME:
			if (child->type != R_JSON_STRING) {
				break;
			}
			if (function->name) {
				free (function->name);
			}
			function->name = strdup (child->str_value);
			break;
		case FUNCTION_FIELD_BITS:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			function->bits = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_TYPE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			function->type = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_CC:
			if (child->type != R_JSON_STRING) {
				break;
			}
			function->cc = r_str_constpool_get (&ctx->anal->constpool, child->str_value);
			break;
		case FUNCTION_FIELD_STACK:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			function->stack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_MAXSTACK:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			function->maxstack = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_NINSTR:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			function->ninstr = (int)child->num.s_value;
			break;
		case FUNCTION_FIELD_FOLDED:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			function->folded = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_PURE:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			function->is_pure = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_BP_FRAME:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			function->bp_frame = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_NORETURN:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			noreturn = child->num.u_value ? true : false;
			break;
		case FUNCTION_FIELD_FINGERPRINT:
			if (child->type != R_JSON_STRING) {
				break;
			}
			if (function->fingerprint) {
				free (function->fingerprint);
				function->fingerprint = NULL;
			}
			function->fingerprint_size = strlen (child->str_value);
			if (!function->fingerprint_size) {
				break;
			}
			function->fingerprint = malloc (function->fingerprint_size);
			if (!function->fingerprint) {
				function->fingerprint_size = 0;
				break;
			}
			int decsz = r_base64_decode (function->fingerprint, child->str_value, function->fingerprint_size);
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
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_INTEGER) {
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
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_STRING) {
					continue;
				}
				char *import = strdup (baby->str_value);
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
		case FUNCTION_FIELD_VARS: {
			if (child->type != R_JSON_ARRAY) {
				break;
			}
			vars_json = child;
			break;
		}
		case FUNCTION_FIELD_LABELS: {
			if (child->type != R_JSON_OBJECT) {
				break;
			}
			RJson *baby;
			for (baby = child->children.first; baby; baby = baby->next) {
				if (baby->type != R_JSON_INTEGER) {
					continue;
				}
				r_anal_function_set_label (function, baby->key, baby->num.u_value);
			}
			break;
		}
		default:
			break;
	})

	bool ret = true;
	errno = 0;
	function->addr = strtoull (k, NULL, 0);
	if (errno || !function->name || !r_anal_add_function (ctx->anal, function)) {
		r_anal_function_free (function);
		ret = false;
		goto beach;
	}
	function->is_noreturn = noreturn; // Can't set directly, r_anal_add_function() overwrites it

	if (vars_json) {
		RJson *baby;
		for (baby = vars_json->children.first; baby; baby = baby->next) {
			r_serialize_anal_var_load (function, ctx->var_parser, baby);
		}
	}

beach:
	r_json_free (json);
	free (json_str);
	return ret;
}

R_API bool r_serialize_anal_functions_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE RSerializeResultInfo *res) {
	FunctionLoadCtx ctx = {
		.anal = anal,
		.parser = key_parser_new (),
		.diff_parser = diff_parser,
		.var_parser = r_serialize_anal_var_parser_new ()
	};
	bool ret;
	if (!ctx.parser || !ctx.var_parser) {
		SERIALIZE_ERR ("parser init failed");
		ret = false;
		goto beach;
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
	key_parser_add (ctx.parser, "vars", FUNCTION_FIELD_VARS);
	key_parser_add (ctx.parser, "labels", FUNCTION_FIELD_LABELS);
	ret = sdb_foreach (db, function_load_cb, &ctx);
	if (!ret) {
		SERIALIZE_ERR ("functions parsing failed");
	}
beach:
	key_parser_free (ctx.parser);
	r_serialize_anal_var_parser_free (ctx.var_parser);
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

static bool xrefs_load_cb(void *user, const char *k, const char *v) {
	RAnal *anal = user;

	errno = 0;
	ut64 from = strtoull (k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_ARRAY) {
		free (json_str);
		return false;
	}

	const RJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != R_JSON_OBJECT) {
			goto resor;
		}
		const RJson *baby = r_json_get (child, "to");
		if (!baby || baby->type != R_JSON_INTEGER) {
			goto resor;
		}
		ut64 to = baby->num.u_value;

		RAnalRefType type = R_ANAL_REF_TYPE_NULL;
		baby = r_json_get (child, "type");
		if (baby) {
			// must be a 1-char string
			if (baby->type != R_JSON_STRING || !baby->str_value[0] || baby->str_value[1]) {
				goto resor;
			}
			switch (baby->str_value[0]) {
			case R_ANAL_REF_TYPE_CODE:
			case R_ANAL_REF_TYPE_CALL:
			case R_ANAL_REF_TYPE_DATA:
			case R_ANAL_REF_TYPE_STRING:
				type = baby->str_value[0];
				break;
			default:
				goto resor;
			}
		}

		r_anal_xrefs_set (anal, from, to, type);
	}

	r_json_free (json);
	free (json_str);

	return true;
resor:
	r_json_free (json);
	free (json_str);
	return false;
}

R_API bool r_serialize_anal_xrefs_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	bool ret = sdb_foreach (db, xrefs_load_cb, anal);
	if (!ret) {
		SERIALIZE_ERR ("xrefs parsing failed");
	}
	return ret;
}

R_API void r_serialize_anal_meta_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	r_serialize_spaces_save (sdb_ns (db, "spaces", true), &anal->meta_spaces);

	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	char key[0x20];
	RIntervalTreeIter it;
	RAnalMetaItem *meta;
	ut64 addr = 0;
	size_t count = 0;
#define FLUSH pj_end (j); \
		if (snprintf (key, sizeof (key), "0x%"PFMT64x, addr) >= 0) { \
			sdb_set (db, key, pj_string (j), 0); \
		}
	r_interval_tree_foreach (&anal->meta, it, meta) {
		RIntervalNode *node = r_interval_tree_iter_get (&it);
		if (count && node->start != addr) {
			// new address
			FLUSH
			pj_reset (j);
			pj_a (j);
			count = 0;
		} else if (!count) {
			// first address
			pj_a (j);
		}
		count++;
		addr = node->start;
		pj_o (j);
		ut64 size = r_meta_node_size (node);
		if (size != 1) {
			pj_kn (j, "size", size);
		}
		char type_str[2] = { 0 };
		switch (meta->type) {
		case R_META_TYPE_DATA:
			type_str[0] = 'd';
			break;
		case R_META_TYPE_CODE:
			type_str[0] = 'c';
			break;
		case R_META_TYPE_STRING:
			type_str[0] = 's';
			break;
		case R_META_TYPE_FORMAT:
			type_str[0] = 'f';
			break;
		case R_META_TYPE_MAGIC:
			type_str[0] = 'm';
			break;
		case R_META_TYPE_HIDE:
			type_str[0] = 'h';
			break;
		case R_META_TYPE_COMMENT:
			type_str[0] = 'C';
			break;
		case R_META_TYPE_RUN:
			type_str[0] = 'r';
			break;
		case R_META_TYPE_HIGHLIGHT:
			type_str[0] = 'H';
			break;
		case R_META_TYPE_VARTYPE:
			type_str[0] = 't';
			break;
		default:
			break;
		}
		pj_ks (j, "type", type_str);
		if (meta->subtype) {
			pj_ki (j, "subtype", meta->subtype);
		}
		if (meta->str) {
			pj_ks (j, "str", meta->str);
		}
		if (meta->space) {
			pj_ks (j, "space", meta->space->name);
		}
		pj_end (j);
	}
	if (count) {
		FLUSH
	}
#undef FLUSH
	pj_free (j);
}

static bool meta_load_cb(void *user, const char *k, const char *v) {
	RAnal *anal = user;

	errno = 0;
	ut64 addr = strtoull (k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_ARRAY) {
		free (json_str);
		return false;
	}

	const RJson *child;
	for (child = json->children.first; child; child = child->next) {
		if (child->type != R_JSON_OBJECT) {
			goto resor;
		}

		ut64 size = 1;
		RAnalMetaType type = R_META_TYPE_ANY;
		const char *str = NULL;
		int subtype = 0;
		const char *space_name = NULL;

		const RJson *baby;
		for (baby = child->children.first; baby; baby = baby->next) {
			if (!strcmp (baby->key, "size")) {
				if (baby->type == R_JSON_INTEGER) {
					size = baby->num.u_value;
				}
				continue;
			}
			if (!strcmp (baby->key, "type")) {
				// only single-char strings accepted
				if (baby->type == R_JSON_STRING && baby->str_value[0] && !baby->str_value[1]) {
					switch (baby->str_value[0]) {
					case 'd':
						type = R_META_TYPE_DATA;
						break;
					case 'c':
						type = R_META_TYPE_CODE;
						break;
					case 's':
						type = R_META_TYPE_STRING;
						break;
					case 'f':
						type = R_META_TYPE_FORMAT;
						break;
					case 'm':
						type = R_META_TYPE_MAGIC;
						break;
					case 'h':
						type = R_META_TYPE_HIDE;
						break;
					case 'C':
						type = R_META_TYPE_COMMENT;
						break;
					case 'r':
						type = R_META_TYPE_RUN;
						break;
					case 'H':
						type = R_META_TYPE_HIGHLIGHT;
						break;
					case 't':
						type = R_META_TYPE_VARTYPE;
						break;
					default:
						break;
					}
				}
				continue;
			}
			if (!strcmp (baby->key, "str")) {
				if (baby->type == R_JSON_STRING) {
					str = baby->str_value;
				}
				continue;
			}
			if (!strcmp (baby->key, "subtype")) {
				if (baby->type == R_JSON_INTEGER) {
					subtype = (int)baby->num.s_value;
				}
				continue;
			}
			if (!strcmp (baby->key, "space")) {
				if (baby->type == R_JSON_STRING) {
					space_name = baby->str_value;
				}
				continue;
			}
		}

		if (type == R_META_TYPE_ANY || (type == R_META_TYPE_COMMENT && !str)) {
			continue;
		}

		RAnalMetaItem *item = R_NEW0 (RAnalMetaItem);
		if (!item) {
			break;
		}
		item->type = type;
		item->subtype = subtype;
		item->space = space_name ? r_spaces_get (&anal->meta_spaces, space_name) : NULL;
		item->str = str ? strdup (str) : NULL;
		if (str && !item->str) {
			free (item);
			continue;
		}
		ut64 end = addr + size - 1;
		if (end < addr) {
			end = UT64_MAX;
		}
		r_interval_tree_insert (&anal->meta, addr, end, item);
	}

	r_json_free (json);
	free (json_str);

	return true;
resor:
	r_json_free (json);
	free (json_str);
	return false;
}

R_API bool r_serialize_anal_meta_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	Sdb *spaces_db = sdb_ns (db, "spaces", false);
	if (!spaces_db) {
		SERIALIZE_ERR ("missing meta spaces namespace");
		return false;
	}
	if (!r_serialize_spaces_load (spaces_db, &anal->meta_spaces, false, res)) {
		return false;
	}
	bool ret = sdb_foreach (db, meta_load_cb, anal);
	if (!ret) {
		SERIALIZE_ERR ("meta parsing failed");
	}
	return ret;
}

typedef struct {
	const RVector/*<const RAnalAddrHintRecord>*/ *addr_hints;
	const char *arch;
	int bits;
	bool arch_set;
	bool bits_set;
} HintsAtAddr;

static void hints_at_addr_kv_free(HtUPKv *kv) {
	free (kv->value);
}

static HintsAtAddr *hints_at_addr(HtUP *acc, ut64 addr) {
	HintsAtAddr *h = ht_up_find (acc, addr, NULL);
	if (h) {
		return h;
	}
	h = R_NEW0 (HintsAtAddr);
	if (!h) {
		return NULL;
	}
	ht_up_insert (acc, addr, h);
	return h;
}

static bool addr_hint_acc_cb(ut64 addr, const RVector/*<const RAnalAddrHintRecord>*/ *records, void *user) {
	HintsAtAddr *h = hints_at_addr (user, addr);
	if (!h) {
		return false;
	}
	h->addr_hints = records;
	return true;
}

static bool arch_hint_acc_cb(ut64 addr, R_NULLABLE const char *arch, void *user) {
	HintsAtAddr *h = hints_at_addr (user, addr);
	if (!h) {
		return false;
	}
	h->arch = arch;
	h->arch_set = true;
	return true;
}

static bool bits_hint_acc_cb(ut64 addr, int bits, void *user) {
	HintsAtAddr *h = hints_at_addr (user, addr);
	if (!h) {
		return false;
	}
	h->bits = bits;
	h->bits_set = true;
	return true;
}

static bool hints_acc_store_cb(void *user, const ut64 addr, const void *v) {
	const HintsAtAddr *h = v;
	char key[0x20];
	if (snprintf (key, sizeof (key), "0x%"PFMT64x, addr) < 0) {
		return false;
	}
	Sdb *db = user;
	PJ *j = pj_new();
	if (!j) {
		return false;
	}
	pj_o (j);
	if (h->arch_set) {
		pj_k (j, "arch");
		if (h->arch) {
			pj_s (j, h->arch);
		} else {
			pj_null (j);
		}
	}
	if (h->bits_set) {
		pj_ki (j, "bits", h->bits);
	}
	if (h->addr_hints) {
		RAnalAddrHintRecord *record;
		r_vector_foreach (h->addr_hints, record) {
			switch (record->type) {
			case R_ANAL_ADDR_HINT_TYPE_IMMBASE:
				pj_ki (j, "immbase", record->immbase);
				break;
			case R_ANAL_ADDR_HINT_TYPE_JUMP:
				pj_kn (j, "jump", record->jump);
				break;
			case R_ANAL_ADDR_HINT_TYPE_FAIL:
				pj_kn (j, "fail", record->fail);
				break;
			case R_ANAL_ADDR_HINT_TYPE_STACKFRAME:
				pj_kn (j, "frame", record->stackframe);
				break;
			case R_ANAL_ADDR_HINT_TYPE_PTR:
				pj_kn (j, "ptr", record->ptr);
				break;
			case R_ANAL_ADDR_HINT_TYPE_NWORD:
				pj_ki (j, "nword", record->nword);
				break;
			case R_ANAL_ADDR_HINT_TYPE_RET:
				pj_kn (j, "ret", record->retval);
				break;
			case R_ANAL_ADDR_HINT_TYPE_NEW_BITS:
				pj_ki (j, "newbits", record->newbits);
				break;
			case R_ANAL_ADDR_HINT_TYPE_SIZE:
				pj_kn (j, "size", record->size);
				break;
			case R_ANAL_ADDR_HINT_TYPE_SYNTAX:
				pj_ks (j, "syntax", record->syntax);
				break;
			case R_ANAL_ADDR_HINT_TYPE_OPTYPE:
				pj_ki (j, "optype", record->optype);
				break;
			case R_ANAL_ADDR_HINT_TYPE_OPCODE:
				pj_ks (j, "opcode", record->opcode);
				break;
			case R_ANAL_ADDR_HINT_TYPE_TYPE_OFFSET:
				pj_ks (j, "toff", record->type_offset);
				break;
			case R_ANAL_ADDR_HINT_TYPE_ESIL:
				pj_ks (j, "esil", record->esil);
				break;
			case R_ANAL_ADDR_HINT_TYPE_HIGH:
				pj_kb (j, "high", true);
				break;
			case R_ANAL_ADDR_HINT_TYPE_VAL:
				pj_kn (j, "val", record->val);
				break;
			}
		}
	}
	pj_end (j);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
	return true;
}

R_API void r_serialize_anal_hints_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	HtUP/*<HintsAtAddr *>*/ *acc = ht_up_new (NULL, hints_at_addr_kv_free, NULL);
	r_anal_addr_hints_foreach (anal, addr_hint_acc_cb, acc);
	r_anal_arch_hints_foreach (anal, arch_hint_acc_cb, acc);
	r_anal_bits_hints_foreach (anal, bits_hint_acc_cb, acc);
	ht_up_foreach (acc, hints_acc_store_cb, db);
	ht_up_free (acc);
}

enum {
	HINTS_FIELD_ARCH,
	HINTS_FIELD_BITS,
	HINTS_FIELD_IMMBASE,
	HINTS_FIELD_JUMP,
	HINTS_FIELD_FAIL,
	HINTS_FIELD_STACKFRAME,
	HINTS_FIELD_PTR,
	HINTS_FIELD_NWORD,
	HINTS_FIELD_RET,
	HINTS_FIELD_NEW_BITS,
	HINTS_FIELD_SIZE,
	HINTS_FIELD_SYNTAX,
	HINTS_FIELD_OPTYPE,
	HINTS_FIELD_OPCODE,
	HINTS_FIELD_TYPE_OFFSET,
	HINTS_FIELD_ESIL,
	HINTS_FIELD_HIGH,
	HINTS_FIELD_VAL
};

typedef struct {
	RAnal *anal;
	KeyParser *parser;
} HintsLoadCtx;

static bool hints_load_cb(void *user, const char *k, const char *v) {
	HintsLoadCtx *ctx = user;
	RAnal *anal = ctx->anal;

	errno = 0;
	ut64 addr = strtoull (k, NULL, 0);
	if (errno) {
		return false;
	}

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_OBJECT) {
		free (json_str);
		return false;
	}

	const RJson *child;
	KEY_PARSER_JSON (ctx->parser, json, child, {
		case HINTS_FIELD_ARCH:
			r_anal_hint_set_arch (anal, addr, child->type == R_JSON_STRING ? child->str_value : NULL);
			break;
		case HINTS_FIELD_BITS:
			r_anal_hint_set_bits (anal, addr, child->type == R_JSON_INTEGER ? (int)child->num.s_value : 0);
			break;
		case HINTS_FIELD_IMMBASE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_immbase (anal, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_JUMP:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_jump (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_FAIL:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_fail (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_STACKFRAME:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_stackframe (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_PTR:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_pointer (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_NWORD:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_nword (anal, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_RET:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_ret (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_NEW_BITS:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_newbits (anal, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_SIZE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_size (anal, addr, child->num.u_value);
			break;
		case HINTS_FIELD_SYNTAX:
			if (child->type != R_JSON_STRING) {
				break;
			}
			r_anal_hint_set_syntax (anal, addr, child->str_value);
			break;
		case HINTS_FIELD_OPTYPE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_type (anal, addr, (int)child->num.s_value);
			break;
		case HINTS_FIELD_OPCODE:
			if (child->type != R_JSON_STRING) {
				break;
			}
			r_anal_hint_set_opcode (anal, addr, child->str_value);
			break;
		case HINTS_FIELD_TYPE_OFFSET:
			if (child->type != R_JSON_STRING) {
				break;
			}
			r_anal_hint_set_offset (anal, addr, child->str_value);
			break;
		case HINTS_FIELD_ESIL:
			if (child->type != R_JSON_STRING) {
				break;
			}
			r_anal_hint_set_esil (anal, addr, child->str_value);
			break;
		case HINTS_FIELD_HIGH:
			if (child->type != R_JSON_BOOLEAN || !child->num.u_value) {
				break;
			}
			r_anal_hint_set_high (anal, addr);
			break;
		case HINTS_FIELD_VAL:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			r_anal_hint_set_val (anal, addr, child->num.u_value);
			break;
		default:
			break;
	})

	r_json_free (json);
	free (json_str);

	return true;
resor:
	r_json_free (json);
	free (json_str);
	return false;
}

R_API bool r_serialize_anal_hints_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	HintsLoadCtx ctx = {
		.anal = anal,
		.parser = key_parser_new (),
	};
	bool ret;
	if (!ctx.parser) {
		SERIALIZE_ERR ("parser init failed");
		ret = false;
		goto beach;
	}
	key_parser_add (ctx.parser, "arch", HINTS_FIELD_ARCH);
	key_parser_add (ctx.parser, "bits", HINTS_FIELD_BITS);
	key_parser_add (ctx.parser, "immbase", HINTS_FIELD_IMMBASE);
	key_parser_add (ctx.parser, "jump", HINTS_FIELD_JUMP);
	key_parser_add (ctx.parser, "fail", HINTS_FIELD_FAIL);
	key_parser_add (ctx.parser, "frame", HINTS_FIELD_STACKFRAME);
	key_parser_add (ctx.parser, "ptr", HINTS_FIELD_PTR);
	key_parser_add (ctx.parser, "nword", HINTS_FIELD_NWORD);
	key_parser_add (ctx.parser, "ret", HINTS_FIELD_RET);
	key_parser_add (ctx.parser, "newbits", HINTS_FIELD_NEW_BITS);
	key_parser_add (ctx.parser, "size", HINTS_FIELD_SIZE);
	key_parser_add (ctx.parser, "syntax", HINTS_FIELD_SYNTAX);
	key_parser_add (ctx.parser, "optype", HINTS_FIELD_OPTYPE);
	key_parser_add (ctx.parser, "opcode", HINTS_FIELD_OPCODE);
	key_parser_add (ctx.parser, "toff", HINTS_FIELD_TYPE_OFFSET);
	key_parser_add (ctx.parser, "esil", HINTS_FIELD_ESIL);
	key_parser_add (ctx.parser, "high", HINTS_FIELD_HIGH);
	key_parser_add (ctx.parser, "val", HINTS_FIELD_VAL);
	ret = sdb_foreach (db, hints_load_cb, &ctx);
	if (!ret) {
		SERIALIZE_ERR ("hints parsing failed");
	}
beach:
	key_parser_free (ctx.parser);
	return ret;
}

R_API void r_serialize_anal_classes_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	sdb_copy (anal->sdb_classes, db);
}

R_API bool r_serialize_anal_classes_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	if (!sdb_ns (db, "attrs", false)) {
		SERIALIZE_ERR ("missing attrs namespace");
		return false;
	}
	sdb_reset (anal->sdb_classes);
	sdb_reset (anal->sdb_classes_attrs);
	sdb_copy (db, anal->sdb_classes);
	return true;
}

R_API void r_serialize_anal_types_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	sdb_copy (anal->sdb_types, db);
}

R_API bool r_serialize_anal_types_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	sdb_reset (anal->sdb_types);
	sdb_copy (db, anal->sdb_types);
	return true;
}

R_API void r_serialize_anal_sign_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	sdb_copy (anal->sdb_zigns, db);
	r_serialize_spaces_save (sdb_ns (db, "spaces", true), &anal->zign_spaces);
}

R_API bool r_serialize_anal_sign_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	sdb_reset (anal->sdb_zigns);
	sdb_copy (db, anal->sdb_zigns);
	Sdb *spaces_db = sdb_ns (db, "spaces", false);
	if (!spaces_db) {
		SERIALIZE_ERR ("missing spaces namespace");
		return false;
	}
	if (!r_serialize_spaces_load (spaces_db, &anal->zign_spaces, false, res)) {
		return false;
	}
	return true;
}

R_API void r_serialize_anal_imports_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	PJ *j = pj_new ();
	if (!j) {
		return;
	}
	pj_a (j);
	RListIter *it;
	const char *imp;
	r_list_foreach (anal->imports, it, imp) {
		pj_s (j, imp);
	}
	pj_end (j);
	sdb_set (db, "imports", pj_string (j), 0);
	pj_free (j);
}

R_API bool r_serialize_anal_imports_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	char *json_str = sdb_get (db, "imports", 0);
	if (!json_str) {
		SERIALIZE_ERR ("missing imports key");
		return false;
	}
	RJson *j = r_json_parse (json_str);
	bool ret = false;
	if (!j) {
		SERIALIZE_ERR ("invalid imports json");
		goto beach;
	}
	if (j->type != R_JSON_ARRAY) {
		SERIALIZE_ERR ("imports is not an array");
		goto beach;
	}
	RJson *child;
	for (child = j->children.first; child; child = child->next) {
		if (child->type != R_JSON_STRING) {
			continue;
		}
		r_anal_add_import (anal, child->str_value);
	}
	ret = true;
beach:
	r_json_free (j);
	free (json_str);
	return ret;
}

R_API void r_serialize_anal_pin_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	sdb_copy (anal->sdb_pins, db);
}

R_API bool r_serialize_anal_pin_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	sdb_copy (db, anal->sdb_pins);
	return true;
}

R_API void r_serialize_anal_cc_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	sdb_copy (anal->sdb_cc, db);
}

R_API bool r_serialize_anal_cc_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	sdb_copy (db, anal->sdb_cc);
	return true;
}

R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
	r_serialize_anal_xrefs_save (sdb_ns (db, "xrefs", true), anal);
	r_serialize_anal_blocks_save (sdb_ns (db, "blocks", true), anal);
	r_serialize_anal_functions_save (sdb_ns (db, "functions", true), anal);
	r_serialize_anal_meta_save (sdb_ns (db, "meta", true), anal);
	r_serialize_anal_hints_save (sdb_ns (db, "hints", true), anal);
	r_serialize_anal_classes_save (sdb_ns (db, "classes", true), anal);
	r_serialize_anal_types_save (sdb_ns (db, "types", true), anal);
	r_serialize_anal_sign_save (sdb_ns (db, "zigns", true), anal);
	r_serialize_anal_imports_save (db, anal);
	r_serialize_anal_pin_save (sdb_ns (db, "pins", true), anal);
	r_serialize_anal_cc_save (sdb_ns (db, "cc", true), anal);
}

R_API bool r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	bool ret = false;
	RSerializeAnalDiffParser diff_parser = r_serialize_anal_diff_parser_new ();
	if (!diff_parser) {
		goto beach;
	}

	r_anal_purge (anal);

	Sdb *subdb;
#define SUB(ns, call) SUB_DO(ns, call, goto beach;)
	SUB ("xrefs", r_serialize_anal_xrefs_load (subdb, anal, res));

	SUB ("blocks", r_serialize_anal_blocks_load (subdb, anal, diff_parser, res));
	// All bbs have ref=1 now
	SUB ("functions", r_serialize_anal_functions_load (subdb, anal, diff_parser, res));
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

	SUB ("meta", r_serialize_anal_meta_load (subdb, anal, res));
	SUB ("hints", r_serialize_anal_hints_load (subdb, anal, res));
	SUB ("classes", r_serialize_anal_classes_load (subdb, anal, res));
	SUB ("types", r_serialize_anal_types_load (subdb, anal, res));
	SUB ("zigns", r_serialize_anal_sign_load (subdb, anal, res));
	if (!r_serialize_anal_imports_load (db, anal, res)) {
		goto beach;
	}
	SUB ("pins", r_serialize_anal_pin_load (subdb, anal, res));
	SUB ("cc", r_serialize_anal_cc_load (subdb, anal, res));

	ret = true;
beach:
	r_serialize_anal_diff_parser_free (diff_parser);
	return ret;
}
