
#include <r_serialize.h>
#include "minunit.h"
#include "test_utils.h"

#include "test_anal_block_invars.inl"

bool test_anal_diff_save() {
	RAnalDiff *diff = r_anal_diff_new ();

	PJ *j = pj_new ();
	r_serialize_anal_diff_save (j, diff);
	mu_assert_streq (pj_string (j), "{}", "empty diff");
	pj_free (j);

	diff->name = strdup (PERTURBATOR_JSON);
	diff->dist = 42.3;
	diff->addr = 0x1337;
	diff->type = R_ANAL_DIFF_TYPE_MATCH;
	diff->size = 0x4242;
	j = pj_new ();
	r_serialize_anal_diff_save (j, diff);
	mu_assert_streq (pj_string (j), "{\"type\":\"m\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}", "full diff");
	pj_free (j);

	diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
	j = pj_new ();
	r_serialize_anal_diff_save (j, diff);
	mu_assert_streq (pj_string (j), "{\"type\":\"u\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}", "full unmatch diff");
	pj_free (j);

	r_anal_diff_free (diff);
	mu_end;
}

bool test_anal_diff_load() {
	RSerializeAnalDiffParser parser = r_serialize_anal_diff_parser_new ();

	char *str = strdup ("{}");
	const nx_json *json = nx_json_parse_utf8 (str);
	RAnalDiff *diff = r_serialize_anal_diff_load (parser, json);
	nx_json_free (json);
	free (str);
	mu_assert_notnull (diff, "diff");
	mu_assert_eq (diff->addr, UT64_MAX, "addr");
	mu_assert_eq (diff->size, 0, "size");
	mu_assert_eq (diff->type, R_ANAL_DIFF_TYPE_NULL, "type");
	mu_assert_eq (diff->dist, 0.0, "dist");
	mu_assert_null (diff->name, "name");
	r_anal_diff_free (diff);

	str = strdup ("{\"type\":\"m\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}");
	json = nx_json_parse_utf8 (str);
	diff = r_serialize_anal_diff_load (parser, json);
	nx_json_free (json);
	free (str);
	mu_assert_notnull (diff, "diff");
	mu_assert_eq (diff->addr, 0x1337, "addr");
	mu_assert_eq (diff->size, 0x4242, "size");
	mu_assert_eq (diff->type, R_ANAL_DIFF_TYPE_MATCH, "type");
	mu_assert_eq (diff->dist, 42.3, "dist");
	mu_assert_streq (diff->name, PERTURBATOR_JSON, "name");
	r_anal_diff_free (diff);

	str = strdup ("{\"type\":\"u\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}");
	json = nx_json_parse_utf8 (str);
	diff = r_serialize_anal_diff_load (parser, json);
	nx_json_free (json);
	free (str);
	mu_assert_notnull (diff, "diff");
	mu_assert_eq (diff->addr, 0x1337, "addr");
	mu_assert_eq (diff->size, 0x4242, "size");
	mu_assert_eq (diff->type, R_ANAL_DIFF_TYPE_UNMATCH, "type");
	mu_assert_eq (diff->dist, 42.3, "dist");
	mu_assert_streq (diff->name, PERTURBATOR_JSON, "name");
	r_anal_diff_free (diff);

	r_serialize_anal_diff_parser_free (parser);
	mu_end;
}

bool test_anal_switch_op_save() {
	RAnalSwitchOp *op = r_anal_switch_op_new (1337, 42, 45, 46);

	PJ *j = pj_new ();
	r_serialize_anal_switch_op_save (j, op);
	mu_assert_streq (pj_string (j), "{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[]}", "empty switch");
	pj_free (j);

	r_anal_switch_op_add_case (op, 1339, 42, 0xdead);
	r_anal_switch_op_add_case (op, 1340, 43, 0xbeef);
	j = pj_new ();
	r_serialize_anal_switch_op_save (j, op);
	mu_assert_streq (pj_string (j), "{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[{\"addr\":1339,\"jump\":57005,\"value\":42},{\"addr\":1340,\"jump\":48879,\"value\":43}]}", "full switch");
	pj_free (j);

	r_anal_switch_op_free (op);
	mu_end;
}

bool test_anal_switch_op_load() {
	char *str = strdup ("{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[]}");
	const nx_json *json = nx_json_parse_utf8 (str);
	RAnalSwitchOp *sop = r_serialize_anal_switch_op_load (json);
	nx_json_free (json);
	free (str);
	mu_assert_notnull (sop, "sop");
	mu_assert_eq (sop->addr, 1337, "addr");
	mu_assert_eq (sop->min_val, 42, "min val");
	mu_assert_eq (sop->max_val, 45, "max val");
	mu_assert_eq (sop->def_val, 46, "def val");
	mu_assert (r_list_empty (sop->cases), "no cases");
	r_anal_switch_op_free (sop);

	str = strdup("{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[{\"addr\":1339,\"jump\":57005,\"value\":42},{\"addr\":1340,\"jump\":48879,\"value\":43}]}");
	json = nx_json_parse_utf8 (str);
	sop = r_serialize_anal_switch_op_load (json);
	nx_json_free (json);
	free (str);
	mu_assert_notnull (sop, "sop");
	mu_assert_eq (sop->addr, 1337, "addr");
	mu_assert_eq (sop->min_val, 42, "min val");
	mu_assert_eq (sop->max_val, 45, "max val");
	mu_assert_eq (sop->def_val, 46, "def val");
	mu_assert_eq (r_list_length (sop->cases), 2, "cases count");
	RAnalCaseOp *cop = r_list_get_n (sop->cases, 0);
	mu_assert_eq (cop->addr, 1339, "addr");
	mu_assert_eq (cop->jump, 0xdead, "jump");
	mu_assert_eq (cop->value, 42, "value");
	cop = r_list_get_n (sop->cases, 1);
	mu_assert_eq (cop->addr, 1340, "addr");
	mu_assert_eq (cop->jump, 0xbeef, "jump");
	mu_assert_eq (cop->value, 43, "value");
	r_anal_switch_op_free (sop);

	mu_end;
}

Sdb *blocks_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x539", "{\"size\":42}", 0);
	sdb_set (db, "0x4d2", "{\"size\":32,\"jump\":4883,\"fail\":16915,\"traced\":true,\"folded\":true,\"colorize\":16711680,\"fingerprint\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"diff\":{\"addr\":54123},\"switch_op\":{\"addr\":49232,\"min\":3,\"max\":5,\"def\":7,\"cases\":[]},\"ninstr\":3,\"op_pos\":[4,7],\"stackptr\":43,\"parent_stackptr\":57,\"cmpval\":3735928559,\"cmpreg\":\"rax\"}", 0);
	return db;
}

bool test_anal_block_save() {
	RAnal *anal = r_anal_new ();

	r_anal_create_block (anal, 1337, 42);

	RAnalBlock *block = r_anal_create_block (anal, 1234, 32);
	block->jump = 0x1313;
	block->fail = 0x4213;
	block->traced = true;
	block->folded = true;
	block->colorize = 0xff0000;
	block->fingerprint = malloc (block->size);
	ut8 v;
	for (v = 0; v < block->size; v++) {
		block->fingerprint[v] = v;
	}
	block->diff = r_anal_diff_new ();
	block->diff->addr = 54123;
	block->switch_op = r_anal_switch_op_new (49232, 3, 5, 7);
	block->ninstr = 3;
	mu_assert ("enough size for op_pos test", block->op_pos_size >= 2); // if this fails, just change the test
	block->op_pos[0] = 4;
	block->op_pos[1] = 7;
	block->stackptr = 43;
	block->parent_stackptr = 57;
	block->cmpval = 0xdeadbeef;
	block->cmpreg = "rax";

	Sdb *db = sdb_new0 ();
	r_serialize_anal_blocks_save (db, anal);

	Sdb *expected = blocks_ref_db ();
	assert_sdb_eq (db, expected, "anal blocks save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_block_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = blocks_ref_db ();
	RSerializeAnalDiffParser diff_parser = r_serialize_anal_diff_parser_new ();
	bool succ = r_serialize_anal_blocks_load (db, anal, diff_parser, NULL);
	mu_assert ("load success", succ);

	RAnalBlock *a = NULL;
	RAnalBlock *b = NULL;
	size_t count = 0;

	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		count++;
		if (block->addr == 1337) {
			a = block;
		} else if (block->addr == 1234)  {
			b = block;
		}
	}
	mu_assert_eq (count, 2, "loaded blocks count");

	mu_assert_notnull (a, "block a");
	mu_assert_eq (a->size, 42, "size");
	mu_assert_eq (a->jump, UT64_MAX, "jump");
	mu_assert_eq (a->fail, UT64_MAX, "fail");
	mu_assert ("traced", !a->traced);
	mu_assert ("folded", !a->folded);
	mu_assert_eq (a->colorize, 0, "colorize");
	mu_assert_null (a->fingerprint, "fingerprint");
	mu_assert_null (a->diff, "diff");
	mu_assert_null (a->switch_op, "switch op");
	mu_assert_eq (a->ninstr, 0, "ninstr");
	mu_assert_eq (a->stackptr, 0, "stackptr");
	mu_assert_eq (a->parent_stackptr, INT_MAX, "parent_stackptr");
	mu_assert_eq (a->cmpval, UT64_MAX, "cmpval");
	mu_assert_null (a->cmpreg, "cmpreg");

	mu_assert_notnull (b, "block b");
	mu_assert_eq (b->size, 32, "size");
	mu_assert_eq (b->jump, 0x1313, "jump");
	mu_assert_eq (b->fail, 0x4213, "fail");
	mu_assert ("traced", b->traced);
	mu_assert ("folded", b->folded);
	mu_assert_eq (b->colorize, 0xff0000, "colorize");
	mu_assert_notnull (b->fingerprint, "fingerprint");
	mu_assert_memeq (b->fingerprint,
			(const ut8 *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10"
			"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32, "fingerprint");
	mu_assert_notnull (b->diff, "diff");
	mu_assert_eq (b->diff->addr, 54123, "diff addr"); // diff is covered in detail by its own tests
	mu_assert_notnull (b->switch_op, "switch op");
	mu_assert_eq (b->switch_op->addr, 49232, "switch op addr"); // switch_op is covered in detail by its own tests
	mu_assert_eq (b->ninstr, 3, "ninstr");
	mu_assert ("op_pos_size", b->op_pos_size >= b->ninstr - 1);
	mu_assert_eq (b->op_pos[0], 4, "op_pos[0]");
	mu_assert_eq (b->op_pos[1], 7, "op_pos[1]");
	mu_assert_eq (b->stackptr, 43, "stackptr");
	mu_assert_eq (b->parent_stackptr, 57, "parent_stackptr");
	mu_assert_eq (b->cmpval, 0xdeadbeef, "cmpval");
	mu_assert_ptreq (b->cmpreg, r_str_constpool_get (&anal->constpool, "rax"), "cmpreg from pool");

	r_anal_free (anal);
	anal = r_anal_new ();
	// This could lead to a buffer overflow if unchecked:
	sdb_set (db, "0x539", "{\"size\":42,\"ninstr\":4,\"op_pos\":[4,7]}", 0);
	succ = r_serialize_anal_blocks_load (db, anal, diff_parser, NULL);
	mu_assert ("reject invalid op_pos array length", !succ);

	r_anal_free (anal);
	anal = r_anal_new ();
	// This could lead to a buffer overflow if unchecked:
	sdb_set (db, "0x539", "{\"size\":33,\"fingerprint\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\"}", 0);
	succ = r_serialize_anal_blocks_load (db, anal, diff_parser, NULL);
	mu_assert ("reject invalid fingerprint size", !succ);

	sdb_free (db);
	r_anal_free (anal);
	r_serialize_anal_diff_parser_free (diff_parser);
	mu_end;
}

Sdb *functions_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x4d2", "{\"name\":\"effekt\",\"type\":1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"pure\":true,\"diff\":{},\"bbs\":[1337]}", 0);
	sdb_set (db, "0xbeef", "{\"name\":\"eskapist\",\"bits\":32,\"type\":16,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[]}", 0);
	sdb_set (db, "0x539", "{\"name\":\"hirsch\",\"bits\":16,\"type\":0,\"cc\":\"fancycall\",\"stack\":42,\"maxstack\":123,\"ninstr\":13,\"folded\":true,\"bp_frame\":true,\"fingerprint\":\"AAECAwQFBgcICQoLDA0ODw==\",\"diff\":{\"addr\":4321},\"bbs\":[1337,1234],\"imports\":[\"earth\",\"rise\"]}", 0);
	sdb_set (db, "0xdead", "{\"name\":\"agnosie\",\"bits\":32,\"type\":8,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[]}", 0);
	sdb_set (db, "0xc0ffee", "{\"name\":\"lifnej\",\"bits\":32,\"type\":32,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[]}", 0);
	sdb_set (db, "0x1092", "{\"name\":\"hiberno\",\"bits\":32,\"type\":2,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"diff\":{},\"bbs\":[]}", 0);
	sdb_set (db, "0x67932", "{\"name\":\"anamnesis\",\"bits\":32,\"type\":4,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"noreturn\":true,\"diff\":{},\"bbs\":[]}", 0);
	sdb_set (db, "0x31337", "{\"name\":\"aldebaran\",\"bits\":32,\"type\":-1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[]}", 0);
	return db;
}

bool test_anal_function_save() {
	RAnal *anal = r_anal_new ();

	RAnalBlock *ba = r_anal_create_block (anal, 1337, 42);
	RAnalBlock *bb = r_anal_create_block (anal, 1234, 32);

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, r_anal_diff_new ());
	r_anal_function_add_block (f, ba);
	r_anal_function_add_block (f, bb);
	f->bits = 16;
	f->cc = r_str_constpool_get (&anal->constpool, "fancycall");
	f->stack = 42;
	f->maxstack = 123;
	f->ninstr = 13;
	f->folded = true;
	f->fingerprint_size = 0x10;
	f->fingerprint = malloc (f->fingerprint_size);
	ut8 v;
	for (v = 0; v < f->fingerprint_size; v++) {
		f->fingerprint[v] = v;
	}
	f->diff->addr = 4321;
	f->imports = r_list_newf (free);
	r_list_push (f->imports, strdup ("earth"));
	r_list_push (f->imports, strdup ("rise"));

	f = r_anal_create_function (anal, "effekt", 1234, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function_add_block (f, ba);
	f->is_pure = true;
	f->bits = 0;

	f = r_anal_create_function (anal, "hiberno", 4242, R_ANAL_FCN_TYPE_LOC, NULL);
	f->bp_frame = false;

	f = r_anal_create_function (anal, "anamnesis", 424242, R_ANAL_FCN_TYPE_SYM, NULL);
	f->is_noreturn = true;

	r_anal_create_function (anal, "agnosie", 0xdead, R_ANAL_FCN_TYPE_IMP, NULL);
	r_anal_create_function (anal, "eskapist", 0xbeef, R_ANAL_FCN_TYPE_INT, NULL);
	r_anal_create_function (anal, "lifnej", 0xc0ffee, R_ANAL_FCN_TYPE_ROOT, NULL);
	r_anal_create_function (anal, "aldebaran", 0x31337, R_ANAL_FCN_TYPE_ANY, NULL);

	r_anal_block_unref (ba);
	r_anal_block_unref (bb);

	Sdb *db = sdb_new0 ();
	r_serialize_anal_functions_save (db, anal);

	Sdb *expected = functions_ref_db ();
	assert_sdb_eq (db, expected, "functions save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_function_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = functions_ref_db ();
	RSerializeAnalDiffParser diff_parser = r_serialize_anal_diff_parser_new ();

	RAnalBlock *ba = r_anal_create_block (anal, 1337, 42);
	RAnalBlock *bb = r_anal_create_block (anal, 1234, 32);

	bool succ = r_serialize_anal_functions_load (db, anal, diff_parser, NULL);
	mu_assert ("load success", succ);

	mu_assert_eq (ba->ref, 3, "ba refs");
	mu_assert_eq (bb->ref, 2, "bb refs");
	r_anal_block_unref (ba);
	r_anal_block_unref (bb);

	mu_assert_eq (r_list_length (anal->fcns), 8, "loaded fcn count");

	RAnalFunction *f = r_anal_get_function_at (anal, 1337);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "hirsch", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_NULL, "type");
	mu_assert_eq (r_list_length (f->bbs), 2, "bbs count");
	mu_assert ("bb", r_list_contains (f->bbs, ba));
	mu_assert ("bb", r_list_contains (f->bbs, bb));
	mu_assert_eq (f->bits, 16, "bits");
	mu_assert_ptreq (f->cc, r_str_constpool_get (&anal->constpool, "fancycall"), "cc");
	mu_assert_eq (f->stack, 42, "stack");
	mu_assert_eq (f->maxstack, 123, "maxstack");
	mu_assert_eq (f->ninstr, 13, "ninstr");
	mu_assert ("folded", f->folded);
	mu_assert ("pure", !f->is_pure);
	mu_assert ("noreturn", !f->is_noreturn);
	mu_assert ("bp_frame", f->bp_frame);
	mu_assert_eq (f->fingerprint_size, 0x10, "fingerprint size");
	mu_assert_memeq (f->fingerprint, (const ut8 *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f", 0x10, "fingerprint");
	mu_assert_notnull (f->diff, "diff");
	mu_assert_eq (f->diff->addr, 4321, "diff addr"); // diff is covered in detail by its own tests
	mu_assert_notnull (f->imports, "imports");
	mu_assert_eq (r_list_length (f->imports), 2, "imports count");
	mu_assert_streq (r_list_get_n (f->imports, 0), "earth", "import");
	mu_assert_streq (r_list_get_n (f->imports, 1), "rise", "import");

	f = r_anal_get_function_at (anal, 1234);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "effekt", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_FCN, "type");
	mu_assert_eq (r_list_length (f->bbs), 1, "bbs count");
	mu_assert ("bb", r_list_contains (f->bbs, ba));
	mu_assert_eq (f->bits, 0, "bits");
	mu_assert_null (f->cc, "cc");
	mu_assert_eq (f->stack, 0, "stack");
	mu_assert_eq (f->maxstack, 0, "maxstack");
	mu_assert_eq (f->ninstr, 0, "ninstr");
	mu_assert ("folded", !f->folded);
	mu_assert ("pure", f->is_pure);
	mu_assert ("noreturn", !f->is_noreturn);
	mu_assert ("bp_frame", f->bp_frame);
	mu_assert_null (f->fingerprint, "fingerprint");
	mu_assert_notnull (f->diff, "diff");
	mu_assert_null (f->imports, "imports");

	f = r_anal_get_function_at (anal, 4242);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "hiberno", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_LOC, "type");
	mu_assert_eq (r_list_length (f->bbs), 0, "bbs count");
	mu_assert_eq (f->bits, 32, "bits");
	mu_assert_null (f->cc, "cc");
	mu_assert_eq (f->stack, 0, "stack");
	mu_assert_eq (f->maxstack, 0, "maxstack");
	mu_assert_eq (f->ninstr, 0, "ninstr");
	mu_assert ("folded", !f->folded);
	mu_assert ("pure", !f->is_pure);
	mu_assert ("noreturn", !f->is_noreturn);
	mu_assert ("bp_frame", !f->bp_frame);
	mu_assert_null (f->fingerprint, "fingerprint");
	mu_assert_notnull (f->diff, "diff");
	mu_assert_null (f->imports, "imports");

	f = r_anal_get_function_at (anal, 424242);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "anamnesis", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_SYM, "type");
	mu_assert_eq (r_list_length (f->bbs), 0, "bbs count");
	mu_assert_eq (f->bits, 32, "bits");
	mu_assert_null (f->cc, "cc");
	mu_assert_eq (f->stack, 0, "stack");
	mu_assert_eq (f->maxstack, 0, "maxstack");
	mu_assert_eq (f->ninstr, 0, "ninstr");
	mu_assert ("folded", !f->folded);
	mu_assert ("pure", !f->is_pure);
	mu_assert ("noreturn", f->is_noreturn);
	mu_assert ("bp_frame", f->bp_frame);
	mu_assert_null (f->fingerprint, "fingerprint");
	mu_assert_notnull (f->diff, "diff");
	mu_assert_null (f->imports, "imports");

	f = r_anal_get_function_at (anal, 0xdead);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "agnosie", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_IMP, "type");

	f = r_anal_get_function_at (anal, 0xbeef);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "eskapist", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_INT, "type");

	f = r_anal_get_function_at (anal, 0xc0ffee);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "lifnej", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_ROOT, "type");

	f = r_anal_get_function_at (anal, 0x31337);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "aldebaran", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_ANY, "type");

	sdb_free (db);
	r_anal_free (anal);
	r_serialize_anal_diff_parser_free (diff_parser);
	mu_end;
}

Sdb *vars_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x539", "{\"name\":\"hirsch\",\"bits\":64,\"type\":0,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[],"
		"\"vars\":["
		"{\"name\":\"arg_rax\",\"type\":\"int64_t\",\"kind\":\"r\",\"reg\":\"rax\",\"arg\":true,\"accs\":[{\"off\":3,\"type\":\"r\",\"sp\":42,\"reg\":\"rax\"},{\"off\":13,\"type\":\"rw\",\"sp\":13,\"reg\":\"rbx\"},{\"off\":23,\"type\":\"w\",\"sp\":123,\"reg\":\"rcx\"}]},"
		"{\"name\":\"var_sp\",\"type\":\"const char *\",\"kind\":\"s\",\"delta\":16,\"accs\":[{\"off\":3,\"type\":\"w\",\"sp\":321,\"reg\":\"rsp\"}]},"
		"{\"name\":\"var_bp\",\"type\":\"struct something\",\"kind\":\"b\",\"delta\":-16},"
		"{\"name\":\"arg_bp\",\"type\":\"uint64_t\",\"kind\":\"b\",\"delta\":16,\"arg\":true}]}", 0);
	return db;
}

bool test_anal_var_save() {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, r_anal_diff_new ());

	RRegItem *rax = r_reg_get (anal->reg, "rax", -1);
	RAnalVar *v = r_anal_function_set_var (f, rax->index, R_ANAL_VAR_KIND_REG, "int64_t", 0, true, "arg_rax");
	r_anal_var_set_access (v, "rax", 1340, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	r_anal_var_set_access (v, "rbx", 1350, R_ANAL_VAR_ACCESS_TYPE_READ | R_ANAL_VAR_ACCESS_TYPE_WRITE, 13);
	r_anal_var_set_access (v, "rcx", 1360, R_ANAL_VAR_ACCESS_TYPE_WRITE, 123);

	v = r_anal_function_set_var (f, 0x10, R_ANAL_VAR_KIND_SPV, "const char *", 0, false, "var_sp");
	r_anal_var_set_access (v, "rsp", 1340, R_ANAL_VAR_ACCESS_TYPE_WRITE, 321);

	r_anal_function_set_var (f, -0x10, R_ANAL_VAR_KIND_BPV, "struct something", 0, false, "var_bp");
	r_anal_function_set_var (f, 0x10, R_ANAL_VAR_KIND_BPV, "uint64_t", 0, true, "arg_bp");

	Sdb *db = sdb_new0 ();
	r_serialize_anal_functions_save (db, anal);

	Sdb *expected = vars_ref_db ();
	assert_sdb_eq (db, expected, "functions save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_var_load() {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	Sdb *db = vars_ref_db ();
	RSerializeAnalDiffParser diff_parser = r_serialize_anal_diff_parser_new ();

	bool succ = r_serialize_anal_functions_load (db, anal, diff_parser, NULL);
	mu_assert ("load success", succ);

	RAnalFunction *f = r_anal_get_function_at (anal, 1337);
	mu_assert_notnull (f, "function");

	mu_assert_eq (r_pvector_len (&f->vars), 4, "vars count");

	RRegItem *rax = r_reg_get (anal->reg, "rax", -1);
	RAnalVar *v = r_anal_function_get_var (f, R_ANAL_VAR_KIND_REG, rax->index);
	mu_assert_notnull (v, "var");
	mu_assert_streq (v->regname, "rax", "var regname");
	mu_assert_streq (v->name, "arg_rax", "var name");
	mu_assert_streq (v->type, "int64_t", "var type");
	mu_assert ("var arg", v->isarg);

	mu_assert_eq (v->accesses.len, 3, "accesses count");
	bool found[3] = { false, false, false };
	RAnalVarAccess *acc;
	r_vector_foreach (&v->accesses, acc) {
		if (acc->offset == 3 && acc->type == R_ANAL_VAR_ACCESS_TYPE_READ && acc->stackptr == 42 && !strcmp(acc->reg, "rax")) {
			found[0] = true;
		} else if (acc->offset == 13 && acc->type == (R_ANAL_VAR_ACCESS_TYPE_READ | R_ANAL_VAR_ACCESS_TYPE_WRITE)
				&& acc->stackptr == 13 && !strcmp(acc->reg, "rbx")) {
			found[1] = true;
		} else if (acc->offset == 23 && acc->type == R_ANAL_VAR_ACCESS_TYPE_WRITE
				&& acc->stackptr == 123 && !strcmp(acc->reg, "rcx")) {
			found[2] = true;
		}
	}
	mu_assert ("var accesses", found[0] && found[1] && found[2]);
	RPVector *used = r_anal_function_get_vars_used_at (f, 1340);
	mu_assert ("var used", r_pvector_contains (used, v));

	v = r_anal_function_get_var (f, R_ANAL_VAR_KIND_SPV, 0x10);
	mu_assert_notnull (v, "var");
	mu_assert_streq (v->name, "var_sp", "var name");
	mu_assert_streq (v->type, "const char *", "var type");
	mu_assert ("var arg", !v->isarg);
	mu_assert_eq (v->accesses.len, 1, "accesses count");
	acc = r_vector_index_ptr (&v->accesses, 0);
	mu_assert_eq (acc->offset, 3, "access offset");
	mu_assert_eq (acc->type, R_ANAL_VAR_ACCESS_TYPE_WRITE, "access type");
	mu_assert_eq (acc->stackptr, 321, "access stackptr");
	mu_assert_streq (acc->reg, "rsp", "access reg");
	mu_assert ("var used", r_pvector_contains (used, v)); // used at the same var as the reg one

	v = r_anal_function_get_var (f, R_ANAL_VAR_KIND_BPV, -0x10);
	mu_assert_notnull (v, "var");
	mu_assert_streq (v->name, "var_bp", "var name");
	mu_assert_streq (v->type, "struct something", "var type");
	mu_assert ("var arg", !v->isarg);
	mu_assert_eq (v->accesses.len, 0, "accesses count");

	v = r_anal_function_get_var (f, R_ANAL_VAR_KIND_BPV, 0x10);
	mu_assert_notnull (v, "var");
	mu_assert_streq (v->name, "arg_bp", "var name");
	mu_assert_streq (v->type, "uint64_t", "var type");
	mu_assert ("var arg", v->isarg);
	mu_assert_eq (v->accesses.len, 0, "accesses count");

	sdb_free (db);
	r_anal_free (anal);
	r_serialize_anal_diff_parser_free (diff_parser);
	mu_end;
}

Sdb *xrefs_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x29a", "[{\"to\":333,\"type\":\"s\"}]", 0);
	sdb_set (db, "0x1337", "[{\"to\":4242},{\"to\":4243,\"type\":\"c\"}]", 0);
	sdb_set (db, "0x2a", "[{\"to\":4321,\"type\":\"d\"}]", 0);
	sdb_set (db, "0x4d2", "[{\"to\":4243,\"type\":\"C\"}]", 0);
	return db;
}

bool test_anal_xrefs_save() {
	RAnal *anal = r_anal_new ();

	r_anal_xrefs_set (anal, 0x1337, 4242, R_ANAL_REF_TYPE_NULL);
	r_anal_xrefs_set (anal, 0x1337, 4243, R_ANAL_REF_TYPE_CODE);
	r_anal_xrefs_set (anal, 1234, 4243, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 42, 4321, R_ANAL_REF_TYPE_DATA);
	r_anal_xrefs_set (anal, 666, 333, R_ANAL_REF_TYPE_STRING);

	Sdb *db = sdb_new0 ();
	r_serialize_anal_xrefs_save (db, anal);

	Sdb *expected = xrefs_ref_db ();
	assert_sdb_eq (db, expected, "xrefs save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_xrefs_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = xrefs_ref_db ();

	bool succ = r_serialize_anal_xrefs_load (db, anal, NULL);
	mu_assert ("load success", succ);
	mu_assert_eq (r_anal_xrefs_count (anal), 5, "xrefs count");

	RList *xrefs = r_anal_xrefs_get_from (anal, 0x1337);
	mu_assert_eq (r_list_length (xrefs), 2, "xrefs from count");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->addr, 4242, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->at, 0x1337, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->type, R_ANAL_REF_TYPE_NULL, "xref type");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->addr, 4243, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->at, 0x1337, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->type, R_ANAL_REF_TYPE_CODE, "xref type");
	r_list_free (xrefs);

	xrefs = r_anal_xrefs_get_from (anal, 1234);
	mu_assert_eq (r_list_length (xrefs), 1, "xrefs from count");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->addr, 4243, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->at, 1234, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->type, R_ANAL_REF_TYPE_CALL, "xref type");
	r_list_free (xrefs);

	xrefs = r_anal_xrefs_get_from (anal, 42);
	mu_assert_eq (r_list_length (xrefs), 1, "xrefs from count");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->addr, 4321, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->at, 42, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->type, R_ANAL_REF_TYPE_DATA, "xref type");
	r_list_free (xrefs);

	xrefs = r_anal_xrefs_get_from (anal, 666);
	mu_assert_eq (r_list_length (xrefs), 1, "xrefs from count");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->addr, 333, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->at, 666, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->type, R_ANAL_REF_TYPE_STRING, "xref type");
	r_list_free (xrefs);

	xrefs = r_anal_xrefs_get (anal, 4243);
	mu_assert_eq (r_list_length (xrefs), 2, "xrefs to count");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->addr, 1234, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->at, 4243, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 0))->type, R_ANAL_REF_TYPE_CALL, "xref type");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->addr, 0x1337, "xref to");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->at, 4243, "xref addr");
	mu_assert_eq (((RAnalRef *)r_list_get_n (xrefs, 1))->type, R_ANAL_REF_TYPE_CODE, "xref type");
	r_list_free (xrefs);

	sdb_free (db);
	r_anal_free (anal);
	mu_end;
}

Sdb *meta_ref_db() {
	Sdb *db = sdb_new0 ();
	Sdb *spaces_db = sdb_ns (db, "spaces", true);
	sdb_set (spaces_db, "name", "CS", 0);
	sdb_set (spaces_db, "spacestack", "[\"*\"]", 0);
	sdb_set (sdb_ns (spaces_db, "spaces", true), "myspace", "s", 0);
	sdb_set(db, "0x20a0", "[{\"size\":32,\"type\":\"s\",\"subtype\":66,\"str\":\"utf32be\"}]", 0);
	sdb_set(db, "0x20c0", "[{\"size\":32,\"type\":\"s\",\"subtype\":103,\"str\":\"guess\"}]", 0);
	sdb_set(db, "0x1337",
			"[{\"size\":16,\"type\":\"d\"},"
			"{\"size\":17,\"type\":\"c\"},"
			"{\"size\":18,\"type\":\"s\",\"str\":\"some string\"},"
			"{\"size\":19,\"type\":\"f\"},"
			"{\"size\":20,\"type\":\"m\"},"
			"{\"size\":21,\"type\":\"h\"},"
			"{\"type\":\"C\",\"str\":\"some comment here\"},"
			"{\"size\":22,\"type\":\"r\"},"
			"{\"size\":23,\"type\":\"H\"},"
			"{\"size\":24,\"type\":\"t\"},"
			"{\"type\":\"C\",\"str\":\"comment in space\",\"space\":\"myspace\"}]", 0);
	sdb_set(db, "0x2000", "[{\"size\":32,\"type\":\"s\",\"subtype\":97,\"str\":\"latin1\"}]", 0);
	sdb_set(db, "0x2040", "[{\"size\":32,\"type\":\"s\",\"subtype\":117,\"str\":\"utf16le\"}]", 0);
	sdb_set(db, "0x2080", "[{\"size\":32,\"type\":\"s\",\"subtype\":98,\"str\":\"utf16be\"}]", 0);
	sdb_set(db, "0x2020", "[{\"size\":32,\"type\":\"s\",\"subtype\":56,\"str\":\"utf8\"}]", 0);
	sdb_set(db, "0x2060", "[{\"size\":32,\"type\":\"s\",\"subtype\":85,\"str\":\"utf32le\"}]", 0);
	return db;
}

bool test_anal_meta_save() {
	RAnal *anal = r_anal_new ();

	r_meta_set (anal, R_META_TYPE_DATA, 0x1337, 0x10, NULL);
	r_meta_set (anal, R_META_TYPE_CODE, 0x1337, 0x11, NULL);
	r_meta_set (anal, R_META_TYPE_STRING, 0x1337, 0x12, "some string");
	r_meta_set (anal, R_META_TYPE_FORMAT, 0x1337, 0x13, NULL);
	r_meta_set (anal, R_META_TYPE_MAGIC, 0x1337, 0x14, NULL);
	r_meta_set (anal, R_META_TYPE_HIDE, 0x1337, 0x15, NULL);
	r_meta_set (anal, R_META_TYPE_COMMENT, 0x1337, 1, "some comment here");
	r_meta_set (anal, R_META_TYPE_RUN, 0x1337, 0x16, NULL);
	r_meta_set (anal, R_META_TYPE_HIGHLIGHT, 0x1337, 0x17, NULL);
	r_meta_set (anal, R_META_TYPE_VARTYPE, 0x1337, 0x18, NULL);

	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_LATIN1, 0x2000, 0x20, "latin1");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF8, 0x2020, 0x20, "utf8");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF16LE, 0x2040, 0x20, "utf16le");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF32LE, 0x2060, 0x20, "utf32le");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF16BE, 0x2080, 0x20, "utf16be");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_UTF32BE, 0x20a0, 0x20, "utf32be");
	r_meta_set_with_subtype (anal, R_META_TYPE_STRING, R_STRING_ENC_GUESS, 0x20c0, 0x20, "guess");

	r_spaces_push (&anal->meta_spaces, "myspace");
	r_meta_set (anal, R_META_TYPE_COMMENT, 0x1337, 1, "comment in space");
	r_spaces_pop (&anal->meta_spaces);

	Sdb *db = sdb_new0 ();
	r_serialize_anal_meta_save (db, anal);

	Sdb *expected = meta_ref_db ();
	assert_sdb_eq (db, expected, "meta save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_meta_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = meta_ref_db ();

	bool succ = r_serialize_anal_meta_load (db, anal, NULL);
	mu_assert ("load success", succ);

	size_t count = 0;
	RAnalMetaItem *meta;
	RIntervalTreeIter it;
	r_interval_tree_foreach (&anal->meta, it, meta) {
		(void)meta;
		count++;
	}
	mu_assert_eq (count, 18, "meta count");

	ut64 size;
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_DATA, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x10, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_CODE, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x11, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x12, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_streq (meta->str, "some string", "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_FORMAT, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x13, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_MAGIC, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x14, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_HIDE, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x15, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_COMMENT, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 1, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_streq (meta->str, "some comment here", "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_RUN, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x16, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_HIGHLIGHT, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x17, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_VARTYPE, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x18, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_null (meta->str, "meta item string");

	r_spaces_push (&anal->meta_spaces, "myspace");
	meta = r_meta_get_at (anal, 0x1337, R_META_TYPE_COMMENT, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 1, "meta item size");
	mu_assert_eq (meta->subtype, 0, "meta item subtype");
	mu_assert_streq (meta->str, "comment in space", "meta item string");
	r_spaces_pop (&anal->meta_spaces);

	meta = r_meta_get_at (anal, 0x2000, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_LATIN1, "meta item subtype");
	mu_assert_streq (meta->str, "latin1", "meta item string");
	meta = r_meta_get_at (anal, 0x2020, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_UTF8, "meta item subtype");
	mu_assert_streq (meta->str, "utf8", "meta item string");
	meta = r_meta_get_at (anal, 0x2040, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_UTF16LE, "meta item subtype");
	mu_assert_streq (meta->str, "utf16le", "meta item string");
	meta = r_meta_get_at (anal, 0x2060, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_UTF32LE, "meta item subtype");
	mu_assert_streq (meta->str, "utf32le", "meta item string");
	meta = r_meta_get_at (anal, 0x2080, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_UTF16BE, "meta item subtype");
	mu_assert_streq (meta->str, "utf16be", "meta item string");
	meta = r_meta_get_at (anal, 0x20a0, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_UTF32BE, "meta item subtype");
	mu_assert_streq (meta->str, "utf32be", "meta item string");
	meta = r_meta_get_at (anal, 0x20c0, R_META_TYPE_STRING, &size);
	mu_assert_notnull (meta, "meta item");
	mu_assert_eq (size, 0x20, "meta item size");
	mu_assert_eq (meta->subtype, R_STRING_ENC_GUESS, "meta item subtype");
	mu_assert_streq (meta->str, "guess", "meta item string");

	sdb_free (db);
	r_anal_free (anal);
	mu_end;
}

Sdb *hints_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x1000", "{\"optype\":-2147483648}", 0);
	sdb_set (db, "0x1001", "{\"optype\":1073741824}", 0);
	sdb_set (db, "0x1002", "{\"optype\":536870912}", 0);
	sdb_set (db, "0x1003", "{\"optype\":268435456}", 0);
	sdb_set (db, "0x1004", "{\"optype\":134217728}", 0);
	sdb_set (db, "0x1005", "{\"optype\":0}", 0);
	sdb_set (db, "0x1006", "{\"optype\":1}", 0);
	sdb_set (db, "0x1007", "{\"optype\":2}", 0);
	sdb_set (db, "0x1008", "{\"optype\":268435458}", 0);
	sdb_set (db, "0x1009", "{\"optype\":134217730}", 0);
	sdb_set (db, "0x100a", "{\"optype\":402653186}", 0);
	sdb_set (db, "0x100b", "{\"optype\":-2147483647}", 0);
	sdb_set (db, "0x100c", "{\"optype\":-1879048191}", 0);
	sdb_set (db, "0x100d", "{\"optype\":536870913}", 0);
	sdb_set (db, "0x100e", "{\"optype\":-1610612735}", 0);
	sdb_set (db, "0x100f", "{\"optype\":-2147483646}", 0);
	sdb_set (db, "0x1010", "{\"optype\":3}", 0);
	sdb_set (db, "0x1011", "{\"optype\":4}", 0);
	sdb_set (db, "0x1012", "{\"optype\":268435460}", 0);
	sdb_set (db, "0x1013", "{\"optype\":134217732}", 0);
	sdb_set (db, "0x1014", "{\"optype\":402653188}", 0);
	sdb_set (db, "0x1015", "{\"optype\":-2147483645}", 0);
	sdb_set (db, "0x1016", "{\"optype\":-2147483644}", 0);
	sdb_set (db, "0x1017", "{\"optype\":5}", 0);
	sdb_set (db, "0x1018", "{\"optype\":-2147483643}", 0);
	sdb_set (db, "0x1019", "{\"optype\":6}", 0);
	sdb_set (db, "0x101a", "{\"optype\":7}", 0);
	sdb_set (db, "0x101b", "{\"optype\":8}", 0);
	sdb_set (db, "0x101c", "{\"optype\":9}", 0);
	sdb_set (db, "0x101d", "{\"optype\":-2147483639}", 0);
	sdb_set (db, "0x101e", "{\"optype\":10}", 0);
	sdb_set (db, "0x101f", "{\"optype\":11}", 0);
	sdb_set (db, "0x1020", "{\"optype\":-2147483637}", 0);
	sdb_set (db, "0x1021", "{\"optype\":12}", 0);
	sdb_set (db, "0x1022", "{\"optype\":268435468}", 0);
	sdb_set (db, "0x1023", "{\"optype\":13}", 0);
	sdb_set (db, "0x1024", "{\"optype\":14}", 0);
	sdb_set (db, "0x1025", "{\"optype\":15}", 0);
	sdb_set (db, "0x1026", "{\"optype\":16}", 0);
	sdb_set (db, "0x1027", "{\"optype\":17}", 0);
	sdb_set (db, "0x1028", "{\"optype\":18}", 0);
	sdb_set (db, "0x1029", "{\"optype\":19}", 0);
	sdb_set (db, "0x102a", "{\"optype\":20}", 0);
	sdb_set (db, "0x102b", "{\"optype\":21}", 0);
	sdb_set (db, "0x102c", "{\"optype\":22}", 0);
	sdb_set (db, "0x102d", "{\"optype\":23}", 0);
	sdb_set (db, "0x102e", "{\"optype\":24}", 0);
	sdb_set (db, "0x102f", "{\"optype\":25}", 0);
	sdb_set (db, "0x1030", "{\"optype\":26}", 0);
	sdb_set (db, "0x1031", "{\"optype\":27}", 0);
	sdb_set (db, "0x1032", "{\"optype\":28}", 0);
	sdb_set (db, "0x1033", "{\"optype\":29}", 0);
	sdb_set (db, "0x1034", "{\"optype\":30}", 0);
	sdb_set (db, "0x1035", "{\"optype\":31}", 0);
	sdb_set (db, "0x1036", "{\"optype\":32}", 0);
	sdb_set (db, "0x1037", "{\"optype\":33}", 0);
	sdb_set (db, "0x1038", "{\"optype\":34}", 0);
	sdb_set (db, "0x1039", "{\"optype\":35}", 0);
	sdb_set (db, "0x103a", "{\"optype\":36}", 0);
	sdb_set (db, "0x103b", "{\"optype\":37}", 0);
	sdb_set (db, "0x103c", "{\"optype\":38}", 0);
	sdb_set (db, "0x103d", "{\"optype\":39}", 0);
	sdb_set (db, "0x103e", "{\"optype\":40}", 0);
	sdb_set (db, "0x103f", "{\"optype\":41}", 0);
	sdb_set (db, "0x1040", "{\"optype\":42}", 0);
	sdb_set (db, "0x1041", "{\"optype\":43}", 0);
	sdb_set (db, "0x1042", "{\"optype\":44}", 0);
	sdb_set (db, "0x1043", "{\"optype\":45}", 0);
	sdb_set (db, "0x1044", "{\"optype\":46}", 0);
	sdb_set (db, "0x1045", "{\"optype\":47}", 0);
	sdb_set (db, "0x100", "{\"arch\":\"arm\"}", 0);
	sdb_set (db, "0x120", "{\"arch\":null}", 0);
	sdb_set (db, "0x200", "{\"immbase\":10}", 0);
	sdb_set (db, "0x210", "{\"jump\":1337,\"fail\":1234}", 0);
	sdb_set (db, "0x220", "{\"syntax\":\"intel\"}", 0);
	sdb_set (db, "0x230", "{\"frame\":48}", 0);
	sdb_set (db, "0x240", "{\"ptr\":4321}", 0);
	sdb_set (db, "0x250", "{\"nword\":3}", 0);
	sdb_set (db, "0x260", "{\"ret\":666}", 0);
	sdb_set (db, "0x270", "{\"newbits\":32}", 0);
	sdb_set (db, "0x280", "{\"size\":7}", 0);
	sdb_set (db, "0x290", "{\"opcode\":\"mov\"}", 0);
	sdb_set (db, "0x2a0", "{\"toff\":\"sometype\"}", 0);
	sdb_set (db, "0x2b0", "{\"esil\":\"13,29,+\"}", 0);
	sdb_set (db, "0x2c0", "{\"high\":true}", 0);
	sdb_set (db, "0x2d0", "{\"val\":54323}", 0);
	return db;
}

// All of these optypes need to be correctly loaded from potentiall older projects
// So changing anything here will require a migration pass!
static int all_optypes[] = {
	R_ANAL_OP_TYPE_COND, R_ANAL_OP_TYPE_REP, R_ANAL_OP_TYPE_MEM, R_ANAL_OP_TYPE_REG, R_ANAL_OP_TYPE_IND,
	R_ANAL_OP_TYPE_NULL, R_ANAL_OP_TYPE_JMP, R_ANAL_OP_TYPE_UJMP, R_ANAL_OP_TYPE_RJMP, R_ANAL_OP_TYPE_IJMP,
	R_ANAL_OP_TYPE_IRJMP, R_ANAL_OP_TYPE_CJMP, R_ANAL_OP_TYPE_RCJMP, R_ANAL_OP_TYPE_MJMP, R_ANAL_OP_TYPE_MCJMP,
	R_ANAL_OP_TYPE_UCJMP, R_ANAL_OP_TYPE_CALL, R_ANAL_OP_TYPE_UCALL, R_ANAL_OP_TYPE_RCALL, R_ANAL_OP_TYPE_ICALL,
	R_ANAL_OP_TYPE_IRCALL, R_ANAL_OP_TYPE_CCALL, R_ANAL_OP_TYPE_UCCALL, R_ANAL_OP_TYPE_RET, R_ANAL_OP_TYPE_CRET,
	R_ANAL_OP_TYPE_ILL, R_ANAL_OP_TYPE_UNK, R_ANAL_OP_TYPE_NOP, R_ANAL_OP_TYPE_MOV, R_ANAL_OP_TYPE_CMOV,
	R_ANAL_OP_TYPE_TRAP, R_ANAL_OP_TYPE_SWI, R_ANAL_OP_TYPE_CSWI, R_ANAL_OP_TYPE_UPUSH, R_ANAL_OP_TYPE_RPUSH,
	R_ANAL_OP_TYPE_PUSH, R_ANAL_OP_TYPE_POP, R_ANAL_OP_TYPE_CMP, R_ANAL_OP_TYPE_ACMP, R_ANAL_OP_TYPE_ADD,
	R_ANAL_OP_TYPE_SUB, R_ANAL_OP_TYPE_IO, R_ANAL_OP_TYPE_MUL, R_ANAL_OP_TYPE_DIV, R_ANAL_OP_TYPE_SHR,
	R_ANAL_OP_TYPE_SHL,	R_ANAL_OP_TYPE_SAL, R_ANAL_OP_TYPE_SAR, R_ANAL_OP_TYPE_OR, R_ANAL_OP_TYPE_AND,
	R_ANAL_OP_TYPE_XOR, R_ANAL_OP_TYPE_NOR, R_ANAL_OP_TYPE_NOT, R_ANAL_OP_TYPE_STORE, R_ANAL_OP_TYPE_LOAD,
	R_ANAL_OP_TYPE_LEA, R_ANAL_OP_TYPE_LEAVE, R_ANAL_OP_TYPE_ROR, R_ANAL_OP_TYPE_ROL, R_ANAL_OP_TYPE_XCHG,
	R_ANAL_OP_TYPE_MOD, R_ANAL_OP_TYPE_SWITCH, R_ANAL_OP_TYPE_CASE, R_ANAL_OP_TYPE_LENGTH, R_ANAL_OP_TYPE_CAST,
	R_ANAL_OP_TYPE_NEW, R_ANAL_OP_TYPE_ABS, R_ANAL_OP_TYPE_CPL, R_ANAL_OP_TYPE_CRYPTO, R_ANAL_OP_TYPE_SYNC
};

#define ALL_OPTYPES_COUNT (sizeof(all_optypes) / sizeof(int))

bool test_anal_hints_save() {
	RAnal *anal = r_anal_new ();

	r_anal_hint_set_arch (anal, 0x100, "arm");
	r_anal_hint_set_bits (anal, 0x100, 16);
	r_anal_hint_set_arch (anal, 0x120, NULL);
	r_anal_hint_set_bits (anal, 0x130, 0);

	r_anal_hint_set_immbase (anal, 0x200, 10);
	r_anal_hint_set_jump (anal, 0x210, 1337);
	r_anal_hint_set_fail (anal, 0x210, 1234);
	r_anal_hint_set_stackframe (anal, 0x230, 0x30);
	r_anal_hint_set_pointer (anal, 0x240, 4321);
	r_anal_hint_set_nword (anal, 0x250, 3);
	r_anal_hint_set_ret (anal, 0x260, 666);
	r_anal_hint_set_newbits (anal, 0x270, 32);
	r_anal_hint_set_size (anal, 0x280, 7);
	r_anal_hint_set_syntax (anal, 0x220, "intel");
	r_anal_hint_set_opcode (anal, 0x290, "mov");
	r_anal_hint_set_offset (anal, 0x2a0, "sometype");
	r_anal_hint_set_esil (anal, 0x2b0, "13,29,+");
	r_anal_hint_set_high (anal, 0x2c0);
	r_anal_hint_set_val (anal, 0x2d0, 54323);

	size_t i;
	for (i = 0; i < ALL_OPTYPES_COUNT; i++) {
		r_anal_hint_set_type (anal, 0x1000 + i, all_optypes[i]);
	}

	Sdb *db = sdb_new0 ();
	r_serialize_anal_hints_save (db, anal);

	Sdb *expected = hints_ref_db ();
	assert_sdb_eq (db, expected, "hints save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_hints_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = hints_ref_db ();

	bool succ = r_serialize_anal_hints_load (db, anal, NULL);
	mu_assert ("load success", succ);

	// TODO: check some stuff

	sdb_free (db);
	r_anal_free (anal);
	mu_end;
}

Sdb *anal_ref_db() {
	Sdb *db = sdb_new0 ();

	Sdb *blocks = sdb_ns (db, "blocks", true);
	sdb_set (blocks, "0x4d2", "{\"size\":32}", 0);
	sdb_set (blocks, "0x539", "{\"size\":42}", 0);

	Sdb *functions = sdb_ns (db, "functions", true);
	sdb_set (functions, "0x4d2", "{\"name\":\"effekt\",\"bits\":32,\"type\":1,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[1337]}", 0);
	sdb_set (functions, "0x539", "{\"name\":\"hirsch\",\"bits\":32,\"type\":0,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[1337,1234]}", 0);

	Sdb *xrefs = sdb_ns (db, "xrefs", true);
	sdb_set (xrefs, "0x42", "[{\"to\":1337,\"type\":\"C\"}]", 0);
	sdb_set (xrefs, "0x539", "[{\"to\":12648430,\"type\":\"d\"}]", 0);

	Sdb *meta = sdb_ns (db, "meta", true);
	Sdb *meta_spaces = sdb_ns (meta, "spaces", true);
	sdb_ns (meta_spaces, "spaces", true);
	sdb_set (meta_spaces, "spacestack", "[\"*\"]", 0);
	sdb_set (meta_spaces, "name", "CS", 0);
	sdb_set (meta, "0x1337", "[{\"type\":\"C\",\"str\":\"some comment\"}]", 0);

	Sdb *hints = sdb_ns (db, "hints", true);
	// TODO: add some hints

	return db;
}

bool test_anal_save() {
	RAnal *anal = r_anal_new ();

	RAnalBlock *ba = r_anal_create_block (anal, 1337, 42);
	RAnalBlock *bb = r_anal_create_block (anal, 1234, 32);

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, r_anal_diff_new ());
	r_anal_function_add_block (f, ba);
	r_anal_function_add_block (f, bb);

	f = r_anal_create_function (anal, "effekt", 1234, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function_add_block (f, ba);

	r_anal_block_unref (ba);
	r_anal_block_unref (bb);

	r_anal_xrefs_set (anal, 0x42, 1337, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 1337, 0xc0ffee, R_ANAL_REF_TYPE_DATA);

	r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x1337, "some comment");

	// TODO: add some hints

	Sdb *db = sdb_new0 ();
	r_serialize_anal_save (db, anal);

	Sdb *expected = anal_ref_db ();
	assert_sdb_eq (db, expected, "anal save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = anal_ref_db ();
	bool succ = r_serialize_anal_load (db, anal, NULL);
	sdb_free (db);
	mu_assert ("load success", succ);

	size_t blocks_count = 0;
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		(void)block;
		blocks_count++;
	}

	// tested in detail by dedicated tests
	mu_assert_eq (blocks_count, 2, "blocks loaded");
	mu_assert_eq (r_list_length (anal->fcns), 2, "functions loaded");
	mu_assert_eq (r_anal_xrefs_count (anal), 2, "xrefs loaded");

	const char *cmt = r_meta_get_string(anal, R_META_TYPE_COMMENT, 0x1337);
	mu_assert_streq (cmt, "some comment", "meta");

	// TODO: check some hints
	
	r_anal_free (anal);
	mu_end;
}

int all_tests() {
	mu_run_test (test_anal_diff_save);
	mu_run_test (test_anal_diff_load);
	mu_run_test (test_anal_switch_op_save);
	mu_run_test (test_anal_switch_op_load);
	mu_run_test (test_anal_block_save);
	mu_run_test (test_anal_block_load);
	mu_run_test (test_anal_function_save);
	mu_run_test (test_anal_function_load);
	mu_run_test (test_anal_var_save);
	mu_run_test (test_anal_var_load);
	mu_run_test (test_anal_xrefs_save);
	mu_run_test (test_anal_xrefs_load);
	mu_run_test (test_anal_meta_save);
	mu_run_test (test_anal_meta_load);
	mu_run_test (test_anal_hints_save);
	mu_run_test (test_anal_hints_load);
	mu_run_test (test_anal_save);
	mu_run_test (test_anal_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
