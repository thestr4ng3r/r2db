
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
	RJson *json = r_json_parse (str);
	RAnalDiff *diff = r_serialize_anal_diff_load (parser, json);
	r_json_free (json);
	free (str);
	mu_assert_notnull (diff, "diff");
	mu_assert_eq (diff->addr, UT64_MAX, "addr");
	mu_assert_eq (diff->size, 0, "size");
	mu_assert_eq (diff->type, R_ANAL_DIFF_TYPE_NULL, "type");
	mu_assert_eq (diff->dist, 0.0, "dist");
	mu_assert_null (diff->name, "name");
	r_anal_diff_free (diff);

	str = strdup ("{\"type\":\"m\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}");
	json = r_json_parse (str);
	diff = r_serialize_anal_diff_load (parser, json);
	r_json_free (json);
	free (str);
	mu_assert_notnull (diff, "diff");
	mu_assert_eq (diff->addr, 0x1337, "addr");
	mu_assert_eq (diff->size, 0x4242, "size");
	mu_assert_eq (diff->type, R_ANAL_DIFF_TYPE_MATCH, "type");
	mu_assert_eq (diff->dist, 42.3, "dist");
	mu_assert_streq (diff->name, PERTURBATOR_JSON, "name");
	r_anal_diff_free (diff);

	str = strdup ("{\"type\":\"u\",\"addr\":4919,\"dist\":42.300000,\"name\":\"\\\\\\\\,\\\\\\\";] [}{'\",\"size\":16962}");
	json = r_json_parse (str);
	diff = r_serialize_anal_diff_load (parser, json);
	r_json_free (json);
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
	RJson *json = r_json_parse (str);
	RAnalSwitchOp *sop = r_serialize_anal_switch_op_load (json);
	r_json_free (json);
	free (str);
	mu_assert_notnull (sop, "sop");
	mu_assert_eq (sop->addr, 1337, "addr");
	mu_assert_eq (sop->min_val, 42, "min val");
	mu_assert_eq (sop->max_val, 45, "max val");
	mu_assert_eq (sop->def_val, 46, "def val");
	mu_assert (r_list_empty (sop->cases), "no cases");
	r_anal_switch_op_free (sop);

	str = strdup("{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[{\"addr\":1339,\"jump\":57005,\"value\":42},{\"addr\":1340,\"jump\":48879,\"value\":43}]}");
	json = r_json_parse (str);
	sop = r_serialize_anal_switch_op_load (json);
	r_json_free (json);
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
	sdb_set (db, "0x539", "{\"name\":\"hirsch\",\"bits\":16,\"type\":0,\"cc\":\"fancycall\",\"stack\":42,\"maxstack\":123,\"ninstr\":13,\"folded\":true,\"bp_frame\":true,\"fingerprint\":\"AAECAwQFBgcICQoLDA0ODw==\",\"diff\":{\"addr\":4321},\"bbs\":[1337,1234],\"imports\":[\"earth\",\"rise\"],\"labels\":{\"beach\":1400,\"another\":1450,\"year\":1440}}", 0);
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

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, NULL);
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
	r_anal_function_set_label (f, "beach", 1400);
	r_anal_function_set_label (f, "another", 1450);
	r_anal_function_set_label (f, "year", 1440);

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
	mu_assert_eq (f->labels->count, 3, "labels count");
	mu_assert_eq (r_anal_function_get_label (f, "beach"), 1400, "label");
	mu_assert_eq (r_anal_function_get_label (f, "another"), 1450, "label");
	mu_assert_eq (r_anal_function_get_label (f, "year"), 1440, "label");

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
	mu_assert_eq (f->labels->count, 0, "labels count");

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
	mu_assert_eq (f->labels->count, 0, "labels count");

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
	mu_assert_eq (f->labels->count, 0, "labels count");

	f = r_anal_get_function_at (anal, 0xdead);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "agnosie", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_IMP, "type");
	mu_assert_eq (f->labels->count, 0, "labels count");

	f = r_anal_get_function_at (anal, 0xbeef);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "eskapist", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_INT, "type");
	mu_assert_eq (f->labels->count, 0, "labels count");

	f = r_anal_get_function_at (anal, 0xc0ffee);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "lifnej", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_ROOT, "type");
	mu_assert_eq (f->labels->count, 0, "labels count");

	f = r_anal_get_function_at (anal, 0x31337);
	mu_assert_notnull (f, "function");
	mu_assert_streq (f->name, "aldebaran", "name");
	mu_assert_eq (f->type, R_ANAL_FCN_TYPE_ANY, "type");
	mu_assert_eq (f->labels->count, 0, "labels count");

	sdb_free (db);
	r_anal_free (anal);
	r_serialize_anal_diff_parser_free (diff_parser);
	mu_end;
}

Sdb *vars_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "0x539", "{\"name\":\"hirsch\",\"bits\":64,\"type\":0,\"stack\":0,\"maxstack\":0,\"ninstr\":0,\"bp_frame\":true,\"diff\":{},\"bbs\":[],"
		"\"vars\":["
		"{\"name\":\"arg_rax\",\"type\":\"int64_t\",\"kind\":\"r\",\"reg\":\"rax\",\"arg\":true,\"accs\":[{\"off\":3,\"type\":\"r\",\"sp\":42,\"reg\":\"rax\"},{\"off\":13,\"type\":\"rw\",\"sp\":13,\"reg\":\"rbx\"},{\"off\":23,\"type\":\"w\",\"sp\":123,\"reg\":\"rcx\"}],\"constrs\":[0,42,1,84,2,126,3,168,4,210,5,252,6,294,7,336,8,378,9,420,10,462,11,504,12,546,13,588,14,630,15,672]},"
		"{\"name\":\"var_sp\",\"type\":\"const char *\",\"kind\":\"s\",\"delta\":16,\"accs\":[{\"off\":3,\"type\":\"w\",\"sp\":321,\"reg\":\"rsp\"}]},"
		"{\"name\":\"var_bp\",\"type\":\"struct something\",\"kind\":\"b\",\"delta\":-16},"
		"{\"name\":\"arg_bp\",\"type\":\"uint64_t\",\"kind\":\"b\",\"delta\":16,\"arg\":true,\"cmt\":\"I have no idea what this var does\"}]}", 0);
	return db;
}

bool test_anal_var_save() {
	RAnal *anal = r_anal_new ();
	r_anal_use (anal, "x86");
	r_anal_set_bits (anal, 64);

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, NULL);

	RRegItem *rax = r_reg_get (anal->reg, "rax", -1);
	RAnalVar *v = r_anal_function_set_var (f, rax->index, R_ANAL_VAR_KIND_REG, "int64_t", 0, true, "arg_rax");
	r_anal_var_set_access (v, "rax", 1340, R_ANAL_VAR_ACCESS_TYPE_READ, 42);
	r_anal_var_set_access (v, "rbx", 1350, R_ANAL_VAR_ACCESS_TYPE_READ | R_ANAL_VAR_ACCESS_TYPE_WRITE, 13);
	r_anal_var_set_access (v, "rcx", 1360, R_ANAL_VAR_ACCESS_TYPE_WRITE, 123);

	ut64 val = 0;
	_RAnalCond cond;
	for (cond = R_ANAL_COND_AL; cond <= R_ANAL_COND_LS; cond++) {
		val += 42;
		RAnalVarConstraint constr = {
			.cond = cond,
			.val = val
		};
		r_anal_var_add_constraint (v, &constr);
	}

	v = r_anal_function_set_var (f, 0x10, R_ANAL_VAR_KIND_SPV, "const char *", 0, false, "var_sp");
	r_anal_var_set_access (v, "rsp", 1340, R_ANAL_VAR_ACCESS_TYPE_WRITE, 321);

	r_anal_function_set_var (f, -0x10, R_ANAL_VAR_KIND_BPV, "struct something", 0, false, "var_bp");
	v = r_anal_function_set_var (f, 0x10, R_ANAL_VAR_KIND_BPV, "uint64_t", 0, true, "arg_bp");
	v->comment = strdup ("I have no idea what this var does");

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

	mu_assert_eq (v->constraints.len, R_ANAL_COND_LS + 1, "constraints count");
	ut64 val = 0;
	_RAnalCond cond;
	for (cond = R_ANAL_COND_AL; cond <= R_ANAL_COND_LS; cond++) {
		val += 42;
		RAnalVarConstraint *constr = r_vector_index_ptr (&v->constraints, (size_t)(cond - R_ANAL_COND_AL));
		mu_assert_eq (constr->cond, cond, "constraint cond");
		mu_assert_eq (constr->val, val, "constraint val");
	}

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
	mu_assert_streq (v->comment, "I have no idea what this var does", "var comment");

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
	sdb_set (db, "0x100", "{\"arch\":\"arm\",\"bits\":16}", 0);
	sdb_set (db, "0x120", "{\"arch\":null}", 0);
	sdb_set (db, "0x130", "{\"bits\":0}", 0);
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

// All of these optypes need to be correctly loaded from potentially older projects
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
	R_ANAL_OP_TYPE_SHL, R_ANAL_OP_TYPE_SAL, R_ANAL_OP_TYPE_SAR, R_ANAL_OP_TYPE_OR, R_ANAL_OP_TYPE_AND,
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

static bool addr_hints_count_cb(ut64 addr, const RVector/*<const RAnalAddrHintRecord>*/ *records, void *user) {
	(*(size_t *)user) += records->len;
	return true;
}

static bool arch_hints_count_cb(ut64 addr, R_NULLABLE const char *arch, void *user) {
	(*(size_t *)user)++;
	return true;
}

static bool bits_hints_count_cb(ut64 addr, int bits, void *user) {
	(*(size_t *)user)++;
	return true;
}

bool test_anal_hints_load() {
	RAnal *anal = r_anal_new ();

	Sdb *db = hints_ref_db ();

	bool succ = r_serialize_anal_hints_load (db, anal, NULL);
	mu_assert ("load success", succ);

	size_t count = 0;
	r_anal_addr_hints_foreach (anal, addr_hints_count_cb, &count);
	r_anal_arch_hints_foreach (anal, arch_hints_count_cb, &count);
	r_anal_bits_hints_foreach (anal, bits_hints_count_cb, &count);
	mu_assert_eq (count, 19 + ALL_OPTYPES_COUNT, "hints count");

	ut64 addr;
	const char *arch = r_anal_hint_arch_at (anal, 0x100, &addr);
	mu_assert_streq (arch, "arm", "arch hint");
	mu_assert_eq (addr, 0x100, "arch hint addr");
	int bits = r_anal_hint_bits_at(anal, 0x100, &addr);
	mu_assert_eq (bits, 16, "bits hint");
	mu_assert_eq (addr, 0x100, "bits hint addr");
	arch = r_anal_hint_arch_at (anal, 0x120, &addr);
	mu_assert_null (arch, "arch hint");
	mu_assert_eq (addr, 0x120, "arch hint addr");
	bits = r_anal_hint_bits_at(anal, 0x100, &addr);
	mu_assert_eq (bits, 16, "bits hint");
	mu_assert_eq (addr, 0x100, "bits hint addr");

#define assert_addr_hint(addr, tp, check) do { \
		const RVector/*<const RAnalAddrHintRecord>*/ *hints = r_anal_addr_hints_at(anal, addr); \
		const RAnalAddrHintRecord *record; \
		bool found = false; \
		r_vector_foreach (hints, record) { \
			if (record->type == R_ANAL_ADDR_HINT_TYPE_##tp) { \
				check; \
				found = true; \
				break; \
			} \
		} \
		mu_assert ("addr hint", found); \
	} while(0) 

	assert_addr_hint (0x200, IMMBASE, mu_assert_eq (record->immbase, 10, "immbase hint"));
	assert_addr_hint (0x210, JUMP, mu_assert_eq (record->jump, 1337, "jump hint"));
	assert_addr_hint (0x210, FAIL, mu_assert_eq (record->fail, 1234, "fail hint"));
	assert_addr_hint (0x230, STACKFRAME, mu_assert_eq (record->stackframe, 0x30, "stackframe hint"));
	assert_addr_hint (0x240, PTR, mu_assert_eq (record->ptr, 4321, "ptr hint"));
	assert_addr_hint (0x250, NWORD, mu_assert_eq (record->nword, 3, "nword hint"));
	assert_addr_hint (0x260, RET, mu_assert_eq (record->retval, 666, "ret hint"));
	assert_addr_hint (0x270, NEW_BITS, mu_assert_eq (record->newbits, 32, "newbits hint"));
	assert_addr_hint (0x280, SIZE, mu_assert_eq (record->size, 7, "size hint"));
	assert_addr_hint (0x220, SYNTAX, mu_assert_streq (record->syntax, "intel", "syntax hint"));
	assert_addr_hint (0x290, OPCODE, mu_assert_streq (record->opcode, "mov", "opcode hint"));
	assert_addr_hint (0x2a0, TYPE_OFFSET, mu_assert_streq (record->type_offset, "sometype", "type offset hint"));
	assert_addr_hint (0x2b0, ESIL, mu_assert_streq (record->esil, "13,29,+", "esil hint"));
	assert_addr_hint (0x2c0, HIGH,);
	assert_addr_hint (0x2d0, VAL, mu_assert_eq (record->val, 54323, "val hint"));

	size_t i;
	for (i = 0; i < ALL_OPTYPES_COUNT; i++) {
		assert_addr_hint (0x1000 + i, OPTYPE, mu_assert_eq (record->optype, all_optypes[i], "optype hint"));
	}

	sdb_free (db);
	r_anal_free (anal);
	mu_end;
}

Sdb *classes_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "Aeropause", "c", 0);
	sdb_set (db, "Bright", "c", 0);
	Sdb *attrs_db = sdb_ns (db, "attrs", true);
	sdb_set (attrs_db, "attrtypes.Bright", "base", 0);
	sdb_set (attrs_db, "attr.Aeropause.vtable.0", "0x1000,4,80", 0);
	sdb_set (attrs_db, "attrtypes.Aeropause", "method,vtable", 0);
	sdb_set (attrs_db, "attr.Aeropause.method", "some_meth,some_other_meth", 0);
	sdb_set (attrs_db, "attr.Bright.base", "0", 0);
	sdb_set (attrs_db, "attr.Aeropause.vtable", "0", 0);
	sdb_set (attrs_db, "attr.Bright.base.0", "Aeropause,8", 0);
	sdb_set (attrs_db, "attr.Aeropause.method.some_meth", "4919,42", 0);
	sdb_set (attrs_db, "attr.Aeropause.method.some_other_meth", "4660,32", 0);
	return db;
}

bool test_anal_classes_save() {
	RAnal *anal = r_anal_new ();

	r_anal_class_create (anal, "Aeropause");
	RAnalMethod crystal = {
		.name = strdup ("some_meth"),
		.addr = 0x1337,
		.vtable_offset = 42
	};
	r_anal_class_method_set (anal, "Aeropause", &crystal);
	r_anal_class_method_fini (&crystal);

	RAnalMethod meth = {
		.name = strdup ("some_other_meth"),
		.addr = 0x1234,
		.vtable_offset = 0x20
	};
	r_anal_class_method_set (anal, "Aeropause", &meth);
	r_anal_class_method_fini (&meth);

	r_anal_class_create (anal, "Bright");
	RAnalBaseClass base = {
		.id = NULL,
		.offset = 8,
		.class_name = strdup ("Aeropause")
	};
	r_anal_class_base_set (anal, "Bright", &base);
	r_anal_class_base_fini (&base);

	RAnalVTable vt = {
		.id = NULL,
		.offset = 4,
		.addr = 0x1000,
		.size = 0x50
	};
	r_anal_class_vtable_set (anal, "Aeropause", &vt);
	r_anal_class_vtable_fini (&vt);

	Sdb *db = sdb_new0 ();
	r_serialize_anal_classes_save (db, anal);

	Sdb *expected = classes_ref_db ();
	assert_sdb_eq (db, expected, "classes save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_classes_load() {
	RAnal *anal = r_anal_new ();
	Sdb *db = classes_ref_db ();
	bool succ = r_serialize_anal_classes_load (db, anal, NULL);
	sdb_free (db);
	mu_assert ("load success", succ);

	SdbList *classes = r_anal_class_get_all (anal, true);
	mu_assert_eq (classes->length, 2, "classes count");
	SdbListIter *iter = ls_head (classes);
	SdbKv *kv = ls_iter_get (iter);
	mu_assert_streq (sdbkv_key (kv), "Aeropause", "class");
	kv = ls_iter_get (iter);
	mu_assert_streq (sdbkv_key (kv), "Bright", "class");
	ls_free (classes);

	RVector *vals = r_anal_class_method_get_all (anal, "Aeropause");
	mu_assert_eq (vals->len, 2, "method count");
	RAnalMethod *meth = r_vector_index_ptr (vals, 0);
	mu_assert_streq (meth->name, "some_meth", "method name");
	mu_assert_eq (meth->addr, 0x1337, "method addr");
	mu_assert_eq (meth->vtable_offset, 42, "method vtable offset");
	meth = r_vector_index_ptr (vals, 1);
	mu_assert_streq (meth->name, "some_other_meth", "method name");
	mu_assert_eq (meth->addr, 0x1234, "method addr");
	mu_assert_eq (meth->vtable_offset, 0x20, "method vtable offset");
	r_vector_free (vals);

	vals = r_anal_class_base_get_all (anal, "Aeropause");
	mu_assert_eq (vals->len, 0, "base count");
	r_vector_free (vals);

	vals = r_anal_class_vtable_get_all (anal, "Aeropause");
	mu_assert_eq (vals->len, 1, "vtable count");
	RAnalVTable *vt = r_vector_index_ptr (vals, 0);
	mu_assert_eq (vt->offset, 4, "vtable offset");
	mu_assert_eq (vt->addr, 0x1000, "vtable addr");
	mu_assert_eq (vt->size, 0x50, "vtable size");
	r_vector_free (vals);

	vals = r_anal_class_method_get_all (anal, "Bright");
	mu_assert_eq (vals->len, 0, "method count");
	r_vector_free (vals);

	vals = r_anal_class_base_get_all (anal, "Bright");
	mu_assert_eq (vals->len, 1, "base count");
	RAnalBaseClass *base = r_vector_index_ptr (vals, 0);
	mu_assert_eq (base->offset, 8, "base class offset");
	mu_assert_streq (base->class_name, "Aeropause", "base class name");
	r_vector_free (vals);

	vals = r_anal_class_vtable_get_all (anal, "Bright");
	mu_assert_eq (vals->len, 0, "vtable count");
	r_vector_free (vals);

	r_anal_free (anal);
	mu_end;
}

Sdb *types_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "snatcher", "union", 0);
	sdb_set (db, "struct.junker.gillian", "char *,0,0", 0);
	sdb_set (db, "junker", "struct", 0);
	sdb_set (db, "typedef.human", "union snatcher", 0);
	sdb_set (db, "union.snatcher.random", "int,0,0", 0);
	sdb_set (db, "human", "typedef", 0);
	sdb_set (db, "struct.junker.seed", "uint64_t,8,0", 0);
	sdb_set (db, "union.snatcher", "random,hajile", 0);
	sdb_set (db, "struct.junker", "gillian,seed", 0);
	sdb_set (db, "union.snatcher.hajile", "uint32_t,0,0", 0);
	sdb_set (db, "badchar", "type", 0);
	sdb_set (db, "type.badchar.size", "16", 0);
	sdb_set (db, "type.badchar", "c", 0);
	sdb_set (db, "enum.mika", "ELIJAH,MODNAR", 0);
	sdb_set (db, "enum.mika.MODNAR", "0x539", 0);
	sdb_set (db, "enum.mika.ELIJAH", "0x2a", 0);
	sdb_set (db, "enum.mika.0x2a", "ELIJAH", 0);
	sdb_set (db, "mika", "enum", 0);
	sdb_set (db, "enum.mika.0x539", "MODNAR", 0);
	return db;
}

bool test_anal_types_save() {
	RAnal *anal = r_anal_new ();

	// struct
	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
	type->name = strdup ("junker");

	RAnalStructMember member;
	member.name = strdup ("gillian");
	member.offset = 0;
	member.type = strdup ("char *");
	r_vector_push (&type->struct_data.members, &member);

	member.name = strdup ("seed");
	member.offset = 8;
	member.type = strdup ("uint64_t");
	r_vector_push (&type->struct_data.members, &member);

	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	// union
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_UNION);
	type->name = strdup ("snatcher");

	RAnalUnionMember mumber;
	mumber.name = strdup ("random");
	mumber.offset = 0;
	mumber.type = strdup ("int");
	r_vector_push (&type->union_data.members, &mumber);

	mumber.name = strdup ("hajile");
	mumber.offset = 0;
	mumber.type = strdup ("uint32_t");
	r_vector_push (&type->union_data.members, &mumber);

	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	// enum
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ENUM);
	type->name = strdup ("mika");

	RAnalEnumCase cas;
	cas.name = strdup ("ELIJAH");
	cas.val = 42;
	r_vector_push (&type->enum_data.cases, &cas);

	cas.name = strdup ("MODNAR");
	cas.val = 1337;
	r_vector_push (&type->enum_data.cases, &cas);

	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	// typedef
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_TYPEDEF);
	type->name = strdup ("human");
	type->type = strdup ("union snatcher");
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	// atomic
	type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	type->name = strdup ("badchar");
	type->size = 16;
	type->type = strdup ("c");
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	Sdb *db = sdb_new0 ();
	r_serialize_anal_types_save (db, anal);

	Sdb *expected = types_ref_db ();
	assert_sdb_eq (db, expected, "types save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_types_load() {
	RAnal *anal = r_anal_new ();
	Sdb *db = types_ref_db ();
	bool succ = r_serialize_anal_types_load (db, anal, NULL);
	sdb_free (db);
	mu_assert ("load success", succ);

	// struct
	RAnalBaseType *type = r_anal_get_base_type (anal, "junker");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_STRUCT, "type kind");
	mu_assert_eq (type->struct_data.members.len, 2, "members count");

	RAnalStructMember *member = r_vector_index_ptr (&type->struct_data.members, 0);
	mu_assert_streq (member->name, "gillian", "member name");
	mu_assert_eq (member->offset, 0, "member offset");
	mu_assert_streq (member->type, "char *", "member type");

	member = r_vector_index_ptr (&type->struct_data.members, 1);
	mu_assert_streq (member->name, "seed", "member name");
	mu_assert_eq (member->offset, 8, "member offset");
	mu_assert_streq (member->type, "uint64_t", "member type");

	r_anal_base_type_free (type);

	// union
	type = r_anal_get_base_type (anal, "snatcher");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_UNION, "type kind");
	mu_assert_eq (type->union_data.members.len, 2, "members count");

	RAnalUnionMember *mumber = r_vector_index_ptr (&type->union_data.members, 0);
	mu_assert_streq (mumber->name, "random", "member name");
	mu_assert_streq (mumber->type, "int", "member type");

	mumber = r_vector_index_ptr (&type->union_data.members, 1);
	mu_assert_streq (mumber->name, "hajile", "member name");
	mu_assert_streq (mumber->type, "uint32_t", "member type");

	r_anal_base_type_free (type);

	// enum
	type = r_anal_get_base_type (anal, "mika");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ENUM, "type kind");
	mu_assert_eq (type->enum_data.cases.len, 2, "cases count");

	RAnalEnumCase *cas = r_vector_index_ptr (&type->enum_data.cases, 0);
	mu_assert_streq (cas->name, "ELIJAH", "case name");
	mu_assert_eq (cas->val, 42, "case value");

	cas = r_vector_index_ptr (&type->enum_data.cases, 1);
	mu_assert_streq (cas->name, "MODNAR", "case name");
	mu_assert_eq (cas->val, 1337, "case value");

	r_anal_base_type_free (type);

	// typedef
	type = r_anal_get_base_type (anal, "human");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_TYPEDEF, "type kind");
	mu_assert_streq (type->type, "union snatcher", "typedefd type");
	r_anal_base_type_free (type);

	// atomic
	type = r_anal_get_base_type (anal, "badchar");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ATOMIC, "type kind");
	mu_assert_eq (type->size, 16, "atomic type size");
	mu_assert_streq (type->type, "c", "atomic type");
	r_anal_base_type_free (type);

	r_anal_free (anal);
	mu_end;
}

Sdb *sign_ref_db() {
	Sdb *db = sdb_new0 ();
	Sdb *spaces = sdb_ns (db, "spaces", true);
	sdb_set (spaces, "spacestack", "[\"koridai\"]", 0);
	sdb_set (spaces, "name", "zs", 0);
	Sdb *spaces_spaces = sdb_ns (spaces, "spaces", true);
	sdb_set (spaces_spaces, "koridai", "s", 0);
	sdb_set (db, "zign|*|sym.mahboi", "|s:4|b:deadbeef|m:c0ffee42|o:4919|g:7b0000000b0000000c0000000d0000002a000000|r:gwonam,link|x:king,ganon|v:r16,s42,b13|t:func.sym.mahboi.ret=char *,func.sym.mahboi.args=2,func.sym.mahboi.arg.0=\"int,arg0\",func.sym.mahboi.arg.1=\"uint32_t,die\"|c:This peace is what all true warriors strive for|n:sym.Mah.Boi|h:7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851", 0);
	sdb_set (db, "zign|koridai|sym.boring", "|c:gee it sure is boring around here", 0);
	return db;
}

bool test_anal_sign_save() {
	RAnal *anal = r_anal_new ();

	RSignItem *item = r_sign_item_new ();
	item->name = strdup ("sym.mahboi");
	item->realname = strdup ("sym.Mah.Boi");
	item->comment = strdup ("This peace is what all true warriors strive for");

	item->bytes = R_NEW0 (RSignBytes);
	item->bytes->size = 4;
	item->bytes->bytes = (ut8 *)strdup ("\xde\xad\xbe\xef");
	item->bytes->mask = (ut8 *)strdup ("\xc0\xff\xee\x42");

	item->graph = R_NEW0 (RSignGraph);
	item->graph->bbsum = 42;
	item->graph->cc = 123;
	item->graph->ebbs = 13;
	item->graph->edges = 12;
	item->graph->nbbs = 11;

	item->addr = 0x1337;

	item->refs = r_list_newf (free);
	r_list_append (item->refs, strdup ("gwonam"));
	r_list_append (item->refs, strdup ("link"));

	item->xrefs = r_list_newf (free);
	r_list_append (item->xrefs, strdup ("king"));
	r_list_append (item->xrefs, strdup ("ganon"));

	item->vars = r_list_newf (free);
	r_list_append (item->vars, strdup ("r16"));
	r_list_append (item->vars, strdup ("s42"));
	r_list_append (item->vars, strdup ("b13"));

	item->types = r_list_newf (free);
	r_list_append (item->types, strdup ("func.sym.mahboi.ret=char *"));
	r_list_append (item->types, strdup ("func.sym.mahboi.args=2"));
	r_list_append (item->types, strdup ("func.sym.mahboi.arg.0=\"int,arg0\""));
	r_list_append (item->types, strdup ("func.sym.mahboi.arg.1=\"uint32_t,die\""));

	item->hash = R_NEW0 (RSignHash);
	item->hash->bbhash = strdup ("7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851");

	r_sign_add_item (anal, item);
	r_sign_item_free (item);

	r_spaces_set (&anal->zign_spaces, "koridai");
	r_sign_add_comment (anal, "sym.boring", "gee it sure is boring around here");

	Sdb *db = sdb_new0 ();
	r_serialize_anal_sign_save (db, anal);

	Sdb *expected = sign_ref_db ();
	assert_sdb_eq (db, expected, "zignatures save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_sign_load() {
	RAnal *anal = r_anal_new ();
	Sdb *db = sign_ref_db ();
	bool succ = r_serialize_anal_sign_load (db, anal, NULL);
	sdb_free (db);
	mu_assert ("load success", succ);

	r_spaces_set (&anal->zign_spaces, NULL);
	RSignItem *item = r_sign_get_item (anal, "sym.mahboi");
	mu_assert_notnull (item, "get item");

	mu_assert_streq (item->name, "sym.mahboi", "name");
	mu_assert_streq (item->realname, "sym.Mah.Boi", "realname");
	mu_assert_streq (item->comment, "This peace is what all true warriors strive for", "comment");
	mu_assert_notnull (item->bytes, "bytes");
	mu_assert_eq (item->bytes->size, 4, "bytes size");
	mu_assert_memeq (item->bytes->bytes, (ut8 *)"\xde\xad\xbe\xef", 4, "bytes bytes");
	mu_assert_memeq (item->bytes->mask, (ut8 *)"\xc0\xff\xee\x42", 4, "bytes mask");
	mu_assert_notnull (item->graph, "graph");
	mu_assert_eq (item->graph->bbsum, 42, "graph bbsum");
	mu_assert_eq (item->graph->cc, 123, "graph cc");
	mu_assert_eq (item->graph->ebbs, 13, "graph ebbs");
	mu_assert_eq (item->graph->edges, 12, "graph edges");
	mu_assert_eq (item->graph->nbbs, 11, "graph nbbs");
	mu_assert_eq (item->addr, 0x1337, "addr");
	mu_assert_notnull (item->refs, "refs");
	mu_assert_eq (r_list_length (item->refs), 2, "refs count");
	mu_assert_streq (r_list_get_n (item->refs, 0), "gwonam", "ref");
	mu_assert_streq (r_list_get_n (item->refs, 1), "link", "ref");
	mu_assert_notnull (item->xrefs, "xrefs");
	mu_assert_eq (r_list_length (item->xrefs), 2, "xrefs count");
	mu_assert_streq (r_list_get_n (item->xrefs, 0), "king", "xref");
	mu_assert_streq (r_list_get_n (item->xrefs, 1), "ganon", "xref");
	mu_assert_notnull (item->vars, "vars");
	mu_assert_eq (r_list_length (item->vars), 3, "vars count");
	mu_assert_streq (r_list_get_n (item->vars, 0), "r16", "var");
	mu_assert_streq (r_list_get_n (item->vars, 1), "s42", "var");
	mu_assert_streq (r_list_get_n (item->vars, 2), "b13", "var");
	mu_assert_notnull (item->types, "types");
	mu_assert_eq (r_list_length (item->types), 4, "types count");
	mu_assert_streq (r_list_get_n (item->types, 0), "func.sym.mahboi.ret=char *", "type");
	mu_assert_streq (r_list_get_n (item->types, 1), "func.sym.mahboi.args=2", "type");
	mu_assert_streq (r_list_get_n (item->types, 2), "func.sym.mahboi.arg.0=\"int,arg0\"", "type");
	mu_assert_streq (r_list_get_n (item->types, 3), "func.sym.mahboi.arg.1=\"uint32_t,die\"", "type");
	mu_assert_notnull (item->hash, "hash");
	mu_assert_streq (item->hash->bbhash, "7bfa1358c427e26bc03c2384f41de7be6ebc01958a57e9a6deda5bdba9768851", "hash val");
	r_sign_item_free (item);

	r_spaces_set (&anal->zign_spaces, "koridai");
	item = r_sign_get_item (anal, "sym.boring");
	mu_assert_notnull (item, "get item in space");
	mu_assert_streq (item->comment, "gee it sure is boring around here", "item in space comment");
	r_sign_item_free (item);

	r_anal_free (anal);
	mu_end;
}

static Sdb *cc_ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "cc.sectarian.ret", "rax", 0);
	sdb_set (db, "cc.sectarian.self", "rsi", 0);
	sdb_set (db, "cc.sectarian.error", "rdi", 0);
	sdb_set (db, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (db, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (db, "cc.sectarian.argn", "stack", 0);
	sdb_set (db, "sectarian", "cc", 0);
	return db;
}

bool test_anal_cc_save() {
	RAnal *anal = r_anal_new ();

	r_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");
	r_anal_cc_set_self (anal, "sectarian", "rsi");
	r_anal_cc_set_error (anal, "sectarian", "rdi");

	Sdb *db = sdb_new0 ();
	r_serialize_anal_cc_save (db, anal);

	Sdb *expected = cc_ref_db ();
	assert_sdb_eq (db, expected, "cc save");
	sdb_free (db);
	sdb_free (expected);
	r_anal_free (anal);
	mu_end;
}

bool test_anal_cc_load() {
	RAnal *anal = r_anal_new ();
	Sdb *db = cc_ref_db ();
	bool succ = r_serialize_anal_cc_load (db, anal, NULL);
	sdb_free (db);
	mu_assert ("load success", succ);

	char *v = r_anal_cc_get (anal, "sectarian");
	mu_assert_streq (v, "rax rsi.sectarian (rdx, rcx, stack) rdi;", "get cc");
	free (v);
	const char *vv = r_anal_cc_self (anal, "sectarian");
	mu_assert_streq (vv, "rsi", "get self");
	vv = r_anal_cc_error (anal, "sectarian");
	mu_assert_streq (vv, "rdi", "get error");

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
	sdb_set (hints, "0x10e1", "{\"arch\":\"arm\"}", 0);

	Sdb *classes = sdb_ns (db, "classes", true);
	sdb_set (classes, "Aeropause", "c", 0);
	Sdb *class_attrs = sdb_ns (classes, "attrs", true);
	sdb_set (class_attrs, "attrtypes.Aeropause", "method", 0);
	sdb_set (class_attrs, "attr.Aeropause.method", "some_meth", 0);
	sdb_set (class_attrs, "attr.Aeropause.method.some_meth", "4919,42", 0);

	Sdb *types = sdb_ns (db, "types", true);
	sdb_set (types, "badchar", "type", 0);
	sdb_set (types, "type.badchar.size", "16", 0);
	sdb_set (types, "type.badchar", "c", 0);

	Sdb *zigns = sdb_ns (db, "zigns", true);
	Sdb *zign_spaces = sdb_ns (zigns, "spaces", true);
	sdb_set (zign_spaces, "spacestack", "[\"koridai\"]", 0);
	sdb_set (zign_spaces, "name", "zs", 0);
	Sdb *zign_spaces_spaces = sdb_ns (zign_spaces, "spaces", true);
	sdb_set (zign_spaces_spaces, "koridai", "s", 0);
	sdb_set (zigns, "zign|koridai|sym.boring", "|c:gee it sure is boring around here", 0);

	sdb_set (db, "imports", "[\"pigs\",\"dogs\",\"sheep\"]", 0);

	Sdb *pins = sdb_ns (db, "pins", true);
	sdb_set (pins, "0x1337", "!sudo rm -rf /", 0);
	sdb_set (pins, "0xc0ffee", "pd 42", 0);

	Sdb *cc = sdb_ns (db, "cc", true);
	sdb_set (cc, "cc.sectarian.ret", "rax", 0);
	sdb_set (cc, "cc.sectarian.arg1", "rcx", 0);
	sdb_set (cc, "cc.sectarian.arg0", "rdx", 0);
	sdb_set (cc, "cc.sectarian.argn", "stack", 0);
	sdb_set (cc, "sectarian", "cc", 0);

	return db;
}

bool test_anal_save() {
	RAnal *anal = r_anal_new ();

	RAnalBlock *ba = r_anal_create_block (anal, 1337, 42);
	RAnalBlock *bb = r_anal_create_block (anal, 1234, 32);

	RAnalFunction *f = r_anal_create_function (anal, "hirsch", 1337, R_ANAL_FCN_TYPE_NULL, NULL);
	r_anal_function_add_block (f, ba);
	r_anal_function_add_block (f, bb);

	f = r_anal_create_function (anal, "effekt", 1234, R_ANAL_FCN_TYPE_FCN, NULL);
	r_anal_function_add_block (f, ba);

	r_anal_block_unref (ba);
	r_anal_block_unref (bb);

	r_anal_xrefs_set (anal, 0x42, 1337, R_ANAL_REF_TYPE_CALL);
	r_anal_xrefs_set (anal, 1337, 0xc0ffee, R_ANAL_REF_TYPE_DATA);

	r_meta_set_string (anal, R_META_TYPE_COMMENT, 0x1337, "some comment");

	r_anal_hint_set_arch (anal, 4321, "arm");

	r_anal_class_create (anal, "Aeropause");
	RAnalMethod crystal = {
		.name = strdup ("some_meth"),
		.addr = 0x1337,
		.vtable_offset = 42
	};
	r_anal_class_method_set (anal, "Aeropause", &crystal);
	r_anal_class_method_fini (&crystal);

	RAnalBaseType *type = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	type->name = strdup ("badchar");
	type->size = 16;
	type->type = strdup ("c");
	r_anal_save_base_type (anal, type);
	r_anal_base_type_free (type);

	r_spaces_set (&anal->zign_spaces, "koridai");
	r_sign_add_comment (anal, "sym.boring", "gee it sure is boring around here");

	r_anal_add_import (anal, "pigs");
	r_anal_add_import (anal, "dogs");
	r_anal_add_import (anal, "sheep");

	r_anal_pin (anal, 0x1337, "!sudo rm -rf /");
	r_anal_pin (anal, 0xc0ffee, "pd 42");

	r_anal_cc_set (anal, "rax sectarian(rdx, rcx, stack)");

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

	// all tested in detail by dedicated tests, we only check here
	// if the things are loaded at all when loading a whole anal.
	size_t blocks_count = 0;
	RBIter iter;
	RAnalBlock *block;
	r_rbtree_foreach (anal->bb_tree, iter, block, RAnalBlock, _rb) {
		(void)block;
		blocks_count++;
	}

	mu_assert_eq (blocks_count, 2, "blocks loaded");
	mu_assert_eq (r_list_length (anal->fcns), 2, "functions loaded");
	mu_assert_eq (r_anal_xrefs_count (anal), 2, "xrefs loaded");

	const char *cmt = r_meta_get_string(anal, R_META_TYPE_COMMENT, 0x1337);
	mu_assert_streq (cmt, "some comment", "meta");

	const char *hint = r_anal_hint_arch_at (anal, 4321, NULL);
	mu_assert_streq (hint, "arm", "hint");

	SdbList *classes = r_anal_class_get_all (anal, true);
	mu_assert_eq (classes->length, 1, "classes count");
	SdbListIter *siter = ls_head (classes);
	SdbKv *kv = ls_iter_get (siter);
	mu_assert_streq (sdbkv_key (kv), "Aeropause", "class");
	ls_free (classes);
	RVector *vals = r_anal_class_method_get_all (anal, "Aeropause");
	mu_assert_eq (vals->len, 1, "method count");
	RAnalMethod *meth = r_vector_index_ptr (vals, 0);
	mu_assert_streq (meth->name, "some_meth", "method name");
	r_vector_free (vals);

	RAnalBaseType *type = r_anal_get_base_type (anal, "badchar");
	mu_assert_notnull (type, "get type");
	mu_assert_eq (type->kind, R_ANAL_BASE_TYPE_KIND_ATOMIC, "type kind");
	mu_assert_eq (type->size, 16, "atomic type size");
	mu_assert_streq (type->type, "c", "atomic type");
	r_anal_base_type_free (type);

	r_spaces_set (&anal->zign_spaces, "koridai");
	RSignItem *item = r_sign_get_item (anal, "sym.boring");
	mu_assert_notnull (item, "get item in space");
	mu_assert_streq (item->comment, "gee it sure is boring around here", "item in space comment");
	r_sign_item_free (item);

	mu_assert_eq (r_list_length (anal->imports), 3, "imports count");
	mu_assert_streq (r_list_get_n (anal->imports, 0), "pigs", "import");
	mu_assert_streq (r_list_get_n (anal->imports, 1), "dogs", "import");
	mu_assert_streq (r_list_get_n (anal->imports, 2), "sheep", "import");

	size_t pin_count = sdb_count (anal->sdb_pins);
	mu_assert_eq (pin_count, 2, "pins count");
	const char *pin = r_anal_pin_call (anal, 0x1337);
	mu_assert_streq (pin, "!sudo rm -rf /", "pin");
	pin = r_anal_pin_call (anal, 0xc0ffee);
	mu_assert_streq (pin, "pd 42", "pin");

	char *cc = r_anal_cc_get (anal, "sectarian");
	mu_assert_streq (cc, "rax sectarian (rdx, rcx, stack);", "get cc");
	free (cc);

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
	mu_run_test (test_anal_classes_save);
	mu_run_test (test_anal_classes_load);
	mu_run_test (test_anal_types_save);
	mu_run_test (test_anal_types_load);
	mu_run_test (test_anal_sign_save);
	mu_run_test (test_anal_sign_load);
	mu_run_test (test_anal_cc_save);
	mu_run_test (test_anal_cc_load);
	mu_run_test (test_anal_save);
	mu_run_test (test_anal_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
