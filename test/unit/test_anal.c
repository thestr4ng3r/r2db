
#include <r_serialize.h>
#include "minunit.h"
#include "test_utils.h"

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

int all_tests() {
	mu_run_test (test_anal_diff_save);
	mu_run_test (test_anal_diff_load);
	mu_run_test (test_anal_switch_op_save);
	mu_run_test (test_anal_switch_op_load);
	mu_run_test (test_anal_block_save);
	mu_run_test (test_anal_block_load);
	mu_run_test (test_anal_function_save);
	mu_run_test (test_anal_function_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}