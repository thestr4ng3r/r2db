
#include <r_serialize.h>
#include "minunit.h"
#include "test_utils.h"

bool test_anal_diff_save() {
	RAnalDiff *diff = r_anal_diff_new ();

	PJ *j = pj_new ();
	r_serialize_anal_diff_save (j, diff);
	mu_assert_streq (pj_string (j), "{\"addr\":18446744073709551615,\"dist\":0.000000,\"size\":0}", "empty diff");
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

	char *str = strdup ("{\"addr\":18446744073709551615,\"dist\":0.000000,\"size\":0}");
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

bool test_anal_hint_save() {
	RAnalHint *hint = malloc(sizeof(*hint));
	if (!hint) {
		return false;
	}

	hint->addr = 0x00;
	hint->ptr = 0x01;
	hint->val = 0;
	hint->jump = 0x00;
	hint->fail = 0x0;
	hint->ret = 0x1337;
	hint->arch = "arm";
	hint->opcode = "adr x18, 0x24601";
	hint->syntax = NULL;
	hint->esil = "148993,x18,=";
	hint->offset = 0;

	hint->type = 1;
	hint->size = 10;
	hint->bits = 32;
	hint->new_bits = 0;
	hint->immbase = 0x42;
	hint->high = true; // highlight hint
	hint->nword = 0x69;
	hint->stackframe = 0x1337;

	r_serialize_anal_hint_save (db, hint);

	// Todo; Fix the string to match.
	mu_assert_streq (pj_string (j), "{\"addr\":1337,\"min\":42,\"max\":45,\"def\":46,\"cases\":[]}", "empty switch");

	mu_end;
}

bool test_anal_hint_load() {
	// Todo;
	mu_end;
}

int all_tests() {
	mu_run_test (test_anal_diff_save);
	mu_run_test (test_anal_diff_load);
	mu_run_test (test_anal_switch_op_save);
	mu_run_test (test_anal_switch_op_load);
	mu_run_test (test_anal_hint_save);
	mu_run_test (test_anal_hint_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
