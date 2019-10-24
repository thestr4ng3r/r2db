
#include <r_serialize.h>
#include "minunit.h"

#define PERTURBATOR "\\,\";] [}{'"
#define PERTURBATOR_JSON "\\\\,\\\";] [}{'"

static void diff_cb(const SdbDiff *diff, void *user) {
	char buf[512];
	if (sdb_diff_format (buf, sizeof(buf), diff) < 0) {
		return;
	}
	printf ("%s\n", buf);
}

static void print_sdb(Sdb *sdb) {
	Sdb *e = sdb_new0 ();
	sdb_diff (sdb, e, diff_cb, NULL);
}

#define assert_sdb_eq(actual, expected, msg) mu_assert ((msg), sdb_diff (expected, actual, diff_cb, NULL));

bool test_spaces_save(void) {
	RSpaces *spaces = r_spaces_new ("myspaces");
	r_spaces_add (spaces, "a");
	r_spaces_add (spaces, "b");
	r_spaces_add (spaces, "c");
	r_spaces_add (spaces, PERTURBATOR);

	Sdb *db = sdb_new0 ();
	r_serialize_spaces_save (db, spaces);

	Sdb *expected = sdb_new0 ();
	sdb_set (expected, "name", "myspaces", 0);
	sdb_set (expected, "spacestack", "[\"*\"]", 0);
	Sdb *expected_spaces = sdb_ns (expected, "spaces", true);
	sdb_set (expected_spaces, "a", "s", 0);
	sdb_set (expected_spaces, "b", "s", 0);
	sdb_set (expected_spaces, "c", "s", 0);
	sdb_set (expected_spaces, PERTURBATOR, "s", 0);

	assert_sdb_eq (db, expected, "spaces save (no current, empty stack)");
	sdb_free (db);

	r_spaces_set (spaces, PERTURBATOR);
	db = sdb_new0 ();
	r_serialize_spaces_save (db, spaces);

	sdb_set (expected, "spacestack", "[\""PERTURBATOR_JSON"\"]", 0);

	assert_sdb_eq (db, expected, "spaces save (current, empty stack)");
	sdb_free (db);

	r_spaces_push (spaces, "a");
	r_spaces_push (spaces, "b");
	db = sdb_new0 ();
	r_serialize_spaces_save (db, spaces);

	sdb_set (expected, "spacestack", "[\""PERTURBATOR_JSON"\",\"a\",\"b\"]", 0);
	assert_sdb_eq (db, expected, "spaces save (current, stack)");

	sdb_free (db);
	sdb_free (expected);
	mu_end;
}

bool test_spaces_load_noname_nostack(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "name", "myspaces", 0);
	sdb_set (db, "spacestack", "[\"*\"]", 0);
	Sdb *db_spaces = sdb_ns (db, "spaces", true);
	sdb_set (db_spaces, "a", "s", 0);
	sdb_set (db_spaces, "b", "s", 0);
	sdb_set (db_spaces, "c", "s", 0);
	sdb_set (db_spaces, PERTURBATOR, "s", 0);

	RSpaces *spaces = r_spaces_new ("fixed name");
	char *err = NULL;
	bool suck = r_serialize_spaces_load (db, spaces, false, &err);
	mu_assert (err, err == NULL);
	mu_assert ("load success", suck);
	mu_assert_streq (spaces->name, "fixed name", "spaces load without name");
	mu_assert_null (spaces->current, "spaces load no current");
	mu_assert_eq (r_list_length (spaces->spacestack), 0, "empty spacestack");
	RBIter rbiter;
	RSpace *space;
	int i = 0;
	r_rbtree_foreach (spaces->spaces, rbiter, space, RSpace, rb) {
		switch (i) {
			case 0:
				mu_assert_streq (space->name, PERTURBATOR, "loaded spaces");
				break;
			case 1:
				mu_assert_streq (space->name, "a", "loaded spaces");
				break;
			case 2:
				mu_assert_streq (space->name, "b", "loaded spaces");
				break;
			case 3:
				mu_assert_streq (space->name, "c", "loaded spaces");
				break;
			default:
				break;	
		}
		i++;
	}
	mu_assert_eq (i, 4, "loaded spaces count");
	r_spaces_free (spaces);

	sdb_free (db);
	mu_end;
}

bool test_spaces_load_name_stack(void) {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "name", "myspaces", 0);
	sdb_set (db, "spacestack", "[\"a\",\"*\",\""PERTURBATOR_JSON"\",\"b\",\""PERTURBATOR_JSON"\"]", 0);
	Sdb *db_spaces = sdb_ns (db, "spaces", true);
	sdb_set (db_spaces, "a", "s", 0);
	sdb_set (db_spaces, "b", "s", 0);
	sdb_set (db_spaces, "c", "s", 0);
	sdb_set (db_spaces, PERTURBATOR, "s", 0);

	RSpaces *spaces = r_spaces_new ("");
	char *err = NULL;
	bool suck = r_serialize_spaces_load (db, spaces, true, &err);
	mu_assert (err, err == NULL);
	mu_assert ("load success", suck);
	mu_assert_streq (spaces->name, "myspaces", "loaded name");
	mu_assert_notnull (spaces->current, "current non-null");
	mu_assert_streq (spaces->current->name, PERTURBATOR, "current");
	mu_assert_eq (r_list_length (spaces->spacestack), 4, "spacestack size");
	mu_assert_streq ((const char *)r_list_get_n (spaces->spacestack, 0), "a", "spacestack");
	mu_assert_streq ((const char *)r_list_get_n (spaces->spacestack, 1), "*", "spacestack");
	mu_assert_streq ((const char *)r_list_get_n (spaces->spacestack, 2), PERTURBATOR, "spacestack");
	mu_assert_streq ((const char *)r_list_get_n (spaces->spacestack, 3), "b", "spacestack");
	RBIter rbiter;
	RSpace *space;
	int i = 0;
	r_rbtree_foreach (spaces->spaces, rbiter, space, RSpace, rb) {
		switch (i) {
			case 0:
				mu_assert_streq (space->name, PERTURBATOR, "loaded spaces");
				break;
			case 1:
				mu_assert_streq (space->name, "a", "loaded spaces");
				break;
			case 2:
				mu_assert_streq (space->name, "b", "loaded spaces");
				break;
			case 3:
				mu_assert_streq (space->name, "c", "loaded spaces");
				break;
			default:
				break;	
		}
		i++;
	}
	mu_assert_eq (i, 4, "loaded spaces count");
	r_spaces_free (spaces);

	sdb_free (db);
	mu_end;
}

int all_tests() {
	mu_run_test (test_spaces_save);
	mu_run_test (test_spaces_load_noname_nostack);
	mu_run_test (test_spaces_load_name_stack);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}