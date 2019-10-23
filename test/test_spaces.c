
#include <r_serialize.h>
#include "minunit.h"

#define PERTURBATOR "\\,\";][}{'"

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

	mu_assert ("spaces save", sdb_diff (expected, db, diff_cb, NULL));

	sdb_free (db);
	sdb_free (expected);
	mu_end;
}

int all_tests() {
	mu_run_test (test_spaces_save);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}