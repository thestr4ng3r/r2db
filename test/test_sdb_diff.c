
#include "sdb_diff.h"
#include "minunit.h"

const char *base_query =
	"test/a=123\n"
	"test/c=hello\n"
	"test/b=test\n"
	"test/subspace/here=lol\n"
	"test/subspace/some=values\n"
	"test/subspace/are=saved\n";

static Sdb *test_sdb_new() {
	Sdb *r = sdb_new0 ();
	sdb_query (r, base_query);
	sdb_ns (r, "emptyns", true);
	return r;
}

bool test_sdb_diff_equal(void) {
	Sdb *a = test_sdb_new ();
	Sdb *b = test_sdb_new ();
	mu_assert ("equal db (no diff)", sdb_diff (a, b, NULL));
	char *diff;
	mu_assert ("equal db (diff)", sdb_diff (a, b, &diff));
	mu_assert_streq (diff, "", "equal db diff");
	free (diff);
	mu_end;
}

bool test_sdb_diff_ns_empty(void) {
	Sdb *a = test_sdb_new ();
	Sdb *b = test_sdb_new ();
	sdb_ns_unset (b, "emptyns", NULL);

	mu_assert ("empty ns removed (no diff)", !sdb_diff (a, b, NULL));
	char *diff;
	mu_assert ("empty ns removed (diff)", !sdb_diff (a, b, &diff));
	mu_assert_streq (diff, "-NS emptyns\n", "empty ns removed diff");
	free (diff);

	mu_assert ("empty ns added (no diff)", !sdb_diff (b, a, NULL));
	mu_assert ("empty ns added (diff)", !sdb_diff (b, a, &diff));
	mu_assert_streq (diff, "+NS emptyns\n", "empty ns added diff");
	free (diff);

	mu_end;
}

int all_tests() {
	mu_run_test (test_sdb_diff_equal);
	mu_run_test (test_sdb_diff_ns_empty);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}