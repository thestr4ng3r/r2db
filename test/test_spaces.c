
#include <r_serialize.h>
#include "sdb_diff.h"
#include "minunit.h"

#define PERTURBATOR "\\,\";][}{'"

bool test_spaces_save(void) {
	RSpaces *spaces = r_spaces_new ("myspaces");
	r_spaces_add (spaces, "a");
	r_spaces_add (spaces, "b");
	r_spaces_add (spaces, "c");
	r_spaces_add (spaces, PERTURBATOR);

	Sdb *db = sdb_new0 ();
	r_serialize_spaces_save (db, spaces);


	mu_end;
}

int all_tests() {
	mu_run_test (test_spaces_save);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}