#include <sdb_archive.h>
#include "minunit.h"
#include "test_utils.h"


static Sdb *ref() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "testkey", "testval", 0);
	sdb_set (db, "testkey2", "testval2", 0);
	sdb_set (db, "t35tk3y", "t35tv4l", 0);

	Sdb *sub = sdb_ns (db, "subns", true);
	sdb_set (sub, "asjdk", "jdskfj", 0);
	sdb_set (sub, "asjdsafk", "jdskwefdfj", 0);
	sdb_set (sub, "asjasdfdk", "jdshfdghkfj", 0);

	Sdb *subsub = sdb_ns (sub, "deepersubns", true);
	sdb_set (subsub, "fjksdf", "fjsdlkf", 0);
	sdb_set (subsub, "fjksefwfddf", "fjsdlasdfkf", 0);
	sdb_set (subsub, "fjksdfhhdf", "fjsadfdlkf", 0);
	sdb_set (subsub, "fjdfhksdf", "fjs4tdlkf", 0);

	return db;
}

#define FILENAME "/tmp/sdb_archive_test.tar.gz"

bool test_sdb_archive(void) {
	remove (FILENAME);
	Sdb *db = ref ();
	sdb_archive_save (db, FILENAME);
	sdb_free (db);
	db = sdb_archive_load (FILENAME);
	Sdb *refdb = ref ();
	assert_sdb_eq (db, refdb, "archive save/load");
	free (db);
	free (refdb);
	remove (FILENAME);
	mu_end;
}

int all_tests() {
	mu_run_test (test_sdb_archive);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
