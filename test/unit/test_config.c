
#include <r_serialize.h>
#include "minunit.h"
#include "test_utils.h"

Sdb *ref_db() {
	Sdb *db = sdb_new0 ();
	sdb_set (db, "somestring", "somevalue", 0);
	sdb_set (db, "someint", "42", 0);
	sdb_set (db, "somebiggerint", "0x00001337", 0);
	return db;
}

bool test_config_save() {
	RConfig *config = r_config_new (NULL);
	r_config_set (config, "somestring", "somevalue");
	r_config_set_i (config, "someint", 42);
	r_config_set_i (config, "somebiggerint", 0x1337);
	r_config_lock (config, true);

	Sdb *db = sdb_new0 ();
	r_serialize_config_save (db, config);
	r_config_free (config);

	Sdb *expected = ref_db ();
	assert_sdb_eq (db, expected, "config save");
	sdb_free (db);
	sdb_free (expected);
	mu_end;
}

bool test_config_load() {
	RConfig *config = r_config_new (NULL);
	r_config_set (config, "somestring", "someoldvalue");
	r_config_set_i (config, "someint", 0);
	r_config_set_i (config, "somebiggerint", 0);
	r_config_lock (config, true);

	Sdb *db = ref_db ();
	sdb_set (db, "sneaky", "not part of config", 0);
	bool suck = r_serialize_config_load (db, config, NULL);
	sdb_free (db);
	mu_assert ("load success", suck);

	mu_assert_eq (r_list_length (config->nodes), 3, "count after load");
	mu_assert_streq (r_config_get (config, "somestring"), "somevalue", "loaded config string");
	mu_assert_eq_fmt (r_config_get_i (config, "someint"), (ut64)42, "loaded config int", "%"PFMT64u);
	mu_assert_eq_fmt (r_config_get_i (config, "somebiggerint"), (ut64)0x1337, "loaded config bigger int", "0x%"PFMT64x);
	r_config_free (config);
	mu_end;
}

int all_tests() {
	mu_run_test (test_config_save);
	mu_run_test (test_config_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}
