
#include <r_serialize.h>
#include "minunit.h"
#include "test_utils.h"

Sdb *ref_0_db() {
	Sdb *db = sdb_new0 ();

	sdb_set (db, "base", "-1337", 0);
	sdb_set (db, "realnames", "1", 0);

	Sdb *spaces_db = sdb_ns (db, "spaces", true);
	sdb_set (spaces_db, "name", "fs", 0);
	sdb_set (spaces_db, "spacestack", "[\"reveries\"]", 0);
	Sdb *spaces_spaces_db = sdb_ns (spaces_db, "spaces", true);
	sdb_set (spaces_spaces_db, "ghost", "s", 0);
	sdb_set (spaces_spaces_db, "reveries", "s", 0);

	Sdb *tags_db = sdb_ns (db, "tags", true);
	sdb_set (tags_db, "tag."PERTURBATOR, PERTURBATOR, 0);
	sdb_set (tags_db, "tag.lotus", "eater", 0);

	Sdb *zones_db = sdb_ns (db, "zones", true);
	sdb_set (zones_db, "blackwater park", "{\"from\":12345,\"to\":12648243}", 0);
	sdb_set (zones_db, PERTURBATOR, "{\"from\":3735928559,\"to\":18446744073709551614}", 0);

	Sdb *flags_db = sdb_ns (db, "flags", true);
	sdb_set (flags_db, "damnation", "{\"realname\":\"Damnation\",\"demangled\":true,\"offset\":3582,\"size\":16,\"space\":\"reveries\",\"color\":\"white\",\"comment\":\"windowpane\",\"alias\":\"d4mn4t10n\"}", 0);
	sdb_set (flags_db, "deliverance", "{\"realname\":\"deliverance\",\"demangled\":false,\"offset\":66,\"size\":19}", 0);

	return db;
}

RFlag *ref_0_flag() {
	RFlag *flag = r_flag_new ();

	flag->base = -1337;
	flag->realnames = true;

	r_flag_set (flag, "deliverance", 0x42 + 1337, 0x13);

	r_flag_space_set (flag, "ghost");
	r_flag_space_set (flag, "reveries");

	RFlagItem *damnation = r_flag_set (flag, "damnation", 0x1337, 0x10);
	damnation->demangled = true;
	r_flag_item_set_realname (damnation, "Damnation");
	r_flag_item_set_color (damnation, "white");
	r_flag_item_set_comment (damnation, "windowpane");
	r_flag_item_set_alias (damnation, "d4mn4t10n");

	r_flag_tags_set (flag, "lotus", "eater");
	r_flag_tags_set (flag, PERTURBATOR, PERTURBATOR);

	r_flag_zone_add (flag, "blackwater park", 0xc0ff33);
	r_flag_zone_add (flag, "blackwater park", 12345);
	r_flag_zone_add (flag, PERTURBATOR, 0xdeadbeef);
	r_flag_zone_add (flag, PERTURBATOR, UT64_MAX - 1);

	return flag;
}

Sdb *ref_1_db() {
	Sdb *db = sdb_new0 ();

	sdb_set (db, "base", "0", 0);
	sdb_set (db, "realnames", "0", 0);

	Sdb *spaces_db = sdb_ns (db, "spaces", true);
	sdb_set (spaces_db, "name", "fs", 0);
	sdb_set (spaces_db, "spacestack", "[\"*\"]", 0);
	sdb_ns (spaces_db, "spaces", true);
	sdb_ns (db, "tags", true);
	sdb_ns (db, "zones", true);
	sdb_ns (db, "flags", true);

	return db;
}

RFlag *ref_1_flag() {
	RFlag *flag = r_flag_new ();
	flag->base = 0;
	flag->realnames = false;
	return flag;
}

static bool test_save(RFlag *flag, Sdb *ref) {
	Sdb *db = sdb_new0 ();
	r_serialize_flag_save (db, flag);
	assert_sdb_eq (db, ref, "save");
	sdb_free (db);
	sdb_free (ref);
	r_flag_free (flag);
	return true;
}

static bool test_load(Sdb *db, RFlag *ref) {
	RFlag *flag = r_flag_new ();

	char *err = NULL;
	bool suck = r_serialize_flag_load (db, flag, &err);
	mu_assert (err, err == NULL);
	mu_assert ("load success", suck);

	// TODO: compare everything in flag against ref

	sdb_free (db);
	r_flag_free (ref);
	return true;
}

#define TEST_CALL(name, call) \
bool name() { \
	if (!(call)) { \
		return false; \
	} \
	mu_end; \
}

TEST_CALL (test_flag_0_save, test_save(ref_0_flag (), ref_0_db ()));
TEST_CALL (test_flag_1_save, test_save(ref_1_flag (), ref_1_db ()));
TEST_CALL (test_flag_0_load, test_load(ref_0_db (), ref_0_flag ()));
TEST_CALL (test_flag_1_load, test_load(ref_1_db (), ref_1_flag ()));

int all_tests() {
	mu_run_test (test_flag_0_save);
	mu_run_test (test_flag_1_save);
	mu_run_test (test_flag_0_load);
	mu_run_test (test_flag_1_load);
	return tests_passed != tests_run;
}

int main(int argc, char **argv) {
	return all_tests();
}