
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
	sdb_set (flags_db, "d4mn4t10n", "{\"realname\":\"d4mn4t10n\",\"demangled\":false,\"offset\":3582,\"size\":1}", 0);
	sdb_set (flags_db, "deliverance", "{\"realname\":\"deliverance\",\"demangled\":false,\"offset\":66,\"size\":19}", 0);

	return db;
}

RFlag *ref_0_flag() {
	RFlag *flag = r_flag_new ();

	flag->base = -1337;
	flag->realnames = true;

	r_flag_set (flag, "deliverance", 0x42 + 1337, 0x13);
	r_flag_set (flag, "d4mn4t10n", 0x1337, 1);

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

	r_flag_zone_add (flag, PERTURBATOR, 0xdeadbeef);
	r_flag_zone_add (flag, PERTURBATOR, UT64_MAX - 1);
	r_flag_zone_add (flag, "blackwater park", 0xc0ff33);
	r_flag_zone_add (flag, "blackwater park", 12345);

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

static bool space_eq(RSpace *actual, RSpace *expected) {
	mu_assert ("space null", (!actual) == (!expected));
	if (expected != NULL) {
		mu_assert_streq (actual->name, expected->name, "space name");
	}
	return true;
}

static bool spaces_eq(RSpaces *actual, RSpaces *expected) {
	assert_streq_null (actual->name, expected->name, "spaces name");

	RBIter actual_iter = r_rbtree_first (actual->spaces);
	RBIter expected_iter = r_rbtree_first (expected->spaces);
	while (r_rbtree_iter_has (&actual_iter) && r_rbtree_iter_has (&expected_iter)) {
		RSpace *actual_space = r_rbtree_iter_get (&actual_iter, RSpace, rb);
		RSpace *expected_space = r_rbtree_iter_get (&expected_iter, RSpace, rb);
		if (!space_eq (actual_space, expected_space)) {
			return false;
		}
		r_rbtree_iter_next (&actual_iter);
		r_rbtree_iter_next (&expected_iter);
	}
	mu_assert ("spaces count", !r_rbtree_iter_has (&actual_iter) && !r_rbtree_iter_has (&expected_iter));

	if (!space_eq (actual->current, expected->current)) {
		return false;
	}

	RListIter *actual_stack_iter = r_list_iterator (actual->spacestack);
	RListIter *expected_stack_iter = r_list_iterator (expected->spacestack);
	while (actual_stack_iter && expected_stack_iter) {
		RSpace *actual_space = r_list_iter_get (actual_stack_iter);
		RSpace *expected_space = r_list_iter_get (expected_stack_iter);
		if (!space_eq (actual_space, expected_space)) {
			return false;
		}
	}
	mu_assert ("spacestack count", !actual_stack_iter && !expected_stack_iter);

	return true;
}

typedef struct {
	bool equal;
	RFlag *other;
} FlagCmpCtx;

static bool flag_cmp(RFlagItem *actual, RFlagItem *expected) {
	mu_assert_notnull (expected, "flag");
	assert_streq_null (actual->realname, expected->realname, "flag realname");
	mu_assert_eq (actual->demangled, expected->demangled, "flag demangled");
	mu_assert_eq_fmt (actual->offset, expected->offset, "flag offset", "0x%"PFMT64x);
	mu_assert_eq_fmt (actual->size, expected->size, "flag size", "0x%"PFMT64x);
	mu_assert_eq (!actual->space, !expected->space, "flag space null");
	if (expected->space) {
		mu_assert_streq (actual->space->name, expected->space->name, "flag space");
	}
	assert_streq_null (actual->color, expected->color, "flag color");
	assert_streq_null (actual->comment, expected->comment, "flag comment");
	assert_streq_null (actual->alias, expected->alias, "flag alias");
	return true;
}

static bool flag_cmp_cb(RFlagItem *fi, void *user) {
	FlagCmpCtx *ctx = user;
	RFlagItem *fo = r_flag_get (ctx->other, fi->name);
	if(!flag_cmp (fi, fo)) {
		ctx->equal = false;
		return false;
	}
	return true;
}

static bool test_load(Sdb *db, RFlag *ref) {
	RFlag *flag = r_flag_new ();

	bool suck = r_serialize_flag_load (db, flag, NULL);
	sdb_free (db);
	mu_assert ("load success", suck);

	if (!spaces_eq (&flag->spaces, &ref->spaces)) {
		return false;
	}

	mu_assert_eq (r_list_length (flag->zones), r_list_length (ref->zones), "zones count");
	RListIter *actual_iter;
	RFlagZoneItem *actual_zone;
	r_list_foreach (flag->zones, actual_iter, actual_zone) {
		RListIter *expected_iter;
		RFlagZoneItem *expected_zone;
		r_list_foreach (ref->zones, expected_iter, expected_zone) {
			if (strcmp (actual_zone->name, expected_zone->name) != 0) {
				continue;
			}
			mu_assert_streq (actual_zone->name, expected_zone->name, "zone name");
			mu_assert_eq_fmt (actual_zone->from, expected_zone->from, "zone from", "0x%"PFMT64x);
			mu_assert_eq_fmt (actual_zone->to, expected_zone->to, "zone from", "0x%"PFMT64x);
			goto kontinju;
		}
		mu_assert ("zone", false);
kontinju:
		continue;
	}

	mu_assert_eq_fmt (flag->base, ref->base, "base", "0x%"PFMT64x);
	mu_assert_eq (flag->realnames, ref->realnames, "realnames");
	assert_sdb_eq (flag->tags, ref->tags, "tags");

	mu_assert_eq (r_flag_count (flag, NULL), r_flag_count (ref, NULL), "flags count");
	FlagCmpCtx cmp_ctx = { true, ref };
	r_flag_foreach (flag, flag_cmp_cb, &cmp_ctx);

	r_flag_free (flag);
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
