/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"

/*
 * SDB Format:
 *
 * /
 *   /flags => see flag.c
 */

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core) {
	r_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);
}

R_API bool r_serialize_core_load(R_NONNULL Sdb *db, R_NONNULL RCore *core, R_NULLABLE char **err) {
	Sdb *flags_db = sdb_ns (db, "flags", false);
	if (!flags_db) {
		SERIALIZE_ERR ("missing flags namespace");
		return false;
	}
	if (!r_serialize_flag_load (flags_db, core->flags, err)) {
		return false;
	}
	return true;
}