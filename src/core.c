/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 */

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core) {
	r_serialize_config_save (sdb_ns (db, "config", true), core->config);
	r_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);
}

R_API bool r_serialize_core_load(R_NONNULL Sdb *db, R_NONNULL RCore *core, R_NULLABLE char **err) {
	Sdb *subdb;
#define SUB(ns, call) \
	subdb = sdb_ns (db, ns, false); \
	if (!subdb) { \
		SERIALIZE_ERR ("missing " ns " namespace"); \
		return false; \
	} \
	if (!(call)) { \
		return false; \
	} \

	SUB ("config", r_serialize_config_load (subdb, core->config, err));
	SUB ("flags", r_serialize_flag_load (subdb, core->flags, err));
	return true;
}