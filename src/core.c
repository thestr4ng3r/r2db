/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 *   offset=<offset>
 *   blocksize=<blocksize>
 */

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core) {
	r_serialize_config_save (sdb_ns (db, "config", true), core->config);
	r_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);

	char buf[0x20];
	if (snprintf (buf, sizeof (buf), "0x%"PFMT64x, core->offset) < 0) {
		return;
	}
	sdb_set (db, "offset", buf, 0);

	if (snprintf (buf, sizeof (buf), "0x%"PFMT32x, core->blocksize) < 0) {
		return;
	}
	sdb_set (db, "blocksize", buf, 0);

	r_serialize_anal_save(db, core);
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

	const char *str = sdb_get (db, "offset", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing offset in core");
		return false;
	}
	core->offset = strtoull (str, NULL, 0);

	str = sdb_get (db, "blocksize", 0);
	if (!str || !*str) {
		SERIALIZE_ERR ("missing blocksize in core");
		return false;
	}
	core->blocksize = strtoull (str, NULL, 0);

	// handled by config already:
	// cfglog, cmdrepeat, cmdtimes

	r_serialize_anal_load(db, core);

	return true;
}
