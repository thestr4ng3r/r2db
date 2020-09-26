/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"

/*
 * SDB Format:
 *
 * /
 *   /config => see config.c
 *   /flags => see flag.c
 *   /anal => see anal.c
 *   offset=<offset>
 *   blocksize=<blocksize>
 */

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core) {
	r_serialize_config_save (sdb_ns (db, "config", true), core->config);
	r_serialize_flag_save (sdb_ns (db, "flags", true), core->flags);
	r_serialize_anal_save (sdb_ns (db, "anal", true), core->anal);

	char buf[0x20];
	if (snprintf (buf, sizeof (buf), "0x%"PFMT64x, core->offset) < 0) {
		return;
	}
	sdb_set (db, "offset", buf, 0);

	if (snprintf (buf, sizeof (buf), "0x%"PFMT32x, core->blocksize) < 0) {
		return;
	}
	sdb_set (db, "blocksize", buf, 0);
}

R_API bool r_serialize_core_load(R_NONNULL Sdb *db, R_NONNULL RCore *core, R_NULLABLE RSerializeResultInfo *res) {
	Sdb *subdb;

#define SUB(ns, call) SUB_DO(ns, call, return false;)

	SUB ("config", r_serialize_config_load (subdb, core->config, res));
	SUB ("flags", r_serialize_flag_load (subdb, core->flags, res));
	SUB ("anal", r_serialize_anal_load (subdb, core->anal, res));

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

	return true;
}
