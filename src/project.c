/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_project.h>
#include <r_serialize.h>

#include <sdb_archive.h>
#include "serialize_util.h"

#define R2DB_KEY_TYPE        "type"
#define R2DB_KEY_VERSION     "version"

#define R2DB_PROJECT_VERSION 1
#define R2DB_PROJECT_TYPE    "radare2 r2db project"


R_API RProjectErr r_project_save(RCore *core, RProject *prj) {
	sdb_set (prj, R2DB_KEY_TYPE, R2DB_PROJECT_TYPE, 0);
	sdb_set (prj, R2DB_KEY_VERSION, sdb_fmt ("%u", R2DB_PROJECT_VERSION), 0);
	r_serialize_core_save (sdb_ns (prj, "core", true), core);
	return R_PROJECT_ERR_SUCCESS;
}

R_API RProjectErr r_project_save_file(RCore *core, const char *file) {
	RProject *prj = sdb_new0 ();
	if (!prj) {
		return R_PROJECT_ERR_UNKNOWN;
	}
	r_project_save (core, prj);
	sdb_archive_save (prj, file);
	sdb_free (prj);
	return R_PROJECT_ERR_SUCCESS;
}

R_API RProjectErr r_project_load(RCore *core, RProject *prj, RSerializeResultInfo *res) {
	const char *type = sdb_const_get (prj, R2DB_KEY_TYPE, 0);
	if (!type || strcmp (type, R2DB_PROJECT_TYPE) != 0) {
		return R_PROJECT_ERR_INVALID_TYPE;
	}
	const char *version_str = sdb_const_get (prj, R2DB_KEY_VERSION, 0);
	if (!version_str) {
		return R_PROJECT_ERR_INVALID_VERSION;
	}
	unsigned long version = strtoul (version_str, NULL, 0);
	if (!version || version == ULONG_MAX) {
		return R_PROJECT_ERR_INVALID_VERSION;
	} else if (version > R2DB_PROJECT_VERSION) {
		return R_PROJECT_ERR_NEWER_VERSION;
	}

	Sdb *core_db = sdb_ns (prj, "core", false);
	if (!core_db) {
		SERIALIZE_ERR ("missing core namespace");
		return R_PROJECT_ERR_INVALID_CONTENTS;
	}
	if (!r_serialize_core_load (core_db, core, res)) {
		return R_PROJECT_ERR_INVALID_CONTENTS;
	}

	return R_PROJECT_ERR_SUCCESS;
}

R_API RProjectErr r_project_load_file(RCore *core, const char *file, RSerializeResultInfo *res) {
	RProject *prj = sdb_archive_load (file);
	if (!prj) {
		SERIALIZE_ERR ("failed to read database file");
		return R_PROJECT_ERR_UNKNOWN;
	}
	RProjectErr ret = r_project_load (core, prj, res);
	sdb_free (prj);
	return ret;
}
