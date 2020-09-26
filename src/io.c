/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include <r_serialize.h>
#include "serialize_util.h"
#include <errno.h>

/*
 *
 * SDB Format:
 *
 * /
 *   /files
 *     <fd>={TODO}
 */

R_API void r_serialize_io_files_save(R_NONNULL Sdb *db, R_NONNULL RIO *io) {
}

R_API bool r_serialize_io_files_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	return true;
}

R_API void r_serialize_io_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal) {
}

R_API bool r_serialize_io_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res) {
	return true;
}
