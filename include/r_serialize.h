/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2DB_R_SERIALIZE_H
#define R2DB_R_SERIALIZE_H

#include <r_core.h>

// RSpaces

R_API void r_serialize_spaces_save(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces);
/**
 * @param load_name whether to overwrite the name in spaces with the value from db
 */
R_API bool r_serialize_spaces_load(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces, bool load_name, R_NULLABLE char **err);

// RFlag

R_API void r_serialize_flag_zones_save(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones);
R_API bool r_serialize_flag_zones_load(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones, R_NULLABLE char **err);
R_API void r_serialize_flag_save(R_NONNULL Sdb *db, R_NONNULL RFlag *flag);
R_API bool r_serialize_flag_load(R_NONNULL Sdb *db, R_NONNULL RFlag *flag, R_NULLABLE char **err);

// RConfig

R_API void r_serialize_config_save(R_NONNULL Sdb *db, R_NONNULL RConfig *config);
R_API bool r_serialize_config_load(R_NONNULL Sdb *db, R_NONNULL RConfig *config, R_NULLABLE char **err);

// RAnal

R_API void r_serialize_anal_blocks_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API void r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);

R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API void r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);

// RCore

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core);
R_API bool r_serialize_core_load(R_NONNULL Sdb *db, R_NONNULL RCore *core, R_NULLABLE char **err);

#endif //R2DB_R_SERIALIZE_H
