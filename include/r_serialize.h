
#ifndef R2DB_R_SERIALIZE_H
#define R2DB_R_SERIALIZE_H

#include <r_util/r_spaces.h>

R_API bool r_serialize_spaces_save(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces);
/**
 * @param load_name whether to overwrite the name in spaces with the value from db
 */
R_API bool r_serialize_spaces_load(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces, bool load_name, R_NULLABLE char **err);

#endif //R2DB_R_SERIALIZE_H
