
#ifndef R2DB_SERIALIZE_UTIL_H
#define R2DB_SERIALIZE_UTIL_H

#include <r_util/r_str.h>

#define SERIALIZE_ERR(...) do { if(err) { *err = r_str_newf(__VA_ARGS__); } } while(0)

#endif //R2DB_SERIALIZE_UTIL_H
