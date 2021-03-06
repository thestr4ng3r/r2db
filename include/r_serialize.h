/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#ifndef R2DB_R_SERIALIZE_H
#define R2DB_R_SERIALIZE_H

#include <r_core.h>
#include <r_util/r_json.h>

typedef RList RSerializeResultInfo;
static inline RSerializeResultInfo *r_serialize_result_info_new(void) { return r_list_newf (free); }
static inline void r_serialize_result_info_free(RSerializeResultInfo *info) { r_list_free (info); }

// RSpaces

R_API void r_serialize_spaces_save(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces);
/**
 * @param load_name whether to overwrite the name in spaces with the value from db
 */
R_API bool r_serialize_spaces_load(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces, bool load_name, R_NULLABLE RSerializeResultInfo *res);

// RFlag

R_API void r_serialize_flag_zones_save(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones);
R_API bool r_serialize_flag_zones_load(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_flag_save(R_NONNULL Sdb *db, R_NONNULL RFlag *flag);
R_API bool r_serialize_flag_load(R_NONNULL Sdb *db, R_NONNULL RFlag *flag, R_NULLABLE RSerializeResultInfo *res);

// RConfig

R_API void r_serialize_config_save(R_NONNULL Sdb *db, R_NONNULL RConfig *config);
R_API bool r_serialize_config_load(R_NONNULL Sdb *db, R_NONNULL RConfig *config, R_NULLABLE RSerializeResultInfo *res);

// RAnal

R_API void r_serialize_anal_case_op_save(R_NONNULL PJ *j, R_NONNULL RAnalCaseOp *op);
R_API void r_serialize_anal_switch_op_save(R_NONNULL PJ *j, R_NONNULL RAnalSwitchOp *op);
R_API RAnalSwitchOp *r_serialize_anal_switch_op_load(R_NONNULL const RJson *json);

typedef void *RSerializeAnalDiffParser;
R_API RSerializeAnalDiffParser r_serialize_anal_diff_parser_new();
R_API void r_serialize_anal_diff_parser_free(RSerializeAnalDiffParser parser);
R_API R_NULLABLE RAnalDiff *r_serialize_anal_diff_load(R_NONNULL RSerializeAnalDiffParser parser, R_NONNULL const RJson *json);
R_API void r_serialize_anal_diff_save(R_NONNULL PJ *j, R_NONNULL RAnalDiff *diff);
R_API void r_serialize_anal_blocks_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);

/**
 * RAnal must not contain any blocks when calling this function!
 * All loaded blocks will have a ref of 1 after this function and should be unrefd once after loading functions.
 */
R_API bool r_serialize_anal_blocks_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE RSerializeResultInfo *res);

typedef void *RSerializeAnalVarParser;
R_API RSerializeAnalVarParser r_serialize_anal_var_parser_new();
R_API void r_serialize_anal_var_parser_free(RSerializeAnalVarParser parser);
R_API R_NULLABLE RAnalVar *r_serialize_anal_var_load(R_NONNULL RAnalFunction *fcn, R_NONNULL RSerializeAnalVarParser parser, R_NONNULL const RJson *json);

R_API void r_serialize_anal_functions_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_functions_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, RSerializeAnalDiffParser diff_parser, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_xrefs_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_xrefs_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_meta_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_meta_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_hints_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_hints_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_classes_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_classes_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_types_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_types_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_sign_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_sign_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_imports_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_imports_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_pin_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_pin_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);
R_API void r_serialize_anal_cc_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_cc_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);

R_API void r_serialize_anal_save(R_NONNULL Sdb *db, R_NONNULL RAnal *anal);
R_API bool r_serialize_anal_load(R_NONNULL Sdb *db, R_NONNULL RAnal *anal, R_NULLABLE RSerializeResultInfo *res);

// RCore

R_API void r_serialize_core_save(R_NONNULL Sdb *db, R_NONNULL RCore *core);
R_API bool r_serialize_core_load(R_NONNULL Sdb *db, R_NONNULL RCore *core, R_NULLABLE RSerializeResultInfo *res);

#endif //R2DB_R_SERIALIZE_H
