/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>

/*
 *
 * RConfig isn't completely serialized, only the values.
 *
 * SDB Format:
 *
 * /
 *   <name>=<value>
 *   ...
 *
 */

R_API void r_serialize_config_save(R_NONNULL Sdb *db, R_NONNULL RConfig *config) {
	RListIter *iter;
	RConfigNode *node;
	r_list_foreach (config->nodes, iter, node) {
		sdb_set (db, node->name, node->value, 0);
	}
}

static bool load_config_cb(void *user, const char *k, const char *v) {
	RConfig *config = user;
	RConfigNode *node = r_config_node_get (config, k);
	if (!node) {
		return 1;
	}
	r_config_set (config, k, v);
	return 1;
}

R_API bool r_serialize_config_load(R_NONNULL Sdb *db, R_NONNULL RConfig *config, R_NULLABLE char **err) {
	sdb_foreach (db, load_config_cb, config);
	return true;
}
