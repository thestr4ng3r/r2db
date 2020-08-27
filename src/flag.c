/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_serialize.h>

#include "serialize_util.h"

#if R_FLAG_ZONE_USE_SDB
#error "R_FLAG_ZONE_USE_SDB not supported by r_serialize"
#endif

/*
 * SDB Format:
 *
 * /
 *   base=<base>
 *   realnames=<realnames?"1":"0">
 *   /spaces
 *     see spaces.c
 *   /tags
 *     like RFlag.tags
 *   /zones
 *     <zone name>={"from":<from>,"to":<to>}
 *   /flags
 *     <flag name>={"realname":<str>,"demangled":<bool>,"offset":<uint>,"size":<uint>,"space":<str>,"color":<str>,"comment":<str>,"alias":<str>}
 *
 */

R_API void r_serialize_flag_zones_save(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones) {
	RListIter *it;
	RFlagZoneItem *item;
	r_list_foreach (zones, it, item) {
		PJ *j = pj_new ();
		if (!j) {
			return;
		}
		pj_o (j);
		pj_kn (j, "from", item->from);
		pj_kn (j, "to", item->to);
		pj_end (j);
		sdb_set (db, item->name, pj_string (j), 0);
		pj_free (j);
	}
}

static bool zone_load_cb(void *user, const char *k, const char *v) {
	RList *list = user;
	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json  = r_json_parse (json_str);
	if (!json) {
		free (json_str);
		return false;
	}
	if (json->type != R_JSON_OBJECT) {
		goto beach;
	}
	const RJson *child;
	RFlagZoneItem *item = R_NEW0 (RFlagZoneItem);
	if (!item) {
		goto beach;
	}
	item->name = strdup (k);
	if (!item->name) {
		free (item);
		goto beach;
	}
	for (child = json->children.first; child; child = child->next) {
		if (child->type != R_JSON_INTEGER) {
			continue;
		}
		if (strcmp (child->key, "from") == 0) {
			item->from = child->num.u_value;
		} else if (strcmp (child->key, "to") == 0) {
			item->to = child->num.u_value;
		}
	}
	r_list_append (list, item);
beach:
	r_json_free (json);
	free (json_str);
	return true;
}

R_API bool r_serialize_flag_zones_load(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones, R_NULLABLE char **err) {
	r_return_val_if_fail (zones, false);
	r_list_purge (zones);
	bool r = sdb_foreach (db, zone_load_cb, zones);
	if (!r) {
		SERIALIZE_ERR ("failed to parse a flag zone json");
	}
	return r;
}

static bool flag_save_cb(RFlagItem *flag, void *user) {
	Sdb *db = user;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_o (j);
	if (flag->realname) {
		pj_ks (j, "realname", flag->realname);
	}
	pj_kb (j, "demangled", flag->demangled);
	pj_kn (j, "offset", flag->offset);
	pj_kn (j, "size", flag->size);
	if (flag->space) {
		pj_ks (j, "space", flag->space->name);
	}
	if (flag->color) {
		pj_ks (j, "color", flag->color);
	}
	if (flag->comment) {
		pj_ks (j, "comment", flag->comment);
	}
	if (flag->alias) {
		pj_ks (j, "alias", flag->alias);
	}
	pj_end (j);
	sdb_set (db, flag->name, pj_string (j), 0);
	pj_free (j);
	return true;
}

R_API void r_serialize_flag_save(R_NONNULL Sdb *db, R_NONNULL RFlag *flag) {
	r_serialize_spaces_save (sdb_ns (db, "spaces", true), &flag->spaces);
	char buf[32];
	if (snprintf (buf, sizeof (buf), "%"PFMT64d, flag->base) < 0) {
		return;
	}
	sdb_set (db, "base", buf, 0);
	sdb_set (db, "realnames", flag->realnames ? "1" : "0", 0);
	sdb_copy (flag->tags, sdb_ns (db, "tags", true));
	r_serialize_flag_zones_save (sdb_ns (db, "zones", true), flag->zones);
	r_flag_foreach (flag, flag_save_cb, sdb_ns (db, "flags", true));
}

typedef enum {
	FLAG_FIELD_REALNAME,
	FLAG_FIELD_DEMANGLED,
	FLAG_FIELD_OFFSET,
	FLAG_FIELD_SIZE,
	FLAG_FIELD_SPACE,
	FLAG_FIELD_COLOR,
	FLAG_FIELD_COMMENT,
	FLAG_FIELD_ALIAS
} FlagField;

typedef struct {
	RFlag *flag;
	HtPP *fields;
} FlagLoadCtx;

static bool flag_load_cb(void *user, const char *k, const char *v) {
	FlagLoadCtx *ctx = user;

	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *json = r_json_parse (json_str);
	if (!json || json->type != R_JSON_OBJECT) {
		free (json_str);
		return false;
	}

	RFlagItem proto = {0 };
	bool offset_set = false;
	bool size_set = false;

	const RJson *child;
	for (child = json->children.first; child; child = child->next) {
		bool found;
		FlagField field = (FlagField)ht_pp_find (ctx->fields, child->key, &found);
		if (!found) {
			continue;
		}
		switch (field) {
		case FLAG_FIELD_REALNAME:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.realname = (char *)child->str_value;
			break;
		case FLAG_FIELD_DEMANGLED:
			if (child->type != R_JSON_BOOLEAN) {
				break;
			}
			proto.demangled = child->num.u_value != 0;
			break;
		case FLAG_FIELD_OFFSET:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.offset = child->num.u_value;
			offset_set = true;
			break;
		case FLAG_FIELD_SIZE:
			if (child->type != R_JSON_INTEGER) {
				break;
			}
			proto.size = child->num.u_value;
			size_set = true;
			break;
		case FLAG_FIELD_SPACE:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.space = r_flag_space_get (ctx->flag, child->str_value);
			break;
		case FLAG_FIELD_COLOR:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.color = (char *)child->str_value;
			break;
		case FLAG_FIELD_COMMENT:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.comment = (char *)child->str_value;
			break;
		case FLAG_FIELD_ALIAS:
			if (child->type != R_JSON_STRING) {
				break;
			}
			proto.alias = (char *)child->str_value;
			break;
		default:
			break;
		}
	}

	bool res = true;
	if (!offset_set || !size_set) {
		res = false;
		goto beach;
	}

	RFlagItem *item = r_flag_set (ctx->flag, k, proto.offset - ctx->flag->base, proto.size);
	if (proto.realname) {
		r_flag_item_set_realname (item, proto.realname);
	}
	item->demangled = proto.demangled;
	item->space = proto.space;
	if (proto.color) {
		r_flag_item_set_color (item, proto.color);
	}
	if (proto.comment) {
		r_flag_item_set_comment (item, proto.comment);
	}
	if(proto.alias) {
		r_flag_item_set_alias (item, proto.alias);
	}

beach:
	r_json_free (json);
	free (json_str);
	return res;
}

static bool load_flags(R_NONNULL Sdb *flags_db, R_NONNULL RFlag *flag) {
	FlagLoadCtx ctx = { flag, ht_pp_new0 () };
	if (!ctx.fields) {
		return false;
	}
	ht_pp_insert (ctx.fields, "realname", (void *)FLAG_FIELD_REALNAME);
	ht_pp_insert (ctx.fields, "demangled", (void *)FLAG_FIELD_DEMANGLED);
	ht_pp_insert (ctx.fields, "offset", (void *)FLAG_FIELD_OFFSET);
	ht_pp_insert (ctx.fields, "size", (void *)FLAG_FIELD_SIZE);
	ht_pp_insert (ctx.fields, "space", (void *)FLAG_FIELD_SPACE);
	ht_pp_insert (ctx.fields, "color", (void *)FLAG_FIELD_COLOR);
	ht_pp_insert (ctx.fields, "comment", (void *)FLAG_FIELD_COMMENT);
	ht_pp_insert (ctx.fields, "alias", (void *)FLAG_FIELD_ALIAS);
	bool r = sdb_foreach (flags_db, flag_load_cb, &ctx);
	ht_pp_free (ctx.fields);
	return r;
}

R_API bool r_serialize_flag_load(R_NONNULL Sdb *db, R_NONNULL RFlag *flag, R_NULLABLE char **err) {
	r_flag_unset_all (flag);

	const char *str = sdb_const_get (db, "base", NULL);
	if (!str) {
		SERIALIZE_ERR ("flag base key is missing");
		return false;
	}
	flag->base = strtoll (str, NULL, 0);

	str = sdb_const_get (db, "realnames", 0);
	if (!str) {
		SERIALIZE_ERR ("flag realnames key is missing");
		return false;
	}
	flag->realnames = strtoul (str, NULL, 0) ? true : false;

	Sdb *spaces_db = sdb_ns (db, "spaces", false);
	if (!spaces_db) {
		SERIALIZE_ERR ("missing spaces namespace");
		return false;
	}
	if (!r_serialize_spaces_load (spaces_db, &flag->spaces, false, err)) {
		return false;
	}

	Sdb *tags_db = sdb_ns (db, "tags", false);
	if (!tags_db) {
		SERIALIZE_ERR ("missing tags namespace");
		return false;
	}
	sdb_copy (tags_db, flag->tags);

	Sdb *zones_db = sdb_ns (db, "zones", false);
	if (!zones_db) {
		SERIALIZE_ERR ("missing zones namespace");
		return false;
	}
	r_flag_zone_reset (flag);
	if (!r_serialize_flag_zones_load (zones_db, flag->zones, err)) {
		return false;
	}

	Sdb *flags_db = sdb_ns (db, "flags", false);
	if (!flags_db) {
		SERIALIZE_ERR ("missing flags sub-namespace");
		return false;
	}
	if (!load_flags (flags_db, flag)) {
		SERIALIZE_ERR ("failed to parse a flag json");
		return false;
	}

	return true;
}
