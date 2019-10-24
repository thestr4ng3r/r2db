
#include <r_serialize.h>

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
 *     <flag name>=[{"realname":<str>,"demangled":<bool>,"offset":<uint>,"size":<uint>,"space":<str>,"color":<str>,"comment":<str>,"alias":<str>},...]
 *
 */

R_API void r_serialize_flag_zones_save(R_NONNULL Sdb *db, R_NONNULL RList/*<RFlagZoneItem *>*/ *zones) {
	RListIter it;
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

static void flag_save(PJ *j, RFlagItem *flag) {
	pj_o (j);
	pj_ks (j, "realname", flag->realname);
	pj_kb (j, "demangled", flag->demangled);
	pj_kn (j, "offset", flag->offset);
	pj_kn (j, "size", flag->size);
	pj_ks (j, "space", flag->space->name);
	pj_ks (j, "color", flag->color);
	pj_ks (j, "comment", flag->comment);
	pj_ks (j, "alias", flag->alias);
	pj_end (j);
}

static bool flag_save_list_cb(void *user, const void *k, const void *v) {
	Sdb *db = user;
	const char *name = k;
	const RList *flags = v;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);
	RListIter *it;
	RFlagItem *flag;
	r_list_foreach (flags, it, flag) {
		flag_save (j, flag);
	}
	pj_end (j);
	sdb_set (db, name, pj_string (j), 0);
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
	sdb_copy (sdb_ns (db, "tags", true), flag->tags);
	r_serialize_flag_zones_save (sdb_ns (db, "zones", true), flag->zones);
	ht_pp_foreach (flag->ht_name, flag_save_list_cb, sdb_ns (db, "flags", true));
}

