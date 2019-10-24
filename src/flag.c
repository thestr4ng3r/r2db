
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

R_API void r_serialize_flag_save(R_NONNULL Sdb *db, R_NONNULL RFlag *flag) {
	r_serialize_spaces_save (sdb_ns (db, "spaces", true), &flag->spaces);
	char buf[32];
	if (snprintf (buf, sizeof (buf), "%"PFMT64d, flag->base) < 0) {
		return;
	}
	sdb_set (db, "base", buf, 0);
	sdb_set (db, "realnames", flag->realnames ? "1" : "0", 0);

	// TODO: copy tags db

	r_serialize_flag_zones_save (sdb_ns (db, "zones", true), flag->zones);
}
