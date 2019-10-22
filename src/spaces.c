
#include <r_project.h>

/*
 * SDB Format:
 *
 * /
 *   name=<spaces name>
 *   current=<space name>
 *   spacestack=[<space name>,<space name>,<space name>] (json)
 *   /spaces
 *     <space name>="s"
 *     ...
 */

R_API bool r_project_save_spaces(Sdb *db, RSpaces *spaces) {
	sdb_set (db, "name", spaces->name, 0);
	if (spaces->current) {
		sdb_set (db, "current", spaces->current->name, 0);
	}

	PJ *j = pj_new ();
	if(!j) {
		return false;
	}
	pj_a (j);
	RListIter *iter;
	char *spacename;
	r_list_foreach (spaces->spacestack, iter, spacename) {
		pj_s (j, spacename);
	}
	sdb_set (db, "spacestack", pj_string (j), 0);
	pj_free (j);

	Sdb *db_spaces = sdb_ns (db, "spaces", true);
	RBIter rbiter;
	RSpace *space;
	r_rbtree_foreach (spaces->spaces, rbiter, space, RSpace, rb) {
		sdb_set (db_spaces, space->name, "s", 0);
	}

	return true;
}

R_API void r_project_load_spaces(Sdb *db, RSpaces *spaces, bool name) {
}