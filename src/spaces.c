
#include <r_project.h>

/*
 * SDB Format:
 *
 * /
 *   name=<spaces name>
 *   current=<space name>
 *   spacestack=<space name>,<space name>,<space name>
 *   /spaces
 *     <space name>
 *     ...
 */


static char *sdb_array_escape(const char *s) {
	r_return_val_if_fail (s, NULL);
	size_t l = strlen (s);
	const char *end = s + l;
	char *r = malloc (l * 2 + 1);
	if (!r) {
		return NULL;
	}
	char *cur = r;
	for (; s != end; s++) {
		char c = *s;
		if (c == SDB_RS || c == '\\') {
			*cur++ = '\\';
			if (c == SDB_RS) {
				c = '_';
			}
		}
		*cur++ = c;
	}
	*cur = '\0';
	return r;
}

static char *sdb_array_unescape(const char *s) {
	r_return_val_if_fail (s, NULL);
	size_t l = strlen (s);
	const char *end = s + l;
	char *r = malloc(l + 1);
	if (!r) {
		return NULL;
	}
	char *cur = r;
	for (; s != end; cur++) {
		char c = *s++;
		if (c == '\\') {
			c = *s++;
			if (c == '_') {
				c = ',';
			}
		}
		*cur = c;
	}
	*cur = '\0';
	return r;
}

R_API void r_project_save_spaces(RSpaces *spaces, Sdb *db) {
	sdb_set (db, "name", spaces->name, 0);
	if (spaces->current) {
		sdb_set (db, "current", spaces->current->name, 0);
	}
	Sdb *db_spaces = sdb_ns (db, "spaces", true);
}

R_API void r_project_load_spaces(RSpaces *spaces, Sdb *db, bool name) {

}