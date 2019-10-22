
#include <r_project.h>

#include <nxjson.h>

#include "serialize_util.h"

/*
 * SDB Format:
 *
 * /
 *   name=<spaces name>
 *   spacestack=[<space name>,<space name>,<space name>, <current>] (json)
 *   /spaces
 *     <space name>="s"
 *     ...
 */

#define KEY_NAME "name"
#define KEY_SPACESTACK "spacestack"
#define KEY_SPACES "spaces"

R_API bool r_serialize_spaces_save(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces) {
	sdb_set (db, KEY_NAME, spaces->name, 0);

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
	pj_s (j, spaces->current ? spaces->current->name : "*"); // push current manually, will be popped on load
	sdb_set (db, KEY_SPACESTACK, pj_string (j), 0);
	pj_free (j);

	Sdb *db_spaces = sdb_ns (db, KEY_SPACES, true);
	RBIter rbiter;
	RSpace *space;
	r_rbtree_foreach (spaces->spaces, rbiter, space, RSpace, rb) {
		sdb_set (db_spaces, space->name, "s", 0);
	}

	return true;
}

int foreach_space_cb(void *user, const char *k, const char *v) {
	RSpaces *spaces = user;
	r_spaces_add (spaces, k);
	return true;
}

R_API bool r_serialize_spaces_load(R_NONNULL Sdb *db, R_NONNULL RSpaces *spaces, bool load_name, R_NULLABLE char **err) {
	if (load_name) {
		char *old_name = (char *)spaces->name;
		spaces->name = sdb_get (db, KEY_NAME, NULL);
		if (!spaces->name) {
			spaces->name = old_name;
			SERIALIZE_ERR ("failed to get spaces name from db");
			return false;
		}
		free (old_name);
	}

	Sdb *db_spaces = sdb_ns (db, KEY_SPACES, false);
	if (!db_spaces) {
		SERIALIZE_ERR ("failed to get spaces sub-namespace");
		return false;
	}
	sdb_foreach (db_spaces, foreach_space_cb, spaces);

	r_list_purge (spaces->spacestack);
	char *stack_json_str = sdb_get (db, KEY_SPACES, NULL);
	if (!stack_json_str) {
		SERIALIZE_ERR ("stackspace is missing");
		return false;
	}

	bool res = true;
	const nx_json *stack_json = nx_json_parse_utf8 (stack_json_str); // TODO: get json error
	if (!stack_json) {
		SERIALIZE_ERR ("failed to parse stackspace json"); // TODO: print json error
		res = false;
		goto beach;
	}
	if (stack_json->type != NX_JSON_ARRAY) {
		SERIALIZE_ERR ("stackspace json is not an array");
		res = false;
		goto beach;
	}
	nx_json *stack_element;
	for (stack_element = stack_json->children.first; stack_element; stack_element = stack_element->next) {
		if (stack_element->type != NX_JSON_STRING) {
			SERIALIZE_ERR ("stackspace element is not a string");
			res = false;
			goto beach;
		}
		RSpace *space = r_spaces_get (spaces, stack_element->text_value);
		r_list_append (spaces->spacestack, space ? space->name : "*");
	}

	r_spaces_pop (spaces); // current is the top stack element, pop it

beach:
	nx_json_free (stack_json);
	free (stack_json_str);
	return res;
}