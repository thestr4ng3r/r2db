/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_project.h>
#include <r_core.h>

#define CMD_PREFIX "PP"

static void usage(const RCore* const core) {
	const char* help[] = {
		"Usage: "CMD_PREFIX, "",	       "# Projects",
		"PPs",               "[file]",     "save project",
		"PPo",	             "[file]",     "load project",
		NULL
	};
	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static void _cmd_project(RCore *core, const char *input) {
	switch (*input) {
	default:
		usage(core);
		break;
	}
}

static int cmd_project(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, CMD_PREFIX, strlen(CMD_PREFIX))) {
		_cmd_project (core, input + strlen(CMD_PREFIX));
		return true;
	}
	return false;
}

RCorePlugin r_core_plugin_r2db = {
	.name = "r2db",
	.desc = "Projects",
	.license = "LGPL3",
	.call = cmd_project
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_r2db,
	.version = R2_VERSION
};
#endif
