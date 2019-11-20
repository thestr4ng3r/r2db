/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include <r_util.h>
#include <r_core.h>

#include <r_project.h>

#define CMD_PREFIX "PN"

static void usage(const RCore* const core) {
	const char* help[] = {
		"Usage: "CMD_PREFIX,	"",			"# Projects",
		CMD_PREFIX"s",			"[file]",	"save project",
		CMD_PREFIX"l",			"[file]",	"load project",
		NULL
	};
	r_cons_cmd_help(help, core->print->flags & R_PRINT_FLAGS_COLOR);
}

static void cmd_project(RCore *core, const char *input) {
	switch (*input) {
	case 's':
		if (input[1] == ' ') {
			r_project_save_file (core, input + 2);
		}
		break;
	case 'l':
		if (input[1] == ' ') {
			r_project_load_file (core, input + 2);
		}
		break;
	default:
		usage (core);
		break;
	}
}

static int r_cmd_project_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, CMD_PREFIX, strlen (CMD_PREFIX))) {
		cmd_project (core, input + strlen (CMD_PREFIX));
		return true;
	}
	return false;
}

int r_cmd_project_init(void *user, const char *cmd) {
	// RCmd *rcmd = (RCmd*) user;
	// RCore *core = (RCore *) rcmd->data;
	// RConfig *cfg = core->config;
	return true;
}

RCorePlugin r_core_plugin_project = {
		.name = "r2db",
		.desc = "projects",
		.license = "LGPLv3",
		.call = r_cmd_project_call,
		.init = r_cmd_project_init
};


#ifndef CORELIB
RLibStruct radare_plugin = {
		.type = R_LIB_TYPE_CORE,
		.data = &r_core_plugin_project,
		.version = R2_VERSION
};
#endif