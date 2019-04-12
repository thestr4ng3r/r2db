
#include <r_core.h>

static void cmd_project(RCore *core, const char *input) {
	r_cons_printf ("Called %s\n", input);
}

static int r_cmd_project_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, "PN", 2)) {
		cmd_project (core, input + 2);
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