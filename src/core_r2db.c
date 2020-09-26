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

static bool io_files_foreach_cb(void *user, void *data, ut32 id) {
	RIODesc *desc = (RIODesc*) data;
	eprintf ("  RIODesc %p, fd = %d, name = %s, uri = %s\n", desc, desc->fd, desc->name, desc->uri);
	return true;
}

static void debug(RCore *core, const char *input) {
	eprintf ("\n");
	eprintf ("corefiles: (cur = %p)\n", core->file);
	RListIter *it;
	RCoreFile *f;
	r_list_foreach (core->files, it, f) {
		eprintf ("  %p fd = %d, dbg = %d, alive = %d\n", f, f->fd, f->dbg, f->alive);
	}
	eprintf ("\n");

	eprintf ("binfiles: (cur = %p)\n", core->bin->cur);
	RBinFile *bf;
	r_list_foreach (core->bin->binfiles, it, bf) {
		eprintf ("  %p, fd = %d, object = %p\n", bf, bf->fd, bf->o);
		eprintf ("    RBinObject: fd = %d, id = %u, file = %s\n", bf->fd, bf->id, bf->file);
	}

	eprintf ("\n");

	RIO *io = core->io;
	eprintf ("io files:\n");
	r_id_storage_foreach (io->files, io_files_foreach_cb, NULL);

	eprintf ("\n");

	eprintf ("io maps:\n");
	size_t i;
	for (i = 0; i < r_pvector_len (&io->maps); i++) {
		RIOMap *map = r_pvector_at (&io->maps, i);
		eprintf ("  RIOMap: %p, fd = %d, name = %s, itv.addr = 0x%"PFMT64x", itv.size = 0x%"PFMT64x", delta = 0x%"PFMT64x"\n",
				map, map->fd, map->name, map->itv.addr, map->itv.size, map->delta);
	}

	eprintf ("\n");
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
			RSerializeResultInfo *res = r_serialize_result_info_new ();
			RProjectErr err = r_project_load_file (core, input + 2, res);
			if (err != R_PROJECT_ERR_SUCCESS) {
				eprintf ("Failed to load project: %d\n", err);
				RListIter *it;
				char *s;
				r_list_foreach (res, it, s) {
					eprintf ("  %s\n", s);
				}
			}
			r_serialize_result_info_free (res);
		}
		break;
	case 'd':
		debug (core, input + 2);
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
