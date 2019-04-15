
#ifndef R2_PROJECT_H
#define R2_PROJECT_H

#include <r_core.h>
#include <sdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef Sdb RProject;

typedef enum r_project_err {
	R_PROJECT_ERR_SUCCESS,
	R_PROJECT_ERR_FILE,
	R_PROJECT_ERR_INVALID_TYPE,
	R_PROJECT_ERR_INVALID_VERSION,
	R_PROJECT_ERR_NEWER_VERSION,
	R_PROJECT_ERR_UNKNOWN
} RProjectErr;

R_API RProjectErr r_project_save(RCore *core, RProject *prj);
R_API RProjectErr r_project_save_file(RCore *core, const char *file);
R_API RProjectErr r_project_load(RCore *core, RProject *prj);
R_API RProjectErr r_project_load_file(RCore *core, const char *file);

#ifdef __cplusplus
}
#endif

#endif
