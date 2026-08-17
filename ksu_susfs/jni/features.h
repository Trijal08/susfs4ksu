#ifndef FEATURES_H
#define FEATURES_H

#include "features/sus_path.h"
#include "features/sus_kstat.h"
#include "features/sus_mount.h"
#include "features/sus_map.h"
#include "features/spoof_cmdline_or_bootconfig.h"
#include "features/spoof_uname.h"
#include "features/avc_log_spoofing.h"
#include "features/enable_log.h"
#include "features/open_redirect.h"
#include "features/prop_overlay.h"
#include "features/time_offset.h"
#include "features/apply_plan.h"
#include "features/stamp_status.h"
#include "features/show.h"

/* Defined in main.c: the sub-command dispatch, reused by apply_plan. */
int susfs_run_command(int argc, char *argv[]);

#endif // #ifndef FEATURES_H
