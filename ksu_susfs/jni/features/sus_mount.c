#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <errno.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include "sus_mount.h"

#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS 0x55561
#define CMD_SUSFS_HIDE_SUS_MNTS_FOR_UID 0x55563

struct st_susfs_hide_sus_mnts_for_non_su_procs {
	bool                    enabled;
	int                     err;
	/* appended after err to mirror the kernel struct; only sent (full-size)
	 * via CMD_SUSFS_HIDE_SUS_MNTS_FOR_UID (adds target_uid to the hide-set). */
	int                     target_uid;
};

void sus_mount_print_help(void){
	log("    hide_sus_mnts_for_non_su_procs <0|1> [target_uid]\n");
	log("      |--> [target_uid] (optional): instead of the global toggle, add this uid to a per-app hide-set (the <0|1> is ignored in this mode)\n");
	log("      |--> 0 -> DO NOT hide sus mounts for non-su processes\n");
	log("      |--> 1 -> hide all sus mounts for non-su processes\n");
	log("      * Important Notes *\n");
	log("      - It is set to 0 in kernel by default\n");
	log("      - For ReZygisk without TreatWheel module, it is recommended to set to 1 in post-fs-data.sh to prevent zygote from caching the sus mounts in memory, and revert to 0 in boot-completed.sh stage, or keep it enabled if you want to keep them hidden from /proc/self/[mounts|mountinfo|mountstat] for non-su processes\n");
	log("\n");
}

static void print_help(void){
	print_help_banner();
	sus_mount_print_help();
}

int hide_sus_mnts_for_non_su_procs(int argc, char *argv[]) {
	struct st_susfs_hide_sus_mnts_for_non_su_procs info = {0};

	if (argc != 3 && argc != 4) {
		print_help();
		return -EINVAL;
	}

	if (strcmp(argv[2], "0") && strcmp(argv[2], "1")) {
		print_help();
		return -EINVAL;
	}
	info.enabled = atoi(argv[2]);

	// Optional 2nd positional arg = target_uid (per-app hide-set membership).
	// Selects the *_UID command (full-size copy); without it the legacy global
	// toggle is used, leaving the ABI for existing susfs tooling untouched.
	int mount_cmd = CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS;
	if (argc == 4) {
		char *endptr;
		long target_uid = strtol(argv[3], &endptr, 10);
		if (*endptr != '\0' || target_uid < 0) {
			print_help();
			return -EINVAL;
		}
		info.target_uid = (int)target_uid;
		mount_cmd = CMD_SUSFS_HIDE_SUS_MNTS_FOR_UID;
	}
	info.err = ERR_CMD_NOT_SUPPORTED;
	syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, mount_cmd, &info);
	PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, mount_cmd);
	return info.err;
}

