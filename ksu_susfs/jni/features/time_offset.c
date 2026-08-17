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
#include "time_offset.h"

/* Per-uid time offsets. Both are brand-new commands (NOT *_UID variants of an
 * existing struct), so target_uid is the FIRST field — the struct is only ever
 * sent by these commands, so there's no legacy ABI to preserve. Must match the
 * kernel structs in include/linux/susfs.h exactly. */
#define CMD_SUSFS_SET_FILE_TIME_OFFSET_UID 0x55574
#define CMD_SUSFS_SET_UPTIME_OFFSET_UID    0x55575

struct st_susfs_file_time_offset {
	int                     target_uid;
	long                    offset_sec;
	int                     err;
};

struct st_susfs_uptime_offset {
	int                     target_uid;
	long                    offset_sec;
	int                     err;
};

void set_file_time_offset_print_help(void) {
	log("    set_file_time_offset <target_uid> <offset_sec>\n");
	log("      |--> Shift atime/mtime/ctime of files OWNED by <target_uid> by <offset_sec>\n");
	log("      |--> (signed; negative = files look older). 0 removes the offset for the uid.\n");
	log("      |--> e.g., set_file_time_offset 10234 -15552000   (files look 180 days older)\n");
	log("\n");
}

void set_uptime_offset_print_help(void) {
	log("    set_uptime_offset <target_uid> <offset_sec>\n");
	log("      |--> Shift the uptime <target_uid> sees (/proc/uptime, sysinfo, /proc/stat btime,\n");
	log("      |--> /proc/<pid>/stat starttime, times()) by <offset_sec> (signed; positive = up longer).\n");
	log("      |--> 0 removes the offset for the uid.\n");
	log("      |--> e.g., set_uptime_offset 10234 259200          (device looks up 3 days longer)\n");
	log("\n");
}

/* Parse "<cmd> <target_uid> <offset_sec>" (argc == 4). offset_sec is signed. */
static int parse_uid_offset(int argc, char *argv[], int *out_uid, long *out_off) {
	char *endptr;

	if (argc != 4)
		return -EINVAL;

	long uid = strtol(argv[2], &endptr, 10);
	if (*endptr != '\0' || uid < 0)
		return -EINVAL;

	long off = strtol(argv[3], &endptr, 10);
	if (*endptr != '\0')
		return -EINVAL;

	*out_uid = (int)uid;
	*out_off = off;
	return 0;
}

int set_file_time_offset(int argc, char *argv[]) {
	struct st_susfs_file_time_offset info = {0};
	int uid;
	long off;

	if (parse_uid_offset(argc, argv, &uid, &off)) {
		set_file_time_offset_print_help();
		return -EINVAL;
	}
	info.target_uid = uid;
	info.offset_sec = off;

	info.err = ERR_CMD_NOT_SUPPORTED;
	syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_FILE_TIME_OFFSET_UID, &info);
	PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SET_FILE_TIME_OFFSET_UID);
	return info.err;
}

int set_uptime_offset(int argc, char *argv[]) {
	struct st_susfs_uptime_offset info = {0};
	int uid;
	long off;

	if (parse_uid_offset(argc, argv, &uid, &off)) {
		set_uptime_offset_print_help();
		return -EINVAL;
	}
	info.target_uid = uid;
	info.offset_sec = off;

	info.err = ERR_CMD_NOT_SUPPORTED;
	syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SET_UPTIME_OFFSET_UID, &info);
	PRT_MSG_IF_CMD_NOT_SUPPORTED(info.err, CMD_SUSFS_SET_UPTIME_OFFSET_UID);
	return info.err;
}
