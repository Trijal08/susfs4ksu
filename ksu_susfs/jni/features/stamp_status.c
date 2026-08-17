#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include "stamp_status.h"

/* --- SusFS version: reboot backdoor (SUSFS_MAGIC). Struct MUST match the kernel
 *     (include/linux/susfs.h): char[16] + int err. --- */
#define CMD_SUSFS_SHOW_VERSION 0x555e1
#define SUSFS_MAX_VERSION_BUFSIZE 16
struct st_susfs_version {
	char susfs_version[SUSFS_MAX_VERSION_BUFSIZE];
	int  err;
};

/* --- KernelSU version, WITHOUT ksud: install the ksu fd via the reboot backdoor
 *     (magic2 = 0xCAFEBABE), then ioctl(GET_INFO). Struct + ioctl MUST match
 *     KernelSU kernel/include/uapi/supercall.h. GET_INFO is always-allow, so any
 *     root process (this one) may query it. --- */
#define KSU_INSTALL_MAGIC2 0xCAFEBABE
struct ksu_get_info_cmd {
	uint32_t version;
	uint32_t flags;
	uint32_t features;
	uint32_t uapi_version;
};
#define KSU_IOCTL_GET_INFO _IOR('K', 2, struct ksu_get_info_cmd)

/* Retry budget for the boot path. The service fires at boot_completed and can beat the
 * KSU fd-install / SusFS supercall path (or even the property service) to readiness; a
 * transient miss there must be retried, not committed as a blank/false value. */
#define STAMP_MAX_ATTEMPTS 15
#define STAMP_RETRY_US     (200 * 1000)  /* 200ms */

void stamp_status_print_help(void) {
	log("    stamp_status\n");
	log("      |--> Query the SusFS + KernelSU versions and publish them to sys.mist.*\n");
	log("      |--> for the Settings detection UI. Works without ksud.\n");
	log("\n");
}

/* Query SusFS and publish its version. Returns 1 only if the query resolved AND both
 * property writes actually landed (getprop-visible); 0 otherwise so the caller retries.
 * Never writes a negative here — that decision is deferred until retries are exhausted. */
static int stamp_susfs(void) {
	struct st_susfs_version info = {0};
	info.err = ERR_CMD_NOT_SUPPORTED;
	syscall(SYS_reboot, KSU_INSTALL_MAGIC1, SUSFS_MAGIC, CMD_SUSFS_SHOW_VERSION, &info);
	if (info.err || !info.susfs_version[0])
		return 0;
	int a = __system_property_set("sys.mist.susfs.version", info.susfs_version);
	int b = __system_property_set("sys.mist.susfs.integrated", "1");
	return (a == 0 && b == 0) ? 1 : 0;  /* retry if the property write didn't land */
}

/* Query KernelSU (no ksud) and publish its version. Returns 1 only on a resolved query
 * with a landed property write; 0 otherwise. Never clobbers with "" here. */
static int stamp_ksu(void) {
	int fd = -1;
	syscall(SYS_reboot, KSU_INSTALL_MAGIC1, KSU_INSTALL_MAGIC2, 0, &fd);
	if (fd < 0)
		return 0;

	struct ksu_get_info_cmd info = {0};
	int rc = ioctl(fd, KSU_IOCTL_GET_INFO, &info);
	close(fd);
	if (rc != 0 || !info.version)
		return 0;

	char buf[32];
	snprintf(buf, sizeof(buf), "%u", info.version);
	return __system_property_set("sys.mist.ksu.version", buf) == 0 ? 1 : 0;
}

int stamp_status(int argc, char *argv[]) {
	(void)argc;
	(void)argv;

	int ok_susfs = 0, ok_ksu = 0;
	for (int i = 0; i < STAMP_MAX_ATTEMPTS && (!ok_susfs || !ok_ksu); i++) {
		if (!ok_susfs) ok_susfs = stamp_susfs();
		if (!ok_ksu)   ok_ksu   = stamp_ksu();
		if (ok_susfs && ok_ksu)
			break;
		usleep(STAMP_RETRY_US);
	}

	/* Commit definitive negatives only after retries are exhausted, so a transient
	 * early-boot miss never publishes (or clobbers to) a blank/false value. */
	if (!ok_susfs)
		__system_property_set("sys.mist.susfs.integrated", "0");
	if (!ok_ksu) {
		/* Soft fallback: mark KernelSU present if a ksud exists at the standard path. */
		if (access("/data/adb/ksu/bin/ksud", F_OK) == 0)
			__system_property_set("sys.mist.ksu.version", "installed");
		else
			__system_property_set("sys.mist.ksu.version", "");
	}
	return 0;
}
