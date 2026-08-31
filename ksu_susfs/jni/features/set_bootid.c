// set_bootid.c — per-uid /proc/sys/kernel/random/boot_id spoof for the SusFS open_redirect.
//
// A per-boot UUID that FingerprintJS (and GeerGit's anti-fingerprinting) reads to anchor a
// device identity. We give a spoofed app its own boot_id so its visitorId can flip without
// touching the real device profile.
//
// CRITICAL — why this file exists instead of a raw add_open_redirect from the framework:
// A17 libbinder reads /proc/sys/kernel/random/boot_id at process init and calls
// LOG_ALWAYS_FATAL("Bad boot_id: '%s'") on an empty/short value, so the redirect target MUST
// be a valid, non-empty 36-char UUID that the target app's OWN domain can read. The overlay
// therefore lives at
//     /dev/.pc/<uid>/boot_id
// which is labelled mist_prop_file via type_transition (mist_prop_dir:file) — the ONE label
// sepolicy grants `appdomain { open read getattr map }`, exactly like the prop overlay.
// The previous approach redirected to /data/mist_susfs/bootid_<uid> (mist_susfs_data_file,
// which appdomain CANNOT read) => the app's redirected read returned empty => libbinder
// aborted => every spoofed app crashed on launch. That is the bug this replaces.
//
// Defense in depth: we validate the UUID and only register the redirect AFTER the file is
// written, so a bad/empty value never reaches the redirect — the app falls back to the real
// boot_id rather than aborting.

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <susfs_defs.h>
#include "open_redirect.h"
#include "set_bootid.h"

#define BOOT_ID_PROC   "/proc/sys/kernel/random/boot_id"
#define OVERLAY_ROOT   "/dev/.pc"
#define OVERLAY_SCHEME "3"          /* UID_UMOUNTED_APP_PROC — umounted app, uid >= 10000 */
#define UUID_LEN       36

void set_bootid_print_help(void) {
	log("    set_bootid <uid> <uuid>\n");
	log("      |--> Write <uuid> to /dev/.pc/<uid>/boot_id (app-readable mist_prop_file) and\n");
	log("      |--> register a per-uid (scheme 3) open_redirect of %s to it.\n", BOOT_ID_PROC);
	log("      |--> <uuid> must be a canonical 8-4-4-4-12 UUID; refused otherwise so the\n");
	log("      |--> redirect never serves an empty boot_id (A17 libbinder aborts on empty).\n");
	log("      * Only effective for umounted app processes (uid >= 10000).\n\n");
}

/* Canonical lower/upper-hex UUID: 8-4-4-4-12 with dashes at 8,13,18,23. */
static int is_uuid(const char *s) {
	if (strlen(s) != UUID_LEN)
		return 0;
	for (int i = 0; i < UUID_LEN; i++) {
		char c = s[i];
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (c != '-')
				return 0;
		} else if (!isxdigit((unsigned char)c)) {
			return 0;
		}
	}
	return 1;
}

int set_bootid(int argc, char *argv[]) {
	if (argc != 4) {
		set_bootid_print_help();
		return -EINVAL;
	}
	const char *uid = argv[2];
	const char *uuid = argv[3];

	for (const char *c = uid; *c; c++)
		if (*c < '0' || *c > '9') { log("[-] set_bootid: bad uid '%s'\n", uid); return -EINVAL; }
	if (!is_uuid(uuid)) {
		log("[-] set_bootid: '%s' is not a canonical UUID; refusing (app would abort)\n", uuid);
		return -EINVAL;
	}

	// Root-owned file, read by the umounted app as "other" through the redirect: the dirs
	// must be world-searchable and the file world-readable. Clear the umask or the modes
	// below get masked (mist_susfs inherits a restrictive umask) — same as prop_overlay.
	umask(0);
	mkdir(OVERLAY_ROOT, 0751);           /* normally pre-created + labelled mist_prop_dir by init */
	char udir[128];
	snprintf(udir, sizeof(udir), "%s/%s", OVERLAY_ROOT, uid);
	mkdir(udir, 0711);                   /* others: search only (no list); labelled via type_transition */

	char ov[160];
	snprintf(ov, sizeof(ov), "%s/boot_id", udir);
	int fd = open(ov, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (fd < 0) {
		log("[-] set_bootid: open %s: %s\n", ov, strerror(errno));
		return -errno;
	}
	// /proc/sys/kernel/random/boot_id ends in a newline; match it so readers that strip or
	// keep the trailing \n both see a well-formed value.
	char line[UUID_LEN + 2];
	int len = snprintf(line, sizeof(line), "%s\n", uuid);
	ssize_t w = write(fd, line, (size_t)len);
	close(fd);
	if (w != len) {
		log("[-] set_bootid: short write to %s\n", ov);
		return -EIO;
	}

	// Register the redirect ONLY now that a valid file exists (add_open_redirect realpath()s
	// both ends, so a missing/empty target would already fail — but we never want it to).
	char *rargv[6] = { "mist_susfs", "add_open_redirect",
	                   (char *)BOOT_ID_PROC, ov, (char *)OVERLAY_SCHEME, (char *)uid };
	if (add_open_redirect(6, rargv) != 0) {
		log("[-] set_bootid: add_open_redirect for uid %s failed\n", uid);
		return -EIO;
	}
	log("[+] set_bootid uid=%s: boot_id overlay + redirect ok\n", uid);
	return 0;
}
