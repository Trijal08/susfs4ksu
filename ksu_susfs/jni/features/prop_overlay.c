// prop_overlay.c — per-uid system-property overlay for the SusFS open_redirect spoof.
//
// The in-process libc hook (g_device_props) and Java reflection already spoof properties
// for a target app's OWN reads, but a `getprop` SUBPROCESS (fresh process, no override
// table) and raw /dev/__properties__ opens bypass them and read the real values — the
// GETPROP-vs-NATIVE-vs-REFLECTION divergence detectors flag. This closes that gap at the
// one layer all three share: the property-area files.
//
// For each spoofed prop we build a patched copy of its context file under
//   /dev/.pc/<uid>/<ctx>
// and register a per-uid (UID_UMOUNTED_APP_PROC / scheme 3) open_redirect from the real
//   /dev/__properties__/<ctx>
// to the copy. A fresh open by the umounted app (getprop child, raw mmap) is redirected
// to the patched copy => every prop-read path finally agrees. The app's own inherited
// libc mapping still comes from the real file and is served by the g_device_props hook, so
// the two stay consistent as long as both are fed the same values (they are — see the
// framework's buildSusfsCommands, which writes /data/mist_susfs/props/<uid> from the same
// buildPropOverrides map that feeds the hook).
//
// On-disk prop_info layout (bionic, stable ABI): [serial:4][value:PROP_VALUE_MAX][name..],
// sizeof == 96, name null-terminated at prop_info+96. serial = (value_len<<24)|flags, with
// kLongFlag == 1<<16 for long (>MAX) values. So a prop is located by its unique name string
// and patched by offset: value slot at name_off-92, serial at name_off-96. No trie walk.

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <susfs_defs.h>
#include "open_redirect.h"
#include "prop_overlay.h"

#define PROP_DIR        "/dev/__properties__"
#define OVERLAY_ROOT    "/dev/.pc"
#define PROPS_PATH_FMT  "/data/mist_susfs/props_%s"
#define PROP_VALUE_MAX  92          /* bionic PROP_VALUE_MAX */
#define PROPINFO_HDR    96          /* serial(4) + value(92); name starts here */
#define PROP_LONG_FLAG  0x10000u    /* bionic prop_info::kLongFlag (1<<16) */
#define CTX_PREFIX      "u:object_r:"
#define OVERLAY_SCHEME  "3"         /* UID_UMOUNTED_APP_PROC */
#define MAX_PROPS       384

struct kv { char name[128]; char value[PROP_VALUE_MAX]; int done; };
struct match { int idx; long off; };

void build_prop_overlay_print_help(void) {
	log("    build_prop_overlay <uid>\n");
	log("      |--> Build /dev/.pc/<uid>/<ctx> patched property-area copies from\n");
	log("      |--> /data/mist_susfs/props/<uid> ('<name> <value>' per line) and register a\n");
	log("      |--> per-uid open_redirect (scheme 3) for each, so the app's getprop / raw\n");
	log("      |--> property reads match the in-process libc + Java spoof.\n");
	log("      * Only effective for umounted app processes (uid >= 10000).\n\n");
}

static int copy_file(const char *src, const char *dst) {
	int rc = -1;
	int sfd = open(src, O_RDONLY | O_CLOEXEC);
	if (sfd < 0) return -1;
	int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
	if (dfd < 0) { close(sfd); return -1; }
	char buf[65536];
	ssize_t r;
	while ((r = read(sfd, buf, sizeof(buf))) > 0) {
		ssize_t w = 0;
		while (w < r) {
			ssize_t x = write(dfd, buf + w, (size_t)(r - w));
			if (x < 0) goto out;
			w += x;
		}
	}
	if (r == 0) rc = 0;
out:
	close(sfd);
	close(dfd);
	return rc;
}

/* Offset of "<name>\0" within [buf, buf+len), requiring room for the prop_info header
 * before it; -1 if absent. Names are full + unique, so no trie walk is needed. */
static long find_name(const uint8_t *buf, size_t len, const char *name) {
	size_t nl = strlen(name) + 1;               /* include the terminating NUL */
	if (nl > len) return -1;
	const uint8_t *p = buf;
	const uint8_t *end = buf + len - nl + 1;
	while (p < end) {
		const uint8_t *q = memchr(p, name[0], (size_t)(end - p));
		if (!q) break;
		if ((size_t)(q - buf) >= PROPINFO_HDR && memcmp(q, name, nl) == 0)
			return q - buf;
		p = q + 1;
	}
	return -1;
}

/* Patch the value slot (name_off-92) + serial (name_off-96). Static overlay => a clean
 * serial (length in the top byte, zero change-count, no flags) is what fresh readers want. */
static int patch_prop(uint8_t *map, long name_off, const char *value) {
	size_t vlen = strlen(value);
	if (vlen >= PROP_VALUE_MAX) return -1;
	uint32_t old;
	memcpy(&old, map + name_off - PROPINFO_HDR, 4);
	if (old & PROP_LONG_FLAG) return -1;        /* long property: don't corrupt the union */
	uint8_t *vslot = map + name_off - PROP_VALUE_MAX;
	memset(vslot, 0, PROP_VALUE_MAX);
	memcpy(vslot, value, vlen);
	uint32_t ns = ((uint32_t)vlen << 24);
	memcpy(map + name_off - PROPINFO_HDR, &ns, 4);
	return 0;
}

static int is_ctx_file(const char *name) {
	return strncmp(name, CTX_PREFIX, sizeof(CTX_PREFIX) - 1) == 0;
}

static int read_props(const char *uid, struct kv *props, int max) {
	char path[256];
	snprintf(path, sizeof(path), PROPS_PATH_FMT, uid);
	FILE *fp = fopen(path, "re");
	if (!fp) {
		log("[-] prop_overlay: no props file '%s' (%s)\n", path, strerror(errno));
		return 0;
	}
	int n = 0;
	char line[512];
	while (n < max && fgets(line, sizeof(line), fp)) {
		size_t L = strlen(line);
		while (L && (line[L - 1] == '\n' || line[L - 1] == '\r'))
			line[--L] = '\0';
		if (!L || line[0] == '#')
			continue;
		char *sp = strchr(line, ' ');
		if (!sp)
			continue;                           /* need "<name> <value>" */
		*sp = '\0';
		const char *val = sp + 1;
		if (strlen(line) == 0 || strlen(line) >= sizeof(props[n].name))
			continue;
		if (strlen(val) >= PROP_VALUE_MAX) {
			log("[-] prop_overlay: value too long for '%s' (%zu >= %d), skipping\n",
			    line, strlen(val), PROP_VALUE_MAX);
			continue;
		}
		strncpy(props[n].name, line, sizeof(props[n].name) - 1);
		props[n].name[sizeof(props[n].name) - 1] = '\0';
		strncpy(props[n].value, val, PROP_VALUE_MAX - 1);
		props[n].value[PROP_VALUE_MAX - 1] = '\0';
		props[n].done = 0;
		n++;
	}
	fclose(fp);
	return n;
}

/* Revert every existing overlay file for a uid to its REAL context file, in place. The
 * SELinux label survives O_TRUNC (inode xattr) and the redirect stays valid but now serves
 * real bytes. Used by clear_prop_overlay and at the start of build_prop_overlay. */
static int revert_overlay(const char *uid) {
	char udir[128];
	snprintf(udir, sizeof(udir), "%s/%s", OVERLAY_ROOT, uid);
	DIR *d = opendir(udir);
	if (!d)
		return 0;
	int n = 0;
	struct dirent *de;
	while ((de = readdir(d))) {
		if (!is_ctx_file(de->d_name))
			continue;
		char real[512], ov[640];
		snprintf(real, sizeof(real), "%s/%s", PROP_DIR, de->d_name);
		snprintf(ov, sizeof(ov), "%s/%s", udir, de->d_name);
		if (copy_file(real, ov) == 0)
			n++;
	}
	closedir(d);
	return n;
}

int build_prop_overlay(int argc, char *argv[]) {
	if (argc != 3) {
		build_prop_overlay_print_help();
		return -EINVAL;
	}
	const char *uid = argv[2];
	for (const char *c = uid; *c; c++)
		if (*c < '0' || *c > '9') { log("[-] prop_overlay: bad uid '%s'\n", uid); return -EINVAL; }

	// Revert any prior overlay to real FIRST: a context spoofed last build but not this time
	// (a field toggled off) stops spoofing — its redirect persists (open_redirect can't be
	// removed until reboot) but now serves the real file. Enabled contexts are re-patched below.
	revert_overlay(uid);

	struct kv props[MAX_PROPS];
	int np = read_props(uid, props, MAX_PROPS);
	if (np <= 0)
		return 0;

	// The overlay is root-owned; the umounted app reads it through the redirect as "other",
	// so the dirs must be world-searchable and the files world-readable. Clear the umask or
	// the mode args below are masked (mist_susfs inherits a restrictive umask -> 0600/0700,
	// which DAC-denies the app before SELinux even applies).
	umask(0);
	mkdir(OVERLAY_ROOT, 0751);   /* normally pre-created + labelled mist_prop_dir by init */
	char udir[128];
	snprintf(udir, sizeof(udir), "%s/%s", OVERLAY_ROOT, uid);
	mkdir(udir, 0711);           /* others: search only (no list); labelled via type_transition */

	DIR *d = opendir(PROP_DIR);
	if (!d) {
		log("[-] prop_overlay: opendir %s: %s\n", PROP_DIR, strerror(errno));
		return -errno;
	}

	int patched = 0, redirects = 0;
	struct dirent *de;
	while ((de = readdir(d))) {
		if (!is_ctx_file(de->d_name))
			continue;

		char real[512];
		snprintf(real, sizeof(real), "%s/%s", PROP_DIR, de->d_name);
		int rfd = open(real, O_RDONLY | O_CLOEXEC);
		if (rfd < 0)
			continue;
		struct stat st;
		if (fstat(rfd, &st) != 0 || st.st_size <= PROPINFO_HDR) { close(rfd); continue; }
		uint8_t *rmap = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, rfd, 0);
		close(rfd);
		if (rmap == MAP_FAILED)
			continue;

		struct match matches[MAX_PROPS];
		int nm = 0;
		for (int i = 0; i < np; i++) {
			if (props[i].done)
				continue;
			long off = find_name(rmap, st.st_size, props[i].name);
			if (off >= 0) {
				matches[nm].idx = i;
				matches[nm].off = off;      /* copy is byte-identical => same offset */
				nm++;
			}
		}
		munmap(rmap, st.st_size);
		if (nm == 0)
			continue;

		char ov[640];
		snprintf(ov, sizeof(ov), "%s/%s", udir, de->d_name);
		if (copy_file(real, ov) != 0) {
			log("[-] prop_overlay: copy %s -> %s failed (%s)\n", real, ov, strerror(errno));
			continue;
		}
		/* the copy is labelled mist_prop_file via type_transition (mist_prop_dir:file) */

		int ofd = open(ov, O_RDWR | O_CLOEXEC);
		if (ofd < 0) { log("[-] prop_overlay: reopen %s: %s\n", ov, strerror(errno)); continue; }
		struct stat ost;
		if (fstat(ofd, &ost) != 0) { close(ofd); continue; }
		uint8_t *omap = mmap(NULL, ost.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, ofd, 0);
		if (omap == MAP_FAILED) { close(ofd); continue; }
		for (int k = 0; k < nm; k++) {
			int i = matches[k].idx;
			if (patch_prop(omap, matches[k].off, props[i].value) == 0) {
				props[i].done = 1;
				patched++;
			} else {
				log("[-] prop_overlay: could not patch '%s' (long prop?)\n", props[i].name);
			}
		}
		msync(omap, ost.st_size, MS_SYNC);
		munmap(omap, ost.st_size);
		close(ofd);

		char *rargv[6] = { "mist_susfs", "add_open_redirect", real, ov,
		                   (char *)OVERLAY_SCHEME, (char *)uid };
		if (add_open_redirect(6, rargv) == 0)
			redirects++;
		else
			log("[-] prop_overlay: add_open_redirect %s (uid %s) failed\n", de->d_name, uid);
	}
	closedir(d);

	for (int i = 0; i < np; i++)
		if (!props[i].done)
			log("[-] prop_overlay: prop '%s' not found in any context (skipped)\n", props[i].name);
	log("[+] prop_overlay uid=%s: patched %d/%d props, %d redirect(s)\n",
	    uid, patched, np, redirects);
	return 0;
}

int clear_prop_overlay(int argc, char *argv[]) {
	if (argc != 3) {
		build_prop_overlay_print_help();
		return -EINVAL;
	}
	/* Overwrite every overlay copy with the REAL context file: the still-registered redirect
	 * now serves real values, so the app un-spoofs without needing the (irremovable) redirect
	 * gone. Used for uids dropped from the config entirely (build_prop_overlay handles the
	 * per-field case for still-spoofed uids). */
	int n = revert_overlay(argv[2]);
	log("[+] prop_overlay: reverted %d file(s) to real for uid=%s\n", n, argv[2]);
	return 0;
}
