#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <susfs_defs.h>
#include <susfs_utils.h>
#include "../features.h"
#include "apply_plan.h"

/* Absolute install path of this binary (see external/susfs4ksu Android.bp stem).
 * Hidden from spoofed apps after the plan is applied. */
#define MIST_SUSFS_PATH "/system_ext/bin/mist_susfs"
#define APPLY_MAX_TOKENS 16
#define APPLY_MAX_LINE   512
/* Bound on re-apply passes when the plan keeps changing under us (see apply_plan). */
#define APPLY_MAX_PASSES 8

void apply_plan_print_help(void) {
	log("    apply_plan <plan_file>\n");
	log("      |--> Read <plan_file> and run each line as a sub-command (one per line,\n");
	log("      |--> e.g. 'set_uptime_offset <uid> <off>'; blank lines and '#' comments skipped).\n");
	log("      |--> Afterwards hides this binary (%s) from spoofed apps via add_sus_path.\n", MIST_SUSFS_PATH);
	log("\n");
}

/* Tokenize `line` in place (reentrant). A token is either a bare run of
 * non-whitespace or a "double-quoted" span, which may contain spaces — needed for
 * set_uname's "#1 SMP PREEMPT ..." version string. Quotes are stripped; there is no
 * escape syntax (property/uname values never contain a literal '"'). Returns the
 * token count. */
static int tokenize(char *line, char *tokens[], int max) {
	int n = 0;
	char *p = line;
	while (*p && n < max) {
		while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
			p++;
		if (*p == '\0')
			break;
		if (*p == '"') {
			tokens[n++] = ++p;                 /* content begins after the quote */
			while (*p && *p != '"')
				p++;
		} else {
			tokens[n++] = p;
			while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
				p++;
		}
		if (*p)
			*p++ = '\0';                       /* terminate this token, step past */
	}
	return n;
}

/* Hide this binary so a spoofed app scanning /system/bin can't spot it. sus_path only
 * affects umounted (target) apps in the kernel, so root/init can still exec it. */
static void hide_self(void) {
	char *argv[3] = { "mist_susfs", "add_sus_path", MIST_SUSFS_PATH };
	if (access(MIST_SUSFS_PATH, F_OK) == 0)
		susfs_run_command(3, argv);
}

int apply_plan(int argc, char *argv[]) {
	if (argc != 3) {
		apply_plan_print_help();
		return -EINVAL;
	}

	const char *path = argv[2];
	int applied = 0, failed = 0, passes = 0;

	/* Re-apply while the plan changes under us. The init trigger runs
	 * `start mist_susfs_apply` on a `oneshot` service, which is a NO-OP when a
	 * previous apply is still running — so two config changes close together (e.g.
	 * rapid re-randomizes) drop the second, leaving the property overlay serving the
	 * PREVIOUS seed while props_<uid>/the in-process spoof already moved on (a
	 * getprop-vs-Java/native fingerprint drift). Re-reading the plan until its
	 * nanosecond mtime + size stop changing makes the LATEST config always win.
	 * Second granularity isn't enough — the racing writes land in the same second —
	 * hence st_mtim.tv_nsec. Bounded by APPLY_MAX_PASSES. */
	for (;;) {
		struct stat before, after;
		int have_before = (stat(path, &before) == 0);

		applied = 0;
		failed = 0;
		FILE *fp = fopen(path, "re");
		if (!fp)
			log("[-] apply_plan: no plan file '%s' (%s); still hiding + stamping\n",
			    path, strerror(errno));

		char line[APPLY_MAX_LINE];
		while (fp && fgets(line, sizeof(line), fp)) {
			char *s = line;
			while (*s == ' ' || *s == '\t')
				s++;
			if (*s == '\0' || *s == '\n' || *s == '#')
				continue;

			char *tokens[APPLY_MAX_TOKENS];
			int nt = tokenize(line, tokens, APPLY_MAX_TOKENS);
			if (nt < 1)
				continue;

			/* susfs_run_command expects argv[0]=prog, argv[1]=cmd, argv[2..]=args. */
			char *cmd_argv[APPLY_MAX_TOKENS + 1];
			cmd_argv[0] = "mist_susfs";
			for (int i = 0; i < nt; i++)
				cmd_argv[i + 1] = tokens[i];

			if (susfs_run_command(nt + 1, cmd_argv) == 0)
				applied++;
			else
				failed++;
		}
		if (fp)
			fclose(fp);

		passes++;
		if (!have_before || passes >= APPLY_MAX_PASSES)
			break;
		if (stat(path, &after) != 0)
			break;
		if (after.st_mtim.tv_sec == before.st_mtim.tv_sec &&
		    after.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
		    after.st_size == before.st_size)
			break;   /* plan stable — the version we just applied is the latest */
		/* plan changed during this pass — loop and apply the newer one */
	}

	hide_self();

	/* Refresh the SusFS/KernelSU version props for the Settings detection UI. */
	stamp_status(0, NULL);

	log("[+] apply_plan: %d applied, %d failed (%d pass%s)\n",
	    applied, failed, passes, passes == 1 ? "" : "es");
	return failed ? -EIO : 0;
}
