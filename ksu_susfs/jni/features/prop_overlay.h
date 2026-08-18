#ifndef PROP_OVERLAY_H
#define PROP_OVERLAY_H

void build_prop_overlay_print_help(void);

/* build_prop_overlay <uid>
 *   Reads /data/mist_susfs/props/<uid> ("<name> <value>" per line), writes patched
 *   per-uid copies of the relevant /dev/__properties__ context files under
 *   /dev/.pc/<uid>/, and registers a per-uid (scheme 3) open_redirect for each so the
 *   spoofed app's getprop / raw property reads match the in-process libc + Java spoof. */
int build_prop_overlay(int argc, char *argv[]);

/* clear_prop_overlay <uid>
 *   Reverts the uid's overlay files to the REAL context files (in place, keeping the
 *   already-registered redirects) so a mid-session un-spoof serves real values without
 *   needing a reboot (open_redirect entries cannot be removed until reboot). */
int clear_prop_overlay(int argc, char *argv[]);

#endif // #ifndef PROP_OVERLAY_H
