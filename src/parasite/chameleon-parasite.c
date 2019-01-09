/**
 * Parasite implanted into traced process.  Implements the following mechanisms
 * in the context of the traced process:
 *
 *   - Create userfaultfd file descriptors
 *   - Change memory mappings
 *   - Evicting pages to force new page faults for randomization
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 1/8/2019
 */

#include <compel/plugins/std.h>

// TODO implement creating & sending userfaultfd to chameleon

int parasite_trap_cmd(int cmd, void *args) { return 0; }
void parasite_cleanup(void) {}
int parasite_daemon_cmd(int cmd, void *args) { return 0; }

