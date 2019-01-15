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
#include <compel/plugins/plugin-fds.h>

#include "parasite.h"

#define ERROR( fmt, ... ) \
  std_dprintf(STDERR_FILENO, "ERROR: parasite: " fmt, ##__VA_ARGS__)
#ifndef NDEBUG
# define DEBUG( fmt, ... ) \
  std_dprintf(STDERR_FILENO, "DEBUG: parasite: " fmt, ##__VA_ARGS__)
#else
# define DEBUG( fmt, ... ) {}
#endif

static int createAndSendUFFD(void) {
  int uffd, ret;
  if((uffd = sys_userfaultfd(0)) == -1) {
    ERROR("could not create userfaultfd descriptor\n");
    return -1;
  }
  DEBUG("initialized uffd %d\n", uffd);
  ret = fds_send_fd(uffd);
  DEBUG("sent uffd to chameleon\n");
  sys_close(uffd);
  DEBUG("returning %d\n", ret);
  return ret;
}

int parasite_trap_cmd(int cmd, void *args) { return 0; }
void parasite_cleanup(void) {}
int parasite_daemon_cmd(int cmd, void *args) {
  switch(cmd) {
  default: DEBUG("Unknown command: %d\n", cmd); return 0;
  case GET_UFFD: return createAndSendUFFD();
  }
}

