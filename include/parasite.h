/**
 * Utilities to infect, call and cure parasite in child processes.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 1/8/2018
 */

#ifndef _PARASITE_H
#define _PARASITE_H

#include <compel/infect-rpc.h>

/* Commands & arguments for the parasite */
#define GET_UFFD PARASITE_USER_CMDS

union parasiteArgs {
  int uffd; /* GET_UFFD */
};

/* Only include the C++ part for chameleon, not in the parasite */
#ifndef PARASITE

#include "types.h"

struct parasite_ctl;

namespace chameleon {
namespace parasite {

#ifndef NDEBUG
/**
 * Initialize compel logging machinery.
 * @param verbose if true, print everything, else print errors
 */
void initializeLog(bool verbose);
#endif

/**
 * Initialize the parasite context for controlling the child.  Note that the
 * child must have previously been stopped.
 *
 * @param pid PID of child
 * @return an initialized parasite control handle or nullptr if it could not
 *         be initialized
 */
struct parasite_ctl *initialize(int pid);

/**
 * Infect the child with the parasite.  Note that the child must have
 * previously been stopped.
 *
 * @param ctx a parasite control context
 * @param nthreads number of threads in the traced child
 * @return a return code describing the outcome
 */
ret_t infect(struct parasite_ctl *ctx, size_t nthreads);

/**
 * Instantiate and pass a userfaultfd file descriptor from the child to
 * chameleon.
 *
 * @param ctx a parasite control context
 * @return the userfaultfd file descriptor or -1 if it could not be stolen
 */
int stealUFFD(struct parasite_ctl *ctx);

/**
 * Cure the child's parasite.  Internally frees pointed-to ctx and sets its
 * storage to null, meaning it is no longer valid; users must get another
 * context via initialize().  Note that the child must have been previously
 * stopped & infected.
 *
 * @param ctx a pointer to a parasite control context pointer
 * @return a return code describing the outcome
 */
ret_t cure(struct parasite_ctl **ctx);

/**
 * Execute a system call in the context of the child process.  Note that the
 * child must have previously been stopped.
 *
 * @param ctx a pointer to a parasite control context pointer
 * @param syscall the system call number
 * @param sysRet output argument set to return value from system call
 * @param a1-6 arguments to place in registers for syscall
 * @return a return code describing the outcome
 */
ret_t syscall(struct parasite_ctl *ctx, long syscall, long &sysRet,
              long a1 = 0, long a2 = 0, long a3 = 0,
              long a4 = 0, long a5 = 0, long a6 = 0);

/**
 * Return the address at which compel will infect the child process.
 * @param ctx a pointer to a parasite control context pointer
 * @return address at which infection occurs or 0 if not a valid context
 */
uintptr_t infectAddress(struct parasite_ctl *ctx);

}
}

#endif /* PARASITE */

#endif /* _PARASITE_H */

