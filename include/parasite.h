/**
 * Utilities to infect, call and cure parasite in child processes.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 1/8/2018
 */

#ifndef _PARASITE_H
#define _PARASITE_H

#include "types.h"

struct parasite_ctl;

namespace chameleon {
namespace parasite {

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
 * Execute a system call in the context of the child process.  Note that the
 * child must have previously been stopped.
 *
 * @param syscall the system call number
 * @param a1-6 arguments to place in registers for syscall
 * @return a return code describing the outcome
 */
ret_t syscall(struct parasite_ctl *ctx, long syscall,
              long a1, long a2, long a3, long a4, long a5, long a6);

}
}

#endif /* _PARASITE_H */

