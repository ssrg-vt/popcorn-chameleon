/**
 * Utilities to make ptrace bearable.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _PTRACE_H
#define _PTRACE_H

#include <unistd.h>

namespace chameleon {
namespace PTrace {

////////////////////////////////////////////////////////////////////////////////
// Setup
////////////////////////////////////////////////////////////////////////////////

/**
 * Make the current task traceable (a "tracee") by the ptask subsystem.  Should
 * only be called by the spawned process.
 * @return true if call succeeded, false otherwise
 */
bool traceme();

/**
 * Kill the tracee (child) if the tracer (chameleon) exits.
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool killChildOnExit(pid_t tracee);

////////////////////////////////////////////////////////////////////////////////
// Control
////////////////////////////////////////////////////////////////////////////////

/**
 * Resume a tracee (child).
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool resume(pid_t tracee, int signal = 0);

/**
 * Detach from a tracee (child).
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool detach(pid_t tracee);

}
}

#endif /* _PTRACE_H */

