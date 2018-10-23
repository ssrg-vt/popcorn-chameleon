/**
 * Utilities to make ptrace bearable.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _PTRACE_H
#define _PTRACE_H

#include <cstdint>
#include <unistd.h>
#include <sys/user.h>

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
 * @param signal signal to be delivered to child if non-zero
 * @param syscall whether to trace syscalls
 * @return true if call succeeded, false otherwise
 */
bool resume(pid_t tracee, int signal = 0, bool syscall = false);

/**
 * Detach from a tracee (child).
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool detach(pid_t tracee);

/**
 * Get a tracee's (child) registers.
 * @param tracee the tracee's PID
 * @param regs register set struct to be filled
 */
bool getRegs(pid_t tracee, struct user_regs_struct &regs);

/**
 * Set a tracee's (child) registers.
 * @param tracee the tracee's PID
 * @param regs values for tracee's registers
 */
bool setRegs(pid_t tracee, struct user_regs_struct &regs);

/**
 * Read memory from a tracee's (child) address space.
 * @param tracee the tracee's PID
 * @param addr address to read
 * @param data output argument set to bytes read from tracee
 * @return true if succeeded or false otherwise
 */
bool getMem(pid_t tracee, uintptr_t addr, uint64_t &data);

/**
 * Write memory to a tracee's (child) address space.
 * @param tracee the tracee's PID
 * @param addr address to read
 * @param data data to write to addr
 * @return true if succeeded or false otherwise
 */
bool setMem(pid_t tracee, uintptr_t addr, uint64_t data);

}
}

#endif /* _PTRACE_H */

