/**
 * Utilities to make ptrace bearable.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _TRACE_H
#define _TRACE_H

#include <cstdint>
#include <unistd.h>
#include <sys/user.h>

namespace chameleon {
namespace trace {

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
 * Trace all process control events, including execve(), clone() and fork().
 * Additionally, instruct ptrace to kill the child if we exit for any reason.
 * Internally sets PTRACE_O_<EXITKILL|TRACECLONE|TRACEEXEC|TRACEFORK>.
 *
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool traceProcessControl(pid_t tracee);

////////////////////////////////////////////////////////////////////////////////
// Control
////////////////////////////////////////////////////////////////////////////////

/**
 * Attach to a tracee.  If seize == true attach using PTRACE_SEIZE, which
 * allows subsequent interruptions via interrupt().  Otherwise, attach using
 * the more limited via PTRACE_ATTACH.
 *
 * @param tracee the tracee's PID
 * @param seize if true, use PTRACE_SEIZE to attach to tracee
 * @return true if the call succeeded, false otherwise
 */
bool attach(pid_t tracee, bool seize = true);

/**
 * Interrupt a tracee.  Note that this requires attaching to the tracee with
 * trace::attach(pid, true) (use PTRACE_SEIZE).
 *
 * @param tracee the tracee's PID
 * @return true if the call succeeded, false otherwise
 */
bool interrupt(pid_t tracee);

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

#endif /* _TRACE_H */

