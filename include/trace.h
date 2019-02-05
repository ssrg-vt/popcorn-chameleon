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

#include "types.h"

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
 * Return the reason a thread was stopped.
 * @param wstatus the wait status as returned by the wait() family of syscalls
 * @return the reason a thread was stopped
 */
stop_t stopReason(int wstatus);

/* Type of resume operation */
enum resume_t {
  Continue = 0, /* continue until next signal */
  Syscall,      /* continue until next signal or system call */
  SingleStep    /* step a single instruction */
};

/**
 * Resume a tracee (child).
 * @param tracee the tracee's PID
 * @param type the type of resume operation
 * @param signal signal to be delivered to child if non-zero
 * @return true if call succeeded, false otherwise
 */
bool resume(pid_t tracee, resume_t type, int signal = 0);

/**
 * Detach from a tracee (child).
 * @param tracee the tracee's PID
 * @return true if call succeeded, false otherwise
 */
bool detach(pid_t tracee);

/**
 * Retrieve a message about a recent ptrace event.  The returned value depends
 * on the actual event.
 * @param tracee the tracee's PID
 * @param msg reference to storage to be populated with the event message
 * @return true if the call succeeded, false otherwise
 */
bool getEventMessage(pid_t tracee, unsigned long &msg);

/**
 * Get a tracee's (child) registers.
 * @param tracee the tracee's PID
 * @param regs register set struct to be filled
 * @return true if call succeeded, false otherwise
 */
bool getRegs(pid_t tracee, struct user_regs_struct &regs);

/**
 * Get a tracee's (child) floating-point registers.
 * @param tracee the tracee's PID
 * @param regs floating point register set struct to be filled
 * @return true if call succeeded, false otherwise
 */
bool getFPRegs(pid_t tracee, struct user_fpregs_struct &regs);

/**
 * Set a tracee's (child) registers.
 * @param tracee the tracee's PID
 * @param regs values for tracee's registers
 * @return true if call succeeded, false otherwise
 */
bool setRegs(pid_t tracee, struct user_regs_struct &regs);

/**
 * Set a tracee's (child) floating-point registers.
 * @param tracee the tracee's PID
 * @param regs values for tracee's floating-point registers
 * @return true if call succeeded, false otherwise
 */
bool setFPRegs(pid_t tracee, struct user_fpregs_struct &regs);

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

