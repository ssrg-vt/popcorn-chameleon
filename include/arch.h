/**
 * Utilities hiding architecture-specific details.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/16/2018
 */

#ifndef _ARCH_H
#define _ARCH_H

#include <cstdint>
#include <cstddef>
#include <sys/user.h>

namespace chameleon {
namespace arch {

/**
 * Return the system call instruction bytes and write the size of the
 * instruction to the argument.
 * @param size size of the syscall instruction in bytes
 * @return the bytes constituting the syscall instruction
 */
uint64_t syscall(size_t &size);

/**
 * Extract the program counter from a register set.
 * @param regs a register set
 * @return the program counter's value
 */
uintptr_t pc(const struct user_regs_struct &regs);

/**
 * Set a process' program counter in a register set.
 * @param regs a register set
 * @param newPC the new program counter
 */
void pc(user_regs_struct &regs, uintptr_t newPC);

/**
 * Marshal the given arguments into the register set for a function call.
 * @param regs a register set
 * @param a1-6 arguments to place in registers for syscall
 */
void marshalFuncCall(struct user_regs_struct &regs,
                     long a1, long a2, long a3, long a4, long a5, long a6);

/**
 * Marshal the given arguments into the register set for a system call.
 * @param regs a register set
 * @param syscall the system call number
 * @param a1-6 arguments to place in registers for syscall
 */
void marshalSyscall(struct user_regs_struct &regs, long syscall,
                    long a1, long a2, long a3, long a4, long a5, long a6);

/**
 * Retrieve the value in the register used to return system call return values.
 * Note: caller must ensure process is stopped at system call exit boundary!
 * @param regs a register set
 * @return system call return value
 */
int syscallRetval(struct user_regs_struct &regs);

}
}

#endif /* _ARCH_H */

