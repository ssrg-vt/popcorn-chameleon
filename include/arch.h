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

#include "types.h"

namespace chameleon {
namespace arch {

/**
 * Architecture-agnostic register classification.
 */
enum RegType {
  FramePointer,
  StackPointer,
  None
};

/**
 * Initialize architecture-specific information for the
 * decoder/encoder/disassembler library.
 * @return a return code describing the outcome
 */
ret_t initDisassembler();

/**
 * Classify an architecture-specific register as an architecture-agnostic type.
 * @param reg register encoded in the ISA's DWARF debugging register format
 * @return the register type
 */
enum RegType getRegType(uint16_t reg);

/**
 * Return the architecture-specific frame pointer offset from the frame's
 * canonical frame address (CFA).
 * @return frame pointer's offset from the CFA
 */
int32_t framePointerOffset();

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

/**
 * Dump register contents to a stream.
 * @param regs a pre-populated register set
 */
void dumpRegs(struct user_regs_struct &regs);

}
}

#endif /* _ARCH_H */

