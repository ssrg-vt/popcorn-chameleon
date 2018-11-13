/**
 * Utilities hiding architecture-specific details.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/16/2018
 */

#ifndef _ARCH_H
#define _ARCH_H

#define LINUX
#define X86_64
#include <dr_api.h>
#include <dr_ir_opnd.h>

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
 * Classify an architecture-specific register as an architecture-agnostic type.
 * @param reg register encoded in the ISA's DWARF debugging register format
 * @return the register type
 */
enum RegType getRegType(uint16_t reg);

/**
 * Return the size in bytes of a callee-saved register.
 * @param reg register encoded in the ISA's DWARF debugging register format
 * @return size in bytes of the amount of callee-save space used for reg
 */
uint16_t getCalleeSaveSize(uint16_t reg);

/**
 * Initial frame size when entering a function.
 * @return the initial frame size
 */
uint32_t initialFrameSize();

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

///////////////////////////////////////////////////////////////////////////////
// DynamoRIO interface
///////////////////////////////////////////////////////////////////////////////

/**
 * Initialize architecture-specific information for the
 * decoder/encoder/disassembler library.
 * @return a return code describing the outcome
 */
ret_t initDisassembler();

/**
 * Same as above except take as input a DynamoRIO-encoded register.
 * @param reg register encoded in DynamoRIO's register format
 * @return the register type
 */
enum RegType getRegTypeDR(reg_id_t reg);

/**
 * Return DynamoRIO's encoding for a register type.
 * @param reg chameleon's register type
 * @return DynamoRIO's register encoding
 */
reg_id_t getDRRegType(enum RegType reg);

/**
 * Get the update amount for frame size.
 * @param instr the instruction
 * @param newSize the new size with which to rewrite ISA-specific frame setup
 *                instructions to accomodate randomized stack slots
 * @param doEncode output argument set to true if instruction needs to be
 *                 re-encoded (i.e., we rewrote an operand)
 * @return amount, in bytes, the frame is updated
 */
int32_t getFrameSizeUpdate(instr_t &instr, uint32_t newSize, bool &doEncode);

}
}

#endif /* _ARCH_H */

