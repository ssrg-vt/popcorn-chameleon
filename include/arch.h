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

#include <cstdint>
#include <cstddef>
#include <sys/user.h>

#include "randomize.h"
#include "types.h"

/*
 * Stack growth direction -- each ISA must declare which direction the stack
 * grows.
 */
#define UP   0 /* grows from lower addresses to higher addresses */
#define DOWN 1 /* grows from higher addresses to lower addresses */

#ifdef __x86_64__
# define STACK_DIRECTION DOWN
#endif

#ifndef STACK_DIRECTION
# error Each ISA must define which direction the stack grows
#endif

namespace chameleon {
namespace arch {

///////////////////////////////////////////////////////////////////////////////
// Miscellaneous
///////////////////////////////////////////////////////////////////////////////

/**
 * Return whether or not the architecture is supported.
 * @param arch e_machine field from the Elf64_Ehdr
 * @return true if supported or false otherwise
 */
bool supportedArch(uint16_t arch);

///////////////////////////////////////////////////////////////////////////////
// Register information & handling
///////////////////////////////////////////////////////////////////////////////

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
 * Get human-readable name for a register.
 * @param reg register encoded in the ISA's DWARF debugging register format
 * @return the register name
 */
const char *getRegName(uint16_t reg);

/**
 * Return the size in bytes of a callee-saved register.
 * @param reg register encoded in the ISA's DWARF debugging register format
 * @return size in bytes of the amount of callee-save space used for reg
 */
uint16_t getCalleeSaveSize(uint16_t reg);

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
 * @param a1-6 arguments to place in registers for function call
 */
void marshalFuncCall(struct user_regs_struct &regs,
                     long a1, long a2, long a3, long a4, long a5, long a6);

/**
 * Dump register contents.
 * @param regs a pre-populated register set
 */
void dumpRegs(struct user_regs_struct &regs);

/**
 * Dump floating-point register contents.
 * @param regs a pre-populated floating-point register set
 */
void dumpFPRegs(struct user_fpregs_struct &fpregs);

///////////////////////////////////////////////////////////////////////////////
// Stack frame information & handling
///////////////////////////////////////////////////////////////////////////////

/**
 * Initial frame size when entering a function.
 * @return the initial frame size
 */
uint32_t initialFrameSize();

/**
 * Align a frame size to meet the ISA's ABI requirements.
 * @param size a frame size
 * @return the aligned frame size
 */
uint32_t alignFrameSize(uint32_t size);

/**
 * Return the architecture-specific frame pointer offset from the frame's
 * canonical frame address (CFA).
 * @return frame pointer's offset from the CFA
 */
int32_t framePointerOffset();

///////////////////////////////////////////////////////////////////////////////
// Randomization implementation
///////////////////////////////////////////////////////////////////////////////

/**
 * Return a RandomizedFunction object specialized for the current ISA.
 * @param binary a Binary object
 * @param func a function record object
 * @return a RandomizedFunction object
 */
RandomizedFunctionPtr getRandomizedFunction(const Binary &binary,
                                            const function_record *func);

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
 * Get the amount of space allocated/de-allocated on the stack by an
 * instruction.
 * @param instr the instruction
 * @return size, in bytes, of the frame allocation
 */
int32_t getFrameUpdateSize(instr_t *instr);

/**
 * Get offset restrictions, if any, for an operand.
 * @param instr the instruction
 * @param res output operand populated with any restrictions
 * @return true if there is a restriction for the instruction or false if not
 */
bool getRestriction(instr_t *instr, RandRestriction &res);

/**
 * Get offset restrictions, if any, for an operand.
 * @param instr the instruction
 * @param op the operand from the instruction
 * @param res output operand populated with any restrictions
 * @return true if there is a restriction for the operand or false if not
 */
bool getRestriction(instr_t *instr, opnd_t op, RandRestriction &res);

/**
 * Rewrite a frame update instruction with a new size.
 * @param instr the instruction
 * @param newSize the new frame allocation size
 * @param changed output argument set to true if the instruction was changed
 * @return a return code describing the outcome
 */
ret_t rewriteFrameUpdate(instr_t *instr, int32_t newSize, bool &changed);

}
}

#endif /* _ARCH_H */

