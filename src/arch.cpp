#include "arch.h"
#include "log.h"
#include "types.h"

#include "regs.h"
#include <dr_ir_opcodes.h>

using namespace chameleon;

/**
 * Get the size of a DynamoRIO operand in bytes.
 * @param op an operand
 * @return size of the operand in bytes
 */
static inline unsigned getOperandSize(opnd_t op) {
  switch(opnd_get_size(op)) {
  case OPSZ_0: return 0;
  case OPSZ_1: return 1;
  case OPSZ_2: return 2;
  case OPSZ_4: return 4;
  case OPSZ_6: return 6;
  case OPSZ_8: return 8;
  case OPSZ_10: return 10;
  case OPSZ_16: return 16;
  case OPSZ_14: return 14;
  case OPSZ_28: return 28;
  case OPSZ_94: return 94;
  case OPSZ_108: return 108;
  case OPSZ_512: return 512;
  default: WARN("Unknown operand size" << std::endl); return 0;
  }
}

#if defined __x86_64__

enum arch::RegType arch::getRegType(uint16_t reg) {
  switch(reg) {
  case RBP: return RegType::FramePointer;
  case RSP: return RegType::StackPointer;
  default: return RegType::None;
  }
}

uint16_t arch::getCalleeSaveSize(uint16_t reg) {
  switch(reg) {
  case RBX: case RBP: case R12: case R13: case R14: case R15: case RIP:
    return 8;
  default: return 0;
  }
}

uint32_t arch::initialFrameSize() { return 8; }

int32_t arch::framePointerOffset() { return -16; }

uint64_t arch::syscall(size_t &size) {
  size = 2;
  return 0x050f;
}

uintptr_t arch::pc(const struct user_regs_struct &regs)
{ return regs.rip; }
void arch::pc(struct user_regs_struct &regs, uintptr_t newPC)
{ regs.rip = newPC; }

void arch::marshalFuncCall(struct user_regs_struct &regs,
                           long a1, long a2, long a3,
                           long a4, long a5, long a6) {
  regs.rdi = a1;
  regs.rsi = a2;
  regs.rdx = a3;
  regs.rcx = a4;
  regs.r8 = a5;
  regs.r9 = a6;
}

void arch::marshalSyscall(struct user_regs_struct &regs, long syscall,
                          long a1, long a2, long a3,
                          long a4, long a5, long a6) {
  regs.rax = syscall;
  regs.rdi = a1;
  regs.rsi = a2;
  regs.rdx = a3;
  regs.r10 = a4;
  regs.r8 = a5;
  regs.r9 = a6;
}

int arch::syscallRetval(struct user_regs_struct &regs) {
  return regs.rax;
}

#define DUMP_REG( regset, name ) \
  #name": " << std::dec << regset.name << " / 0x" << std::hex << regset.name

void arch::dumpRegs(struct user_regs_struct &regs) {
  INFO(DUMP_REG(regs, rax) << std::endl)
  INFO(DUMP_REG(regs, rbx) << std::endl)
  INFO(DUMP_REG(regs, rcx) << std::endl)
  INFO(DUMP_REG(regs, rdx) << std::endl)
  INFO(DUMP_REG(regs, rsi) << std::endl)
  INFO(DUMP_REG(regs, rdi) << std::endl)
  INFO(DUMP_REG(regs, rbp) << std::endl)
  INFO(DUMP_REG(regs, rsp) << std::endl)
  INFO(DUMP_REG(regs, r8) << std::endl)
  INFO(DUMP_REG(regs, r9) << std::endl)
  INFO(DUMP_REG(regs, r10) << std::endl)
  INFO(DUMP_REG(regs, r11) << std::endl)
  INFO(DUMP_REG(regs, r12) << std::endl)
  INFO(DUMP_REG(regs, r13) << std::endl)
  INFO(DUMP_REG(regs, r14) << std::endl)
  INFO(DUMP_REG(regs, r15) << std::endl)
  INFO(DUMP_REG(regs, rip) << std::endl)
  INFO(DUMP_REG(regs, cs) << std::endl)
  INFO(DUMP_REG(regs, ds) << std::endl)
  INFO(DUMP_REG(regs, es) << std::endl)
  INFO(DUMP_REG(regs, fs) << std::endl)
  INFO(DUMP_REG(regs, fs_base) << std::endl)
  INFO(DUMP_REG(regs, gs) << std::endl)
  INFO(DUMP_REG(regs, gs_base) << std::endl)
  INFO(DUMP_REG(regs, ss) << std::endl);
}

ret_t arch::initDisassembler() {
  bool ret = dr_set_isa_mode(GLOBAL_DCONTEXT, DR_ISA_AMD64, nullptr);
  if(!ret) return ret_t::DisasmSetupFailed;
  else return ret_t::Success;
}

enum arch::RegType arch::getRegTypeDR(reg_id_t reg) {
  switch(reg) {
  case DR_REG_XBP: return RegType::FramePointer;
  case DR_REG_XSP: return RegType::StackPointer;
  default: return RegType::None;
  }
}

reg_id_t arch::getDRRegType(enum RegType reg) {
  switch(reg) {
  case RegType::FramePointer: return DR_REG_XBP;
  case RegType::StackPointer: return DR_REG_XSP;
  default: return DR_REG_NULL;
  }
}

/**
 * Return the immediate value used with the stack pointer in a math operation.
 * @param instr the instruction
 * @param newSize the new size with which to rewrite frame setup immediates to
 *                accomodate randomized stack slots
 * @return the immediate value added to the stack pointer, or 0 if it's not a
 *         immediate used with the stack pointer
 */
static inline int32_t
stackPointerMathImm(instr_t &instr, int32_t newSize, bool &doEncode) {
  bool valid = true;
  int32_t update = 0;
  opnd_t op;

  for(int i = 0; i < instr_num_srcs(&instr); i++) {
    op = instr_get_src(&instr, i);
    if(opnd_is_immed_int(op)) {
      // TODO make newSize have same signedness as update
      update = opnd_get_immed_int(op);
      if(newSize > update) {
        op = opnd_create_immed_int(newSize, opnd_get_size(op));
        instr_set_src(&instr, i, op);
        doEncode = true;
      }
    }
    else if(opnd_is_reg(op)) {
      // Ensure the register operand is the stack pointer
      if(opnd_get_reg(op) != DR_REG_XSP) {
        valid = false;
        break;
      }
    }
    else {
      // Unknown operand type
      valid = false;
      break;
    }
  }
  if(!valid) update = 0;
  return update;
}

int32_t
arch::getFrameSizeUpdate(instr_t &instr, uint32_t newSize, bool &doEncode) {
  switch(instr_get_opcode(&instr)) {
  // Updating stack pointer by an immediate
  case OP_sub: return stackPointerMathImm(instr, newSize, doEncode);
  case OP_add: return -stackPointerMathImm(instr, newSize, doEncode);

  // Pushing/popping values from the stack
  case OP_push: return getOperandSize(instr_get_src(&instr, 0));
  case OP_pushf: return 8;
  case OP_pop: return -getOperandSize(instr_get_dst(&instr, 0));
  case OP_popf: return -8;

  // Instructions that modify the stack pointer in a way we don't care about
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
  case OP_ret:  case OP_ret_far: return 0;

  default: WARN("Unhandled update to stack pointer" << std::endl); return 0;
  }
}

#else
# error "Unsupported architecture!"
#endif

