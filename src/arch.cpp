#include "arch.h"
#include "log.h"
#include "transform.h"
#include "types.h"
#include "utils.h"

#include "regs.h"

using namespace chameleon;

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

uint32_t arch::alignFrameSize(uint32_t size) { return ROUND_UP(size, 16); }

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
  INFO(DUMP_REG(regs, rax) << std::endl);
  INFO(DUMP_REG(regs, rbx) << std::endl);
  INFO(DUMP_REG(regs, rcx) << std::endl);
  INFO(DUMP_REG(regs, rdx) << std::endl);
  INFO(DUMP_REG(regs, rsi) << std::endl);
  INFO(DUMP_REG(regs, rdi) << std::endl);
  INFO(DUMP_REG(regs, rbp) << std::endl);
  INFO(DUMP_REG(regs, rsp) << std::endl);
  INFO(DUMP_REG(regs, r8) << std::endl);
  INFO(DUMP_REG(regs, r9) << std::endl);
  INFO(DUMP_REG(regs, r10) << std::endl);
  INFO(DUMP_REG(regs, r11) << std::endl);
  INFO(DUMP_REG(regs, r12) << std::endl);
  INFO(DUMP_REG(regs, r13) << std::endl);
  INFO(DUMP_REG(regs, r14) << std::endl);
  INFO(DUMP_REG(regs, r15) << std::endl);
  INFO(DUMP_REG(regs, rip) << std::endl);
  INFO(DUMP_REG(regs, cs) << std::endl);
  INFO(DUMP_REG(regs, ds) << std::endl);
  INFO(DUMP_REG(regs, es) << std::endl);
  INFO(DUMP_REG(regs, fs) << std::endl);
  INFO(DUMP_REG(regs, fs_base) << std::endl);
  INFO(DUMP_REG(regs, gs) << std::endl);
  INFO(DUMP_REG(regs, gs_base) << std::endl);
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
 * @return the immediate value added to the stack pointer, or 0 if it's not a
 *         immediate used with the stack pointer
 */
static int32_t stackPointerMathImm(instr_t *instr) {
  bool valid = true;
  int32_t update = 0;
  opnd_t op;

  for(int i = 0; i < instr_num_srcs(instr); i++) {
    op = instr_get_src(instr, i);
    if(opnd_is_immed_int(op)) update = opnd_get_immed_int(op);
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

int32_t arch::getFrameUpdateSize(instr_t *instr) {
  switch(instr_get_opcode(instr)) {
  // Updating stack pointer by an immediate
  case OP_sub: return stackPointerMathImm(instr);
  case OP_add: return -stackPointerMathImm(instr);

  // Pushing/popping values from the stack
  case OP_push:
    return CodeTransformer::getOperandSize(instr_get_src(instr, 0));
  case OP_pushf: return 8;
  case OP_pop:
    return -CodeTransformer::getOperandSize(instr_get_dst(instr, 0));
  case OP_popf: return -8;

  // Instructions that modify the stack pointer in a way we don't care about
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
  case OP_ret:  case OP_ret_far: return 0;

  default: WARN("Unhandled update to stack pointer" << std::endl); return 0;
  }
}

range arch::getOffsetRestriction(opnd_t op) {
  if(opnd_is_base_disp(op)) {
    // Because x86-64 is so *darn* flexible, the compiler can encode
    // displacements with varying bit-widths depending on the needed size
    int disp = opnd_get_disp(op);
    if(INT8_MIN <= disp && disp <= INT8_MAX && !opnd_is_disp_force_full(op))
      return range(INT8_MIN, INT8_MAX);
    else if(INT32_MIN <= disp && disp <= INT32_MAX)
      return range(INT32_MIN, INT32_MAX);
    else return range(INT64_MIN, INT64_MAX);
  }
  return range(INT32_MIN, INT32_MAX);
}

bool arch::canTransformFrameUpdate(instr_t *instr) {
  switch(instr_get_opcode(instr)) {
  case OP_sub: case OP_add: return true;
  default: return false;
  }
}

/**
 * Rewrite a stack pointer + immediate math instruction with a new immediate.
 * @param instr the instruction
 * @param newImm the new immediate
 * @return true if successfully rewritten or false otherwise
 */
static bool rewriteStackPointerMathImm(instr_t *instr, int32_t newImm) {
  bool valid = true;
  opnd_t op;

  for(int i = 0; i < instr_num_srcs(instr); i++) {
    op = instr_get_src(instr, i);
    if(opnd_is_immed_int(op)) {
      op = opnd_create_immed_int(newImm, opnd_get_size(op));
      instr_set_src(instr, i, op);
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

  return valid;
}

ret_t
arch::rewriteFrameUpdate(instr_t *instr, int32_t newSize, bool &changed) {
  changed = false;
  switch(instr_get_opcode(instr)) {
  case OP_sub:
    if(!rewriteStackPointerMathImm(instr, newSize))
      return ret_t::RandomizeFailed;
    changed = true;
    break;
  case OP_add:
    if(!rewriteStackPointerMathImm(instr, -newSize))
      return ret_t::RandomizeFailed;
    changed = true;
    break;
  default: break;
  }
  return ret_t::Success;
}

#else
# error "Unsupported architecture!"
#endif

