#define LINUX
#define X86_64
#include <dr_api.h>

#include "arch.h"
#include "log.h"
#include "types.h"

#include "regs.h"

using namespace chameleon;

#if defined __x86_64__

ret_t arch::initDisassembler() {
  bool ret = dr_set_isa_mode(GLOBAL_DCONTEXT, DR_ISA_AMD64, nullptr);
  if(!ret) return ret_t::DisasmSetupFailed;
  else return ret_t::Success;
}

enum arch::RegType arch::getRegType(uint16_t reg) {
  switch(reg) {
  case RBP: return RegType::FramePointer;
  case RSP: return RegType::StackPointer;
  default: return RegType::None;
  }
}

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

#else
# error "Unsupported architecture!"
#endif

