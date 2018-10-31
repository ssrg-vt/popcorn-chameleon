#define LINUX
#define X86_64
#include <dr_api.h>

#include "arch.h"
#include "log.h"
#include "types.h"

using namespace chameleon;

#if defined __x86_64__

ret_t arch::initDisassembler() {
  bool ret = dr_set_isa_mode(GLOBAL_DCONTEXT, DR_ISA_AMD64, nullptr);
  DEBUG(disassemble_set_syntax(DR_DISASM_ATT));
  if(!ret) return ret_t::DisasmSetupFailed;
  else return ret_t::Success;
}

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

#else
# error "Unsupported architecture!"
#endif

