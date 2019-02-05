#include <cerrno>
#include <csignal>
#include <sys/ptrace.h>

#include "trace.h"

using namespace chameleon;

// Note: the format of the ptrace call is the following:
//   ptrace(int request, pid_t pid, void *addr, void *data)

bool trace::traceme() {
  if(ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == 0) return true;
  else return false;
}

bool trace::traceProcessControl(pid_t tracee) {
  if(ptrace(PTRACE_SETOPTIONS, tracee, nullptr, PTRACE_O_EXITKILL |
                                                PTRACE_O_TRACECLONE |
                                                PTRACE_O_TRACEEXEC |
                                                PTRACE_O_TRACEFORK) == 0)
    return true;
  else return false;
}

bool trace::attach(pid_t tracee, bool seize) {
  if(ptrace((seize ? PTRACE_SEIZE : PTRACE_ATTACH),
            tracee, nullptr, nullptr) == 0) return true;
  else return false;
}

bool trace::interrupt(pid_t tracee) {
  if(ptrace(PTRACE_INTERRUPT, tracee, nullptr, nullptr) == 0) return true;
  else return false;
}

stop_t trace::stopReason(int wstatus) {
  wstatus >>= 8;
  if(wstatus == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) return stop_t::Clone;
  else if(wstatus == (SIGTRAP | (PTRACE_EVENT_EXEC << 8))) return stop_t::Exec;
  else if(wstatus == (SIGTRAP | (PTRACE_EVENT_FORK << 8))) return stop_t::Fork;
  else return stop_t::Other;
}

bool trace::resume(pid_t tracee, resume_t type, int signal) {
  enum __ptrace_request req;
  switch(type) {
  default: return false;
  case Continue: req = PTRACE_CONT; break;
  case Syscall: req = PTRACE_SYSCALL; break;
  case SingleStep: req = PTRACE_SINGLESTEP; break;
  }

  if(ptrace(req, tracee, nullptr, signal) == 0) return true;
  else return false;
}

bool trace::detach(pid_t tracee) {
  if(ptrace(PTRACE_DETACH, tracee, nullptr, nullptr) == 0) return true;
  else return false;
}

bool trace::getEventMessage(pid_t tracee, unsigned long &msg) {
  if(ptrace(PTRACE_GETEVENTMSG, tracee, nullptr, &msg) == 0) return true;
  else return false;
}

bool trace::getRegs(pid_t tracee, struct user_regs_struct &regs) {
  if(ptrace(PTRACE_GETREGS, tracee, nullptr, &regs) == 0) return true;
  else return false;
}

bool trace::getFPRegs(pid_t tracee, struct user_fpregs_struct &regs) {
  if(ptrace(PTRACE_GETFPREGS, tracee, nullptr, &regs) == 0) return true;
  else return false;
}

bool trace::setRegs(pid_t tracee,  struct user_regs_struct &regs) {
  if(ptrace(PTRACE_SETREGS, tracee, nullptr, &regs) == 0) return true;
  else return false;
}

bool trace::setFPRegs(pid_t tracee, struct user_fpregs_struct &regs) {
  if(ptrace(PTRACE_SETFPREGS, tracee, nullptr, &regs) == 0) return true;
  else return false;
}

bool trace::getMem(pid_t tracee, uintptr_t addr, uint64_t &data) {
  // From the ptrace manpage:
  //   On error, all requests return -1, and errno is set appropriately.  Since
  //   the value returned by a successful PTRACE_PEEK* request may be -1, the
  //   caller must clear errno before the call, and then check it afterward to
  //   determine whether or not an error occurred.
  errno = 0;
  data = ptrace(PTRACE_PEEKDATA, tracee, addr, nullptr);
  if(errno) return false;
  return true;
}

bool trace::setMem(pid_t tracee, uintptr_t addr, uint64_t data) {
  if(ptrace(PTRACE_POKEDATA, tracee, addr, data) == 0) return true;
  else return false;
}

