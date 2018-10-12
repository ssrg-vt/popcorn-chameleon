#include <sys/ptrace.h>

#include "ptrace.h"

using namespace chameleon;

// Note: the format of the ptrace call is the following:
//   ptrace(int request, pid_t pid, void *addr, void *data)

bool PTrace::traceme() {
  if(ptrace(PTRACE_TRACEME, 0, 0, 0) == 0) return true;
  else return false;
}

bool PTrace::killChildOnExit(pid_t tracee) {
  if(ptrace(PTRACE_SETOPTIONS, tracee, 0, PTRACE_O_EXITKILL) == 0) return true;
  else return false;
}

bool PTrace::resume(pid_t tracee, int signal) {
  if(ptrace(PTRACE_CONT, tracee, 0, signal) == 0) return true;
  else return false;
}

bool PTrace::detach(pid_t tracee) {
  if(ptrace(PTRACE_DETACH, tracee, 0, 0) == 0) return true;
  else return false;
}

