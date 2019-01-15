#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "arch.h"
#include "log.h"
#include "parasite.h"
#include "process.h"
#include "trace.h"

using namespace chameleon;

/**
 * Called by forked children to set up introspection machinery and execute the
 * requested application.  The process doesn't return from here.
 * @param argv the arguments to pass to the new application
 * @param socket a UNIX domain socket connected to the parent
 */
[[noreturn]] static void
execChild(char **argv, int socket) {
  bool err = false;
  pid_t me;

  // Wait for the parent to attach
  if(recv(socket, &me, sizeof(me), 0) != sizeof(me)) err = true;
  close(socket);
  if(err) {
    perror("Could not wait for parent to set up tracing in the child");
    abort();
  }

  // Trace-stop to allow the parent to configure ptrace options
  if(raise(SIGSTOP)) {
    perror("Could not raise SIGSTOP to enable parent to configure tracing");
    abort();
  }

  // Let's do the dang thing
  execv(argv[0], argv);
  perror("Could not exec application");
  abort();
}

ret_t Process::forkAndExec() {
  bool err = false;
  int sockets[2];
  pid_t child;

  // Don't let the user fork another child if we've already got one
  if(status != Ready) return ret_t::Exists;

  // Establish a pair of connected sockets for synchronizing the parent
  // attaching to the child via ptrace
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1)
    return ret_t::TraceSetupFailed;

  child = fork();
  if(child == 0) execChild(argv, sockets[1]);
  else if(child < 0) {
    close(sockets[0]);
    close(sockets[1]);
    return ret_t::ForkFailed;
  }
  pid = child;
  status = Running;
  nthreads = 1;

  DEBUGMSG("forked child " << pid << std::endl);

  // Attach via seizing (which lets us interrupt the child later on) and
  // release the child
  if(!trace::attach(pid, true) ||
     send(sockets[0], &child, sizeof(child), 0) != sizeof(child)) err = true;
  close(sockets[0]);
  close(sockets[1]);
  if(err) return ret_t::TraceSetupFailed;

  // Wait until the child trace-stops and configure ptrace to allow chameleon
  // to observe a number of events
  if(waitInternal(false) != ret_t::Success || status != Stopped ||
     !trace::traceProcessControl(pid))
    return ret_t::TraceSetupFailed;

  // TODO: without reading the registers, we get a floating-point exception
  // when using x87 (which may appear in odd places like printf).  Maybe it
  // initializes some FP state that is otherwise not initialized? ¯\_(ツ)_/¯
  struct user_fpregs_struct fpregs;
  trace::getFPRegs(pid, fpregs);

  // Finally, get to the other side of the execve
  if(resume(false) != ret_t::Success || waitInternal(false) != ret_t::Success)
    return ret_t::TraceSetupFailed;

  DEBUGMSG("set up child for tracing" << std::endl);

  return ret_t::Success;
}

// TODO check wstatus in waitInternal for the following:
//   clone()  : status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))
//   execve() : status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))
//   fork()   : status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8))

ret_t Process::waitInternal(bool reinject) {
  int wstatus;
  ret_t retval = ret_t::Success;

  // Return immediately if the process is already stopped/exited
  if(status != Running) return ret_t::Success;

  // Wait for the child and update the status based on returned values
  if(waitpid(pid, &wstatus, 0) == -1) {
    status = Unknown;
    retval = ret_t::WaitFailed;
    DEBUGMSG("waiting for child returned an error" << std::endl);
  }
  else {
    if(WIFEXITED(wstatus)) {
      status = Exited;
      exit = WEXITSTATUS(wstatus);
    }
    else if(WIFSIGNALED(wstatus)) {
      status = SignalExit;
      signal = WTERMSIG(wstatus);
    }
    else if(WIFSTOPPED(wstatus)) {
      // Don't reinject SIGTRAP -- it's a syscall invoked by the application
      status = Stopped;
      signal = WSTOPSIG(wstatus);
      reinjectSignal = reinject && (signal != SIGTRAP);
    }
    else {
      status = Unknown;
      retval = ret_t::WaitFailed;
      DEBUGMSG("unknown wait status" << std::endl);
    }
  }

  return retval;
}

ret_t Process::wait() { return waitInternal(true); }

ret_t Process::resume(bool syscall) {
  bool success;

  switch(status) {
  // Return immediately if the process is already running
  case Running: return ret_t::Success;

  // We can't resume a process that's dead...
  case Exited:
  case SignalExit: return ret_t::DoesNotExist;

  default:
    if(reinjectSignal) success = trace::resume(pid, signal, syscall);
    else success = trace::resume(pid, 0, syscall);
    if(success) {
      status = Running;
      return ret_t::Success;
    }
    else return ret_t::PtraceFailed;
  }
}

ret_t Process::continueToNextEvent(bool syscall) {
  ret_t retcode = resume(syscall);
  if(retcode != ret_t::Success) return retcode;
  return waitInternal(true);
}

void Process::detach() {
  trace::detach(pid);
  close(uffd);
  pid = -1;
  status = Ready;
  exit = 0;
  reinjectSignal = false;
  uffd = -1;
}

ret_t Process::stealUserfaultfd(struct parasite_ctl *ctx) {
  ret_t retcode;
  retcode = parasite::infect(ctx, nthreads);
  if(retcode != ret_t::Success) return retcode;
  if((uffd = parasite::stealUFFD(ctx)) == -1) {
    parasite::cure(ctx);
    return ret_t::CompelActionFailed;
  }
  return parasite::cure(ctx);
}

int Process::getExitCode() const {
  if(status == Exited) return exit;
  else return INT32_MAX;
}

int Process::getSignal() const {
  if(status == SignalExit || status == Stopped) return signal;
  else return INT32_MAX;
}

// TODO the functions that only access a single register (i.e., get/setPC())
// should be converted to use PTRACE_PEEKUSER/POKUSER rather than bulk
// reading/writing the entire register set

uintptr_t Process::getPC() const {
  struct user_regs_struct regs;
  if(status != Stopped) return 0;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  return arch::pc(regs);
}

ret_t Process::setPC(uintptr_t newPC) const {
  struct user_regs_struct regs;
  if(status != Stopped) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::pc(regs, newPC);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::setFuncCallRegs(long a1, long a2, long a3,
                               long a4, long a5, long a6) const {
  struct user_regs_struct regs;
  if(status != Stopped) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::marshalFuncCall(regs, a1, a2, a3, a4, a5, a6);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::read(uintptr_t addr, uint64_t &data) const {
  if(!trace::getMem(pid, addr, data)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::write(uintptr_t addr, uint64_t data) const {
  if(!trace::setMem(pid, addr, data)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

void Process::dumpRegs() const {
  struct user_regs_struct regs;
  struct user_fpregs_struct fpregs;
  if(trace::getRegs(pid, regs)) arch::dumpRegs(regs);
  if(trace::getFPRegs(pid, fpregs)) arch::dumpFPRegs(fpregs);
}

