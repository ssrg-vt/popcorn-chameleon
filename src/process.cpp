#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "arch.h"
#include "log.h"
#include "parasite.h"
#include "process.h"

using namespace chameleon;

/*
 * Linux by default allocates 8MB stacks.  If using a different default size,
 * users should set this variable in order to correctly initialize children.
 */
size_t Process::defaultStackSize = 8 * 1024 * 1024;

/*
 * Note: compel's API is a little obtuse -- compel_prepare() allocates a
 * context and compel_infect() controls the child, whereas compel_cure() both
 * cures and frees the context.  Process is currently designed to always have a
 * context ready to go, so use Process::cure() to both cleanup & initialize the
 * next parasite.
 */

/**
 * Called by forked children to set up introspection machinery and execute the
 * requested application.  The process doesn't return from here.
 * @param argv the arguments to pass to the new application
 * @param socket a UNIX domain socket connected to the parent
 */
[[noreturn]] static void execChild(char **argv, int socket) {
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

  DEBUGMSG("forking/execing child process" << std::endl);

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

  // Attach via seizing (which lets us interrupt the child later) and release
  // the child; we can't configure the child until it reaches a trace-stop.
  if(!trace::attach(pid, true) ||
     send(sockets[0], &child, sizeof(child), 0) != sizeof(child)) err = true;
  close(sockets[0]);
  close(sockets[1]);
  if(err) return ret_t::TraceSetupFailed;

  // Wait until the child trace-stops and configure ptrace to allow chameleon
  // to observe task creation events
  if(waitInternal(false) != ret_t::Success || !traceable() ||
     !trace::traceProcessControl(pid))
    return ret_t::TraceSetupFailed;

  // Finally, get to the other side of the execve
  if(resume(trace::Continue) != ret_t::Success)
    return ret_t::TraceSetupFailed;

  return initForkedChild();
}

ret_t Process::initForkedChild() {
  ret_t code;

  // Wait for the child to reach a trace-stop & initialize
  if((code = waitInternal(false)) != ret_t::Success) return code;
  if(!(parasite = parasite::initialize(pid))) return ret_t::CompelInitFailed;
  if(sem_init(&handoff, 0, 0)) return ret_t::TraceSetupFailed;
  if((code = initializeStack()) != ret_t::Success) return code;
  if((code = initializeMemFD()) != ret_t::Success) return code;

  // TODO: without reading the registers, we get a floating-point exception
  // when using x87 (which may appear in odd places like printf).  Maybe it
  // initializes some FP state that is otherwise not initialized? ¯\_(ツ)_/¯
  struct user_fpregs_struct fpregs;
  trace::getFPRegs(pid, fpregs);

  DEBUGMSG("set up child " << pid << " for tracing" << std::endl);

  return ret_t::Success;
}

ret_t Process::traceThread(pid_t pid) {
  // TODO handle multi-threading
  return ret_t::NotImplemented;
}

ret_t Process::waitInternal(bool reinject) {
  int wstatus;
  unsigned long childPid;
  sigset_t block;
  ret_t retval = ret_t::Success;

  // Return immediately if the process is already stopped/exited
  if(status != Running) return ret_t::Success;

  // Wait for the child and update the status based on returned values
  if(waitpid(pid, &wstatus, 0) == -1) {
    if(errno == EINTR) {
      // Prevent whomever interrupted us from interrupting us again while
      // trying to interrupt the child
      sigemptyset(&block);
      sigaddset(&block, SIGINT);
      if(pthread_sigmask(SIG_BLOCK, &block, &intSet))
        return ret_t::SignalMaskFailed;

      // Somebody interrupted us so that we can perform some action on the
      // child; interrupt the child as well.
      if((retval = interrupt()) != ret_t::Success) {
        DEBUGMSG(pid << "'s handler was interrupted, but the handler could "
                 "not interrupt the child" << std::endl);
        status = Unknown;
        return retval;
      }
    }
    else {
      status = Unknown;
      retval = ret_t::WaitFailed;
      DEBUGMSG("waiting for child returned an error" << std::endl);
    }
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
      status = Stopped;
      signal = WSTOPSIG(wstatus);
      stopReason = trace::stopReason(wstatus);
      if(stopReason == stop_t::Clone ||
         stopReason == stop_t::Fork) {
        if(trace::getEventMessage(pid, childPid)) newTaskPid = childPid;
        else retval = ret_t::PtraceFailed;
      }
      // Don't reinject SIGTRAP -- it's a syscall invoked by the application
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

ret_t Process::initializeStack() {
  size_t dashPos, spacePos;
  char buf[128];
  uintptr_t curPage, val;
  std::string line;
  ret_t code;
  Timer t;

  t.start();
  snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
  std::ifstream map(buf);
  if(!map.is_open()) return ret_t::FileOpenFailed;

  do {
    std::getline(map, line);
    if(line.find("[stack]") != std::string::npos) {
      dashPos = line.find('-');
      spacePos = line.find(' ');
      if(dashPos == std::string::npos ||
         spacePos == std::string::npos) return ret_t::BadFormat;
      stackBounds.second = std::stoul(line.substr(dashPos + 1, spacePos),
                                      nullptr, 16);
      map.close();

      // Touch the bottom to map the entire stack for re-randomization
      curPage = stackBounds.second - defaultStackSize;
      code = read(curPage, val);
      if(code != ret_t::Success) return code;
      stackBounds.first = curPage;

      t.end();
      INFO(pid << ": stack setup: " << t.elapsed(Timer::Micro) << " us"
           << std::endl);
      DEBUGMSG(pid << ": stack bounds: 0x" << std::hex << stackBounds.first
               << " - 0x" << stackBounds.second << std::endl);

      return ret_t::Success;
    }
  } while(map.good());

  map.close();
  return ret_t::BadFormat;
}

ret_t Process::initializeMemFD() {
  char buf[128];
  snprintf(buf, sizeof(buf), "/proc/%d/mem", pid);
  if((memFD = open(buf, O_RDWR)) == -1) return ret_t::FileOpenFailed;
  else return ret_t::Success;
}

ret_t Process::cureAndInitParasite() {
  ret_t code;
  if(parasite) {
    if((code = parasite::cure(&parasite)) != ret_t::Success) return code;
    if(!(parasite = parasite::initialize(pid))) return ret_t::CompelInitFailed;
  }
  return ret_t::Success;
}

ret_t Process::wait() { return waitInternal(true); }

ret_t Process::restoreInterrupt() {
  if(status != Interrupted) return ret_t::InvalidState;
  else if(pthread_sigmask(SIG_SETMASK, &intSet, nullptr))
    return ret_t::SignalMaskFailed;
  else return ret_t::Success;
}

ret_t Process::interrupt() {
  ret_t code = ret_t::Success;

  // TODO copy compel_wait_task() for a more robust implementation
  if(!trace::interrupt(pid)) return ret_t::PtraceFailed;
  if((code = waitInternal(false)) != ret_t::Success) return code;
  if(status != Stopped) return ret_t::InterruptFailed;
  status = Interrupted;
  return ret_t::Success;
}

ret_t Process::signalProcess(int signo) const
{ return kill(pid, signo) == 0 ? ret_t::Success : ret_t::SignalFailed; }

ret_t Process::resume(trace::resume_t type) {
  bool success;

  switch(status) {
  // We can't resume an already running process...
  case Running: return ret_t::InvalidState;

  // We can't resume a process that's dead...
  case Exited: /* fall through */
  case SignalExit: return ret_t::DoesNotExist;

  default:
    if(reinjectSignal) success = trace::resume(pid, type, signal);
    else success = trace::resume(pid, type, 0);
    if(success) {
      status = Running;
      return ret_t::Success;
    }
    else return ret_t::PtraceFailed;
  }
}

ret_t Process::continueToNextSignal() {
  ret_t retcode = resume(trace::Continue);
  if(retcode != ret_t::Success) return retcode;
  return waitInternal(true);
}

ret_t Process::continueToNextSignalOrSyscall() {
  ret_t retcode = resume(trace::Syscall);
  if(retcode != ret_t::Success) return retcode;
  return waitInternal(true);
}

ret_t Process::singleStep() {
  ret_t retcode = resume(trace::SingleStep);
  if(retcode != ret_t::Success) return retcode;
  return waitInternal(true);
}

ret_t Process::attach() {
  ret_t code;

  // Note: traceProcessControl() *must* be called after attaching; these
  // options are clobbered otherwise!
  if(!trace::attach(pid, true)) return ret_t::PtraceFailed;
  if((code = interrupt()) != ret_t::Success) return code;
  if(!trace::traceProcessControl(pid)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::attachHandoff() {
  ret_t code;
  if(MASK_INT(sem_wait(&handoff))) return ret_t::HandoffFailed;

  // Child is daemonized and sleeping waiting for commands.  Cure the parasite
  // to return it to a trace-stop before initializing.
  if(!trace::attach(pid, true)) return ret_t::PtraceFailed;
  if((code = cureAndInitParasite()) != ret_t::Success) return code;
  status = Stopped;

  // Note: traceProcessControl() *must* be called after attaching from the
  // handoff; these options are clobbered if set before the handing-off thread
  // detaches!
  if(!trace::traceProcessControl(pid)) return ret_t::PtraceFailed;

  return ret_t::Success;
}

ret_t Process::detach() {
  close(uffd);
  close(memFD);
  pid = newTaskPid = -1;
  status = Ready;
  exit = 0;
  stopReason = stop_t::Other;
  reinjectSignal = false;
  uffd = -1;
  nthreads = 0;
  parasite::cure(&parasite);
  sem_destroy(&handoff);
  trace::detach(pid);
  return ret_t::Success;
}

ret_t Process::detachHandoff() {
  ret_t code;

  // Daemonize the child the wait for us to reattach
  if(parasite::infect(parasite, 1) != ret_t::Success)
    return ret_t::CompelInfectFailed;
  status = Running;

  // At this point the child is asleep waiting for compel commands, but
  // detaching requires it to be in a trace-stop state.  Interrupt & detach.
  if((code = interrupt()) != ret_t::Success) goto err;
  if(!trace::detach(pid)) {
    code = ret_t::PtraceFailed;
    goto err;
  }

  // Signal the other thread that they are now able to attach
  if(sem_post(&handoff)) {
    code = ret_t::HandoffFailed;
    goto err;
  }

  return ret_t::Success;
err:
  if(cureAndInitParasite() == ret_t::Success) status = Stopped;
  return code;
}


pid_t Process::getNewTaskPid() const {
  if(status == Stopped &&
     (stopReason == stop_t::Fork || stopReason == stop_t::Clone))
    return newTaskPid;
  else return INT32_MAX;
}

int Process::getExitCode() const {
  if(status == Exited) return exit;
  else return INT32_MAX;
}

int Process::getSignal() const {
  if(status == SignalExit || traceable()) return signal;
  else return INT32_MAX;
}

stop_t Process::getStopReason() const {
  if(status == Stopped) return stopReason;
  else return stop_t::Other;
}

ret_t Process::readRegs(struct user_regs_struct &regs) const {
  if(!traceable()) return ret_t::InvalidState;
  else if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  else return ret_t::Success;
}

ret_t Process::readFPRegs(struct user_fpregs_struct &regs) const {
  if(!traceable()) return ret_t::InvalidState;
  else if(!trace::getFPRegs(pid, regs)) return ret_t::PtraceFailed;
  else return ret_t::Success;
}

ret_t Process::writeRegs(struct user_regs_struct &regs) const {
  if(!traceable()) return ret_t::InvalidState;
  else if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  else return ret_t::Success;
}

ret_t Process::writeFPRegs(struct user_fpregs_struct &regs) const {
  if(!traceable()) return ret_t::InvalidState;
  else if(!trace::setFPRegs(pid, regs)) return ret_t::PtraceFailed;
  else return ret_t::Success;
}

// TODO the functions that only access a single register (i.e., get/setPC())
// should be converted to use PTRACE_PEEKUSER/POKUSER rather than bulk
// reading/writing the entire register set

uintptr_t Process::getPC() const {
  struct user_regs_struct regs;
  if(!traceable()) return 0;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  return arch::pc(regs);
}

ret_t Process::setPC(uintptr_t newPC) const {
  struct user_regs_struct regs;
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::pc(regs, newPC);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

uintptr_t Process::getSP() const {
  struct user_regs_struct regs;
  if(!traceable() || !trace::getRegs(pid, regs)) return 0;
  return arch::sp(regs);
}

ret_t Process::setSP(uintptr_t newSP) const {
  struct user_regs_struct regs;
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::sp(regs, newSP);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::setFuncCallRegs(long a1, long a2, long a3,
                               long a4, long a5, long a6) const {
  struct user_regs_struct regs;
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::marshalFuncCall(regs, a1, a2, a3, a4, a5, a6);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::read(uintptr_t addr, uint64_t &data) const {
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::getMem(pid, addr, data)) {
    DEBUGMSG("ptrace read failed at address 0x" << std::hex << addr << ": "
             << strerror(errno) << std::endl);
    return ret_t::PtraceFailed;
  }
  return ret_t::Success;
}

ret_t Process::readRegion(uintptr_t addr, byte_iterator &buffer) const {
  ssize_t bytesRead;

  if(!traceable()) return ret_t::InvalidState;

  if(lseek(memFD, addr, SEEK_SET) == -1) {
    DEBUGMSG("could not seek to address 0x" << std::hex << addr << ": "
             << strerror(errno) << std::endl);
    return ret_t::ReadFailed;
  }

  bytesRead = ::read(memFD, (void *)*buffer, buffer.getLength());
  if(bytesRead < 0) {
    DEBUGMSG("error reading child memory: " << strerror(errno) << std::endl);
    return ret_t::ReadFailed;
  }
  else if((size_t)bytesRead < buffer.getLength())
    return ret_t::TruncatedAccess;
  else return ret_t::Success;
}

ret_t Process::write(uintptr_t addr, uint64_t data) const {
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::setMem(pid, addr, data)) {
    DEBUGMSG("ptrace write failed at address 0x" << std::hex << addr << ": "
             << strerror(errno) << std::endl);
    return ret_t::PtraceFailed;
  }
  return ret_t::Success;
}

ret_t Process::writeRegion(uintptr_t addr, const byte_iterator &buffer) const {
  ssize_t bytesWritten;

  if(!traceable()) return ret_t::InvalidState;

  if(lseek(memFD, addr, SEEK_SET) == -1) {
    DEBUGMSG("could not seek to address 0x" << std::hex << addr << ": "
             << strerror(errno) << std::endl);
    return ret_t::WriteFailed;
  }

  bytesWritten = ::write(memFD, (void *)*buffer, buffer.getLength());
  if(bytesWritten < 0) {
    DEBUGMSG("error writing child memory: " << strerror(errno) << std::endl);
    return ret_t::WriteFailed;
  }
  else if((size_t)bytesWritten < buffer.getLength())
    return ret_t::TruncatedAccess;
  else return ret_t::Success;
}

ret_t Process::getSyscallNumber(long &data) const {
  struct user_regs_struct regs;
  if(!traceable()) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  data = arch::syscallNumber(regs);
  return ret_t::Success;
}

void Process::dumpRegs(std::ostream &os) const {
  struct user_regs_struct regs;
  struct user_fpregs_struct fpregs;
  if(!traceable()) {
    WARN("cannot dump registers - invalid state" << std::endl);
    return;
  }
  if(trace::getRegs(pid, regs)) arch::dumpRegs(os, regs);
  if(trace::getFPRegs(pid, fpregs)) arch::dumpFPRegs(os, fpregs);
}

ret_t Process::stealUserfaultfd() {
  ret_t retcode;

  if(!traceable()) return ret_t::InvalidState;

  DEBUGMSG(pid << ": stealing userfault from child" << std::endl);

  retcode = parasite::infect(parasite, nthreads);
  if(retcode != ret_t::Success) return retcode;
  if((uffd = parasite::stealUFFD(parasite)) == -1)
    return ret_t::CompelActionFailed;
  if((retcode = cureAndInitParasite()) != ret_t::Success) return retcode;
  return ret_t::Success;
}

