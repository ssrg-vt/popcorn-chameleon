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
#include "process.h"
#include "trace.h"

using namespace chameleon;

/**
 * Send a file descriptor to another process.
 * @param fd the file descriptor to send
 * @param socket a UNIX domain socket connected to the parent
 * @return true if successfully sent or false othewise
 */
static bool sendFileDescriptor(int fd, int socket) {
  bool success = false;
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char buf[CMSG_SPACE(sizeof(int))], dup[256];
  struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

  memset(buf, 0, sizeof(buf));
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy((int *)CMSG_DATA(cmsg), &fd, sizeof(int));
  if(sendmsg(socket, &msg, 0) >= 0) success = true;
  close(socket);
  return success;
}

/**
 * Receive a file descriptor from another process.
 * @param socket a UNIX domain socket connected to the child
 * @return received file descriptor if successful or -1 otherwise
 */
static int receiveFileDescriptor(int socket) {
  int fd = -1;
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char buf[CMSG_SPACE(sizeof(int))], dup[256];
  struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

  memset(buf, 0, sizeof(buf));
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  if(recvmsg(socket, &msg, 0) >= 0) {
    cmsg = CMSG_FIRSTHDR(&msg);
    memcpy(&fd, (int *)CMSG_DATA(cmsg), sizeof(int));
  }
  close(socket);
  return fd;
}

/**
 * Called by forked children to set up introspection machinery and execute the
 * requested application.  The process doesn't return from here.
 * @param argv the arguments to pass to the new application
 * @param socket a UNIX domain socket connected to the parent
 */
[[noreturn]] static void
execChild(char **argv, int socket) {
  int uffd;

  // Prepare for ptrace on the child (tracee) side
  if(!trace::traceme()) {
    perror("Could not enable ptrace in child");
    close(socket);
    abort();
  }

  // TODO Note: the kernel is modified to update the userfaultfd's context with
  // the task's post execve() mm_struct so the descriptor is valid after
  // starting the new application.  We should instead use CRIU's compel library
  // to instead inject code into the target which establishes the userfaultfd &
  // sends it to the parent before starting the application

  // Open the userfaultfd file descriptor and pass it to the parent.  Set the
  // close-on-exec flag so we don't need to close it ourselves.
  if((uffd = syscall(SYS_userfaultfd, O_CLOEXEC)) == -1) {
    perror("Could not create userfaultfd descriptor in child");
    close(socket);
    abort();
  }

  if(!sendFileDescriptor(uffd, socket)) {
    perror("Could not send userfaultfd file descriptor to parent");
    abort();
  }

  execv(argv[0], argv);
  perror("Could not exec application");
  abort();
}

ret_t Process::forkAndExec() {
  int sockets[2];
  pid_t child;

  // Don't let the user fork another child if we've already got one
  if(status != Ready) return ret_t::Exists;

  // Establish a pair of connected sockets for passing the userfaultfd file
  // descriptor from the child to the parent
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == -1)
    return ret_t::RecvUFFDFailed;

  child = fork();
  if(child == 0) execChild(argv, sockets[1]);
  else if(child < 0) {
    close(sockets[0]);
    close(sockets[1]);
    return ret_t::ForkFailed;
  }
  pid = child;
  status = Running;

  DEBUGMSG("forked child " << pid << std::endl);

  // Receive userfaultfd descriptor from child
  if((uffd = receiveFileDescriptor(sockets[0])) == -1)
    return ret_t::RecvUFFDFailed;

  DEBUGMSG("received userfaultfd (fd=" << uffd << ") from child" << std::endl);

  // Wait for child to execv() & set up tracing infrastructure.  The kernel
  // will stop the child with SIGTRAP before execution begins.
  if(wait_internal(false) != ret_t::Success ||
     status != Stopped ||
     !trace::killChildOnExit(pid))
    return ret_t::TraceSetupFailed;

  DEBUGMSG("set up child for tracing" << std::endl);

  return ret_t::Success;
}

ret_t Process::wait_internal(bool reinject) {
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

ret_t Process::wait() { return wait_internal(true); }

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
  return wait_internal(true);
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

int Process::getExitCode() const {
  if(status == Exited) return exit;
  else return INT32_MAX;
}

int Process::getSignal() const {
  if(status == SignalExit || status == Stopped) return signal;
  else return INT32_MAX;
}

// TODO the functions that only access a single register (i.e., get/setPC(),
// getSyscallReturnValue()) should be converted to use PTRACE_PEEKUSER rather
// than bulk reading/writing the entire register set

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

ret_t Process::setSyscallRegs(long syscall, long a1, long a2, long a3,
                              long a4, long a5, long a6) const {
  struct user_regs_struct regs;
  if(status != Stopped) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  arch::marshalSyscall(regs, syscall, a1, a2, a3, a4, a5, a6);
  if(!trace::setRegs(pid, regs)) return ret_t::PtraceFailed;
  return ret_t::Success;
}

ret_t Process::getSyscallReturnValue(long &retval) const {
  struct user_regs_struct regs;
  if(!stoppedAtSyscall()) return ret_t::InvalidState;
  if(!trace::getRegs(pid, regs)) return ret_t::PtraceFailed;
  retval = arch::syscallRetval(regs);
  if((unsigned long)retval > -4096UL) retval = -retval;
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
  if(trace::getRegs(pid, regs)) arch::dumpRegs(regs);
}

