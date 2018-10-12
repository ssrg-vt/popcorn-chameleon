#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "log.h"
#include "process.h"
#include "ptrace.h"

using namespace chameleon;

/**
 * Called by forked children to set up introspection machinery and execute the
 * requested application.  The process doesn't return from here.
 * @param bin the binary to execute
 * @param argv the arguments to pass to the new application
 */
[[noreturn]] static void execChild(const char *bin, char **argv) {
  if(!PTrace::traceme()) {
    perror("Could not enable ptrace in child");
    abort();
  }

  execv(bin, argv);
  perror("Could not exec application");
  abort();
}

ret_t Process::forkAndExec() {
  pid_t result;

  // Don't let the user fork another child if we've already got one
  if(status != Ready) return ret_t::Exists;

  result = fork();
  if(result == 0) execChild(bin, argv);
  else if(result < 0) return ret_t::ForkFailed;

  DEBUGMSG("forked child " << result << std::endl);

  // Wait for child to execv() & set up tracing infrastructure
  pid = result;
  status = Running;
  if(wait_internal(false) != ret_t::Success ||
     status != Stopped ||
     !PTrace::killChildOnExit(pid))
    return ret_t::SetupFailed;

  DEBUGMSG("set up child for tracing" << std::endl);

  return ret_t::Success;
}

/*
 * If we're waiting for a signal to be delivered that we sent (either directly
 * or indirectly) then we know we don't need to forward it to the child.  In
 * the general case though, when we restart the child we want to forward the
 * signal we intercepted.
 */
ret_t Process::wait_internal(bool reinject) {
  int wstatus;
  ret_t retval = ret_t::Success;

  // Return immediately if the process is already stopped/exited
  if(status != Running) return ret_t::Success;

  // Wait for the child and update the status based on returned values
  if(waitpid(pid, &wstatus, 0) == -1) {
    status = Unknown;
    retval = ret_t::WaitFailed;
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
      reinjectSignal = reinject;
    }
    else {
      status = Unknown;
      retval = ret_t::WaitFailed;
    }
  }

  return retval;
}

ret_t Process::wait() {
  return wait_internal(true);
}

ret_t Process::resume() {
  bool success;

  switch(status) {
  // Return immediately if the process is already running
  case Running: return ret_t::Success;

  // We can't resume a process that's dead...
  case Exited:
  case SignalExit: return ret_t::DoesNotExist;

  default:
    if(reinjectSignal) success = PTrace::resume(pid, signal);
    else success = PTrace::resume(pid, 0);
    if(success) {
      status = Running;
      return ret_t::Success;
    }
    else return ret_t::PtraceFailed;
  }
}

ret_t Process::continueToNextEvent() {
  ret_t retcode = resume();
  if(retcode != ret_t::Success) return retcode;
  return wait_internal(true);
}

void Process::detach() {
  PTrace::detach(pid);
  pid = -1;
  status = Ready;
  exit = 0;
  reinjectSignal = false;
}

int Process::getExitCode() const {
  if(status == Exited) return exit;
  else return INT32_MAX;
}

int Process::getSignal() const {
  if(status == SignalExit || status == Stopped) return signal;
  else return INT32_MAX;
}

