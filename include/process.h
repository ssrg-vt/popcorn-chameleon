/**
 * class Process
 *
 * Implements ability to fork and attach to new processes, introspect and
 * manipulate child processes and clean up when they have finished.  A Process
 * object should only ever have 1 forked child under its control, although it
 * may control multiple threads within that process.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _PROCESS_H
#define _PROCESS_H

#include <sys/signal.h>
#include <sys/types.h>
#include "types.h"

struct parasite_ctl;

namespace chameleon {

class Process {
public:
  enum status_t {
    Ready = 0,  /* child is ready to be run */
    Running,    /* child is running */
    Exited,     /* child exited */
    SignalExit, /* child terminated due to signal */
    Stopped,    /* child is stopped */
    Unknown     /* child has some other status */
  };

  /**
   * Construct a process object.  Initialize the process' command-line but
   * nothing else; users must call forkAndExec() to start the process.
   *
   * Note: argv[0] *must* be the binary to execute
   *
   * @param argc number of arguments
   * @param argv arguments for child process to be executed
   */
  Process(int argc, char **argv) : argc(argc), argv(argv), pid(-1),
                                   status(Ready), exit(0),
                                   reinjectSignal(false), uffd(-1),
                                   nthreads(0) {}
  Process() = delete;

  /////////////////////////////////////////////////////////////////////////////
  // Execution control
  /////////////////////////////////////////////////////////////////////////////

  /**
   * Fork a child process to execute the application and set up ptrace.  The
   * call will wait for the forked tracee's initialization and application
   * execution.  After the tracee receives SIGSTOP (before executing any
   * application code) the tracer will initialize and return with the tracee in
   * the stopped state.  Initialization includes creating a userfaultfd file
   * descriptor in the child and passing it to the parent for handling page
   * faults.  The function returns an error code indicating whether the child
   * was able to be set up and launched successfully.
   *
   * Note: the call returns with the child process in the stopped state.  Users
   * should call resume() or continueToNextEvent() to start the child process.
   *
   * @return a return code describing the outcome
   */
  ret_t forkAndExec();

  /**
   * Wait for a child event and update the process' status, which can be
   * queried via getStatus() after returning.
   *
   * Note: users should *not* attempt to interrupt child processes using libc
   * calls (i.e., kill()) on their own, but should *only* interact with the
   * child through the APIs exposed by Process; circumventing Process' APIs
   * will interfere with child signal delivery.
   *
   * @return a return code describing the outcome
   */
  ret_t wait();

  /**
   * Resume a child.  If syscall = false, tell ptrace to stop at the next
   * signal delivery to the child.  If syscall = true, tell ptrace to stop at
   * either the next signal delivery or system call boundary (either going into
   * or coming out of kernel) by the child.
   *
   * @param syscall whether or not to trace syscalls
   * @return a return code describing the outcome
   */
  ret_t resume(bool syscall);

  /**
   * Continue child execution until the next event.  If syscall = false,
   * continue until the next signal delivery to the child.  If syscall = true,
   * continue until either the next signal delivery or system call boundary
   * (either going into or coming out of kernel) by the child.  Equivalent to
   * calling resume() followed by wait().
   *
   * @param syscall whether or not to trace syscalls
   * @return a return code describing the outcome
   */
  ret_t continueToNextEvent(bool syscall);

  /**
   * Detach from a child and clean up internal state; the process object can be
   * re-used with the same arguments if needed.  If the child process is still
   * running, it will continue untraced.  This *always* succeeds from the the
   * tracer's viewpoint.
   */
  void detach();

  /**
   * Initialize the userfaultfd in the context of the child and send it to
   * Chameleon.  After calling, users can query the file descriptor using
   * getUserfaultfd().  Uses a previously initialized parasite_ctl, but
   * performs the infection/curing internally.
   *
   * @param ctx a previously-initialized libcompel parasite_ctl context
   * @return a return code describing the outcome
   */
  ret_t stealUserfaultfd(struct parasite_ctl *ctx);

  /////////////////////////////////////////////////////////////////////////////
  // Inspect & modify process state
  /////////////////////////////////////////////////////////////////////////////

  /**
   * Process information - return what you ask for.
   */
  int getArgc() const { return argc; }
  char **getArgv() const { return argv; }
  int getPid() const { return pid; }
  status_t getStatus() const { return status; }
  int getUserfaultfd() const { return uffd; }
  size_t getNumThreads() const { return nthreads; }

  /* Note: the following APIs may only be called when the process is stopped */

  /**
   * Get the exit code after the child exits normally.
   * @return exit code if status == Exited, INT32_MAX otherwise
   */
  int getExitCode() const;

  /**
   * Get the signal that caused the child to stop or terminate.
   * @return signal number if status == SignalExit/Stopped, INT32_MAX otherwise
   */
  int getSignal() const;

  /**
   * Return whether the child stopped at a system call boundary or not.
   * @return true if the process is stopped at a system call boundary or false
   *         if stopped for another reason (or is not stopped)
   */
  bool stoppedAtSyscall() const { return getSignal() == SIGTRAP; }

  /**
   * Get the process' current program counter.
   * @return the program counter or 0 if it could not be retrieved
   */
  uintptr_t getPC() const;

  /**
   * Set the process' current program counter.
   * @return a return code describing the outcome
   */
  ret_t setPC(uintptr_t newPC) const;

  /**
   * Marshal a set of arguments into registers to invoke a function call
   * according to the ISA-specific calling convention.
   * @param a1-6 arguments to the system call
   * @return a return code describing the outcome
   */
  ret_t setFuncCallRegs(long a1 = 0, long a2 = 0, long a3 = 0,
                        long a4 = 0, long a5 = 0, long a6 = 0) const;

  /**
   * Read 8 bytes of data from a virtual memory address.
   * @param addr the address to read
   * @param data output argument to which bytes will be written
   * @return a return code describing the outcome
   */
  ret_t read(uintptr_t addr, uint64_t &data) const;

  /**
   * Write 8 bytes of data to a virtual memory address.
   * @param addr the address to write
   * @param data bytes to write to the address
   * @return a return code describing the outcome
   */
  ret_t write(uintptr_t addr, uint64_t data) const;

  /**
   * Dump register contents to an output stream.
   */
  void dumpRegs() const;

private:
  /* Arguments */
  int argc;
  char **argv;

  /* Process information */
  pid_t pid;
  status_t status;
  union {
    int exit;   /* exit code if status == Exited */
    int signal; /* exit/stop signal if status == SignalExit or Stopped */
  };
  bool reinjectSignal; /* whether to re-inject signal into tracee */
  int uffd; /* userfaultfd file descriptor */
  size_t nthreads; /* number of threads in the process */

  /**
   * Internal wait implementation used to save relevant information depending
   * on whether we need to forward a signal to the child.  If we're waiting for
   * a signal to be delivered that we sent (either directly or indirectly) then
   * we know we don't need to forward it to the child.  In the general case
   * though, when we restart the child we want to forward the signal we
   * intercepted.
   *
   * @param reinject whether or not to reinject a signal
   * @return a return code describing the outcome
   */
  ret_t waitInternal(bool reinject);
};

}

#endif /* _PROCESS_H */

