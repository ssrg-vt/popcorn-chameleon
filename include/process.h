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

#include <sys/types.h>
#include "types.h"

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
                                   reinjectSignal(false), uffd(-1) {}
  Process() = delete;

  /**
   * Fork a child process to execute the application and set up ptrace.  The
   * call will wait for the forked tracee's initialization and application
   * execution.  After the tracee receives SIGSTOP (before executing any
   * application code) the tracer will initialize and return with the tracee in
   * the stopped state.  The function returns an error code indicating whether
   * the child was able to be set up and launched successfully.
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
   * child through the APIs exposed by Process; doing so will interfere with
   * child signal delivery.
   *
   * @return a return code describing the outcome
   */
  ret_t wait();

  /**
   * Resume a child.
   * @return a return code describing the outcome
   */
  ret_t resume();

  /**
   * Continue child execution until the next event.  Equivalent to calling
   * resume() followed by wait().
   * @return a return code describing the outcome
   */
  ret_t continueToNextEvent();

  /**
   * Detach from a child and clean up internal state; the process object can be
   * re-used with the same arguments if needed.  If the child process is still
   * running, it will continue untraced.  This *always* succeeds from the the
   * tracer's viewpoint.
   */
  void detach();

  /**
   * Field getters - return what you ask for.
   */
  int getArgc() const { return argc; }
  char **getArgv() const { return argv; }
  int getPid() const { return pid; }
  status_t getStatus() const { return status; }
  int getUserfaultfd() const { return uffd; }

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
  ret_t wait_internal(bool reinject);
};

}

#endif /* _PROCESS_H */

