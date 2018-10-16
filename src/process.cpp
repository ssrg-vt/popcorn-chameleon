#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "log.h"
#include "process.h"
#include "ptrace.h"

using namespace chameleon;

#define SOCK_PATH "/tmp/chameleon-%d"

/**
 * Send a file descriptor to another process.
 * @param fd the file descriptor to send
 * @param desc descriptor identifying the connection (i.e., parent PID)
 * @return true if successfully sent or false othewise
 */
static bool sendFileDescriptor(int fd, int desc) {
  bool success = false;
  int sfd;
  struct sockaddr_un addr;
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char buf[CMSG_SPACE(sizeof(int))], dup[256];
  struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

  // Note: use the close-on-exec flag to make the kernel clean up after us
  if((sfd = socket(AF_UNIX, SOCK_STREAM | O_CLOEXEC, 0)) == -1)
    return false;

  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH, desc);
  if(connect(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1)
    goto finish;

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
  if(sendmsg(sfd, &msg, 0) >= 0) success = true;
finish:
  close(sfd);
  return success;
}

/**
 * Initialize the server side of a UNIX domain socket connection.
 * @param desc descriptor identifying the connection (i.e., parent PID)
 * @return socket file descriptor if successful or -1 otherwise
 */
static int initServerSocket(int desc) {
  int sfd;
  struct sockaddr_un addr;

  if((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) return -1;
  memset(&addr, 0, sizeof(struct sockaddr_un));
  addr.sun_family = AF_UNIX;
  snprintf(addr.sun_path, sizeof(addr.sun_path), SOCK_PATH, desc);
  if(bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un)) == -1 ||
     listen(sfd, 1) == -1) {
    close(sfd);
    sfd = -1;
  }
  return sfd;
}

/**
 * Receive a file descriptor from another process.
 * @param sfd a UNIX domain socket bound as the server
 * @return received file descriptor if successful or -1 otherwise
 */
static int receiveFileDescriptor(int sfd) {
  int cfd, fd = -1;
  struct sockaddr_un addr;
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  char buf[CMSG_SPACE(sizeof(int))], dup[256];
  struct iovec io = { .iov_base = &dup, .iov_len = sizeof(dup) };

  if((cfd = accept(sfd, nullptr, nullptr)) == -1) goto close_server;

  memset(buf, 0, sizeof(buf));
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  if(recvmsg(cfd, &msg, 0) == -1) goto close_client;

  cmsg = CMSG_FIRSTHDR(&msg);
  memcpy(&fd, (int *)CMSG_DATA(cmsg), sizeof(int));
close_client:
  close(cfd);
close_server:
  close(sfd);
  return fd;
}

/**
 * Called by forked children to set up introspection machinery and execute the
 * requested application.  The process doesn't return from here.
 * @param bin the binary to execute
 * @param argv the arguments to pass to the new application
 */
[[noreturn]] static void
execChild(const char *bin, char **argv, pid_t parent) {
  int uffd;

  // Prepare for ptrace on the child (tracee) side
  if(!PTrace::traceme()) {
    perror("Could not enable ptrace in child");
    abort();
  }

  // Open the userfaultfd file descriptor and pass it to the parent.  Set the
  // close-on-exec flag so we don't need to close it ourselves.
  if((uffd = syscall(__NR_userfaultfd, O_CLOEXEC)) == -1) {
    perror("Could not create userfaultfd descriptor in child");
    abort();
  }

  if(!sendFileDescriptor(uffd, parent)) {
    perror("Could not send userfaultfd file descriptor to parent");
    abort();
  }

  execv(bin, argv);
  perror("Could not exec application");
  abort();
}

ret_t Process::forkAndExec() {
  int server;
  pid_t child, parent = getpid();

  // Don't let the user fork another child if we've already got one
  if(status != Ready) return ret_t::Exists;

  // We need the child to create a userfaultfd descriptor and pass it to us
  // through UNIX domain stockets.  Establish the server side before forking
  // the child to avoid racing connection attempts against server setup.
  if((server = initServerSocket(parent)) == -1)
    return ret_t::RecvUFFDFailed;

  child = fork();
  if(child == 0) execChild(argv[0], argv, parent);
  else if(child < 0) return ret_t::ForkFailed;
  pid = child;
  status = Running;

  DEBUGMSG("forked child " << pid << std::endl);

  // Receive userfaultfd descriptor from child
  if((uffd = receiveFileDescriptor(server)) == -1)
    return ret_t::RecvUFFDFailed;

  DEBUGMSG("received userfaultfd (fd=" << uffd << ") from child" << std::endl);

  // Wait for child to execv() & set up tracing infrastructure
  if(wait_internal(false) != ret_t::Success ||
     status != Stopped ||
     !PTrace::killChildOnExit(pid))
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
  close(uffd);
  PTrace::detach(pid);
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

