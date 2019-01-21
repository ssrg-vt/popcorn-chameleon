#include <iostream>
#include <list>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "process.h"
#include "transform.h"
#include "types.h"

using namespace std;
using namespace chameleon;

pid_t masterPID;
static int childArgc;
static char **childArgv;
static bool randomize = true;
#ifndef NDEBUG
bool verboseDebug = false;
#endif

// Some helpful typedefs to safely wrap pointers & make ADTs bearable
typedef unique_ptr<Binary> BinaryPtr;
typedef std::pair<Process, pthread_t> ChildHandler;

// The application's binary file on disk
static BinaryPtr binary;

// Note: chameleon will fork the main application and maintain its information
// in the main thread.  This list holds information for additional children
// forked during the application's (or its children's) execution.
static list<ChildHandler> children; /* running children/handlers */
static list<pthread_t> toJoin; /* children that have exited & need joining */
static pthread_mutex_t childLock = PTHREAD_MUTEX_INITIALIZER,
                       joinLock = PTHREAD_MUTEX_INITIALIZER;

// Declare event & child handling APIs to satisfy compiler
static ret_t addChild(pid_t pid);
static ret_t cleanupChild(pid_t pid);
static Process::status_t handleEvent(Process &child);
static void *forkedChildLoop(void *proc);

static bool checkCompatibility() {
  // TODO other checks?
  if(sysconf(_SC_PAGESIZE) != PAGESZ) return false;
  return true;
}

static void printHelp(const char *bin) {
  cout << bin << " - run an application under the Popcorn Chameleon framework"
              << endl << endl
       << "Usage: " << bin << " [ OPTIONS ] -- <application> [ APP ARGS ]"
                    << endl << endl
       << bin << "'s arguments must precede '--', after which the user should "
                 "specify a binary and any arguments" << endl << endl
       << "Options:" << endl
       << "  -h : print help and exit" << endl
       << "  -n : don't randomize the code section" << endl
#ifndef NDEBUG
       << "  -d : print even more debugging information than normal" << endl
#endif
       << "  -v : print Popcorn Chameleon version and exit" << endl;
}

static void printChameleonInfo() {
  INFO("Popcorn Chameleon, version " << VERSION_MAJOR << "."
       << VERSION_MINOR << endl);
}

static void parseArgs(int argc, char **argv) {
  int c, i;
  bool foundDelim = false;

  // Find the double-dash delimiter & update arguments accordingly.  Note that
  // if we don't find the delimiter we don't exit immediately; the user could
  // be asking for the help text.  Instead, wait until after argument parsing.
  for(i = 0; i < argc; i++) {
    if(strncmp(argv[i], "--", 2) == 0) {
      foundDelim = true;
      break;
    }
  }

  childArgc = argc - i - 1;
  childArgv = &argv[i+1];
  argc = i;
  argv[i] = nullptr;

  // Parse arguments up until the delimiter
  while((c = getopt(argc, argv, "hndv")) != -1) {
    switch(c) {
    default: break;
    case 'h': printHelp(argv[0]); exit(0); break;
    case 'n': randomize = false; break;
#ifndef NDEBUG
    case 'd': verboseDebug = true; break;
#endif
    case 'v': printChameleonInfo(); exit(0); break;
    }
  }

  if(!foundDelim || childArgc <= 0) {
    printHelp(argv[0]);
    ERROR("did not specify a binary" << endl);
  }

  DEBUG(
    DEBUGMSG("child arguments:");
    for(i = 0; i < childArgc; i++)
      DEBUGMSG_RAW(" " << childArgv[i]);
    DEBUGMSG_RAW(endl);
  )
}

static ret_t addChild(pid_t pid) {
  ret_t code = ret_t::Success;

  if(pthread_mutex_lock(&childLock)) return ret_t::LockFailed;

  children.emplace_back(Process(pid), pthread_t());
  ChildHandler &child = children.back();
  if((code = child.first.initForkedChild()) != ret_t::Success) return code;
  if((code = child.first.detachHandoff()) != ret_t::Success) return code;
  if(pthread_create(&child.second, nullptr, forkedChildLoop, &child.first))
    return ret_t::ChildHandlerSetupFailed;

  if(pthread_mutex_unlock(&childLock)) return ret_t::LockFailed;

  return code;
}

static ret_t cleanupChild(pid_t pid) {
  ret_t code = ret_t::Success;
  list<ChildHandler>::iterator it;

  if(pthread_mutex_lock(&childLock)) return ret_t::LockFailed;

  // Find the entry containing the Process object & handler, add the handler to
  // be joined and remove the child entry
  for(it = children.begin(); it != children.end(); it++) {
    if(it->first.getPid() == pid) {
      if(pthread_mutex_lock(&joinLock)) {
        code = ret_t::LockFailed;
        break;
      }
      toJoin.emplace_back(it->second);
      children.erase(it);
      if(pthread_mutex_unlock(&joinLock)) code = ret_t::LockFailed;
      break;
    }
  }

  if(it == children.end()) code = ret_t::ChildHandlerCleanupFailed;
  if(pthread_mutex_unlock(&childLock)) code = ret_t::LockFailed;

  return code;
}

static ret_t joinHandlers() {
  list<pthread_t>::iterator it;
  ret_t code = ret_t::Success;
  static bool joining = false;

  // forkedChildLoop() returns a ret_t disguised as a void *.  Trick the
  // compiler into letting us interpret the return value as a ret_t.
  union {
    void *raw;
    unsigned long rawInt;
  } tmp;

  // Check if somebody else is already joining children.  It's okay if this
  // is stale, we'd rather not block handlers that have better things to do.
  if(joining) return ret_t::Success;

  if(pthread_mutex_lock(&joinLock)) return ret_t::LockFailed;
  joining = true;

  for(it = toJoin.begin(); it != toJoin.end(); ++it) {
    if(pthread_join(*it, &tmp.raw)) {
      code = ret_t::ChildHandlerCleanupFailed;
      break;
    }
    code = (ret_t)tmp.rawInt;

    if(code != ret_t::Success) {
      WARN("handler exited with error: " << retText(code) << endl);
      code = ret_t::Success;
    }
  }
  toJoin.clear();

  joining = false;
  if(pthread_mutex_unlock(&joinLock)) return ret_t::LockFailed;

  return code;
}

static Process::status_t handleEvent(Process &child) {
  pid_t pid = child.getPid();
  ret_t code = child.continueToNextEvent(false);
  if(code != ret_t::Success)
    ERROR(pid << ": could not continue to next event: " << retText(code)
          << endl);

  // We're a big happy family, distribute cleanup work between handlers (any
  // thread is joinable by any other thread).  If we fail, try to limp along...
  code = joinHandlers();
  if(code != ret_t::Success)
    WARN(pid << ": could not join handler: " << retText(code) << endl);

  switch(child.getStatus()) {
  default: INFO(pid << ": unknown status"); return Process::Unknown;
  case Process::Stopped:
    DEBUGMSG(pid << ": stopped with signal " << child.getSignal() << " @ 0x"
             << hex << child.getPC() << endl);

    switch(child.getStopReason()) {
    default: code = ret_t::Success; break;
    case stop_t::Exec:
      ERROR(pid << ": could not handle execve(): "
            << retText(ret_t::NotImplemented) << endl);
      break;
    case stop_t::Clone:
      INFO(pid << ": cloned thread " << child.getNewTaskPid() << endl);
      code = child.traceThread(child.getNewTaskPid());
      break;
    case stop_t::Fork:
      INFO(pid << ": forked process " << child.getNewTaskPid() << endl);
      code = addChild(child.getNewTaskPid());
      break;
    }

    if(code != ret_t::Success) {
      DEBUG(DEBUGMSG(pid << ": problem handling stop event" << endl);
            child.dumpRegs());
      ERROR(pid << ": handling stop event failed: " << retText(code) << endl);
    }

    return Process::Stopped;
  case Process::Exited:
    INFO(pid << ": exited with code " << child.getExitCode() << endl);
    return Process::Exited;
  case Process::SignalExit:
    // TODO dump the instruction at which the child exited
    INFO(pid << ": terminated with signal " << child.getSignal() << endl);
    return Process::SignalExit;
  }
}

static void *forkedChildLoop(void *proc) {
  Process *child = (Process *)proc;
  pid_t cpid = child->getPid();
  Process::status_t status;
  ret_t code = ret_t::Success;

  // Become the child's tracer
  if((code = child->attachHandoff()) != ret_t::Success) return (void *)code;

  // TODO need a CodeTransformer when randomizing the child

  INFO("Beginning forked child " << cpid << endl);

  do {
    status = handleEvent(*child);
  } while(status != Process::Exited && status != Process::SignalExit);

  // Note: cleanupChild() removes the process &handler from the children list,
  // which destroys the Process object pointed to by child.  The child pointer
  // is no longer valid - do not use!
  INFO("Cleaning up forked child " << cpid << endl);
  child->detach(); // TODO CodeTransformer will call this internally
  proc = child = nullptr;
  cleanupChild(cpid);

  return (void *)code;
}

int main(int argc, char **argv) {
  ret_t code;
  Process::status_t status;
  Timer t;

  if(!checkCompatibility()) ERROR("incompatible system" << endl);
  masterPID = getpid();
  parseArgs(argc, argv);

  DEBUG(printChameleonInfo())
  INFO("Starting '" << childArgv[0] << "'" << endl);
  t.start();

  // Initialize libelf and load the binary (including all metadata)
  code = Binary::initLibELF();
  if(code != ret_t::Success)
    ERROR("could not initialize libelf: " << retText(code) << endl);
  binary.reset(new Binary(childArgv[0]));
  code = binary->initialize();
  if(code != ret_t::Success)
    ERROR("could not initialize binary: " << retText(code) << endl);

  // Initialize the main child process
  Process child(childArgc, childArgv);
  code = child.forkAndExec();
  if(code != ret_t::Success)
    ERROR("could not set up child for tracing: " << retText(code) << endl);

  // Set up the state transfomer
  CodeTransformer transformer(child, *binary);
  code = transformer.initialize(randomize);
  if(code != ret_t::Success)
    ERROR("could not set up state transformer: " << retText(code) << endl);

  t.end();
  INFO("Application startup time: " << t.elapsed(Timer::Micro) << " us"
       << endl << "Beginning main child " << child.getPid() << endl);

  do {
    status = handleEvent(child);
  } while(status != Process::Exited && status != Process::SignalExit);

  // TODO if forked children don't exit (and our handlers are blocked waiting),
  // then we're force-killing them by exiting.  Need to gracefully clean up.

  INFO("Cleaning up child " << child.getPid() << endl);

  return 0;
}

