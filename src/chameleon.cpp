#include <list>
#include <memory>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "alarm.h"
#include "config.h"
#include "log.h"
#include "process.h"
#include "transform.h"
#include "types.h"

#ifdef DEBUG_BUILD
#include <fstream>
#endif

using namespace std;
using namespace chameleon;

pid_t masterPID;
static int childArgc;
static char **childArgv;
static bool randomize = true;
static uint64_t randomizePeriod = 0; /* in milliseconds */
#ifdef DEBUG_BUILD
pthread_mutex_t logLock = PTHREAD_MUTEX_INITIALIZER;
static const char *traceFilename = nullptr;
static ofstream traceFile;
bool verboseDebug = false;
static size_t alarmsRung = 0;
#endif

// Some helpful typedefs to safely wrap pointers & make ADTs bearable
typedef unique_ptr<Binary> BinaryPtr;
typedef std::pair<Process, pthread_t> ChildHandler;

// The application's binary file on disk
static BinaryPtr binary;

// Note: chameleon will fork the main application and maintain its information
// in the main thread.  This list holds information for additional children
// forked during the application's (or its children's) execution.
static int numChildren = 0;
static list<ChildHandler> children; /* running children/handlers */
static list<pthread_t> toJoin; /* children that have exited & need joining */
static pthread_mutex_t childLock = PTHREAD_MUTEX_INITIALIZER,
                       joinLock = PTHREAD_MUTEX_INITIALIZER;

// Declare event & child handling APIs to satisfy compiler
static void alarmCallback(void *data);
static ret_t addChild(pid_t pid);
static ret_t cleanupChild(const Process *proc);
static Process::status_t handleEvent(CodeTransformer &CT);
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
       << "  -h      : print help and exit" << endl
       << "  -p MS   : re-randomization period in milliseconds" << endl
       << "  -n      : don't randomize the code section" << endl
#ifdef DEBUG_BUILD
       << "  -t FILE : trace execution by dumping PC values to FILE (warning: slow!)" << endl
       << "  -d      : print even more debugging information than normal" << endl
#endif
       << "  -v      : print Popcorn Chameleon version and exit" << endl;
}

static void printChameleonInfo() {
  INFO("Popcorn Chameleon, version " << VERSION_MAJOR << "."
       << VERSION_MINOR << endl);
  // TODO print setup
}

static void parseArgs(int argc, char **argv) {
  int c, i;
  bool foundDelim = false;
  char *end;

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
  while((c = getopt(argc, argv, "hp:nt:dv")) != -1) {
    switch(c) {
    default: break;
    case 'h': printHelp(argv[0]); exit(0); break;
    case 'p':
      randomizePeriod = strtoul(optarg, &end, 10);
      if(end == optarg)
        ERROR("invalid randomization period '" << optarg << "'" << endl);
      break;
    case 'n': randomize = false; break;
#ifdef DEBUG_BUILD
    case 't': traceFilename = optarg; break;
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

static void alarmCallback(void *data) {
  list<ChildHandler>::iterator it;

  // TODO 1: currently assume that adding/cleaning up children is a rare event
  // and if somebody is calling either addChild() or cleanupChild(), just skip
  // this alarm
  // TODO 2: proper error propagation instead of ERROR when any of the below
  // actions fail
  int ret = pthread_mutex_trylock(&childLock);
  if(ret) {
    if(ret == EBUSY) return; // Somebody else has the lock
    else ERROR("could not try to acquire child lock" << endl);
  }

  // Kick off an action; send a signal to handler threads that are blocked in
  // waitpid(), which will perform an action on the child inside handleEvent().
  // Handlers currently performing other work will skip this alarm.  There's no
  // race condition between the signaled thread finishing this alarm's action
  // and the next alarm signal, as signals received when not blocking in
  // waitpid() are a no-op.
  if(kill(masterPID, SIGINT))
    ERROR("could not interrupt handler for main process" << endl);
  for(it = children.begin(); it != children.end(); it++)
    if(pthread_kill(it->second, SIGINT))
      ERROR("could not interrupt handler for child process "
            << it->first.getPid() << endl);

  DEBUG(alarmsRung++);
  if(pthread_mutex_unlock(&childLock)) ERROR("could not unlock mutex" << endl);
}

static ret_t setupSignalsAndAlarm(Alarm &alarm) {
  struct sigaction handler;
  auto intHandler = [](int signal){};
  ret_t code;

  // Note: all threads in the process will share the signal dispositions set up
  // here.  Additionally, spawned threads will inherit the signal masks set up
  // here (threads may change masks as needed).

  // Register an empty handler for SIGINT, chameleon's preferred method for
  // poking other threads.  Always required as SIGINT is used to wake up page
  // fault handling threads from blocking reads.
  memset(&handler, 0, sizeof(struct sigaction));
  handler.sa_handler = intHandler;
  if(sigaction(SIGINT, &handler, nullptr) == -1) {
    DEBUGMSG("could not initialize handler: " << strerror(errno) << endl);
    return ret_t::ChameleonSignalFailed;
  }

  // Note: initAlarmSignaling() *must* be called before spawning other threads
  // to avoid delivering alarms to incorrect threads.
  if(randomizePeriod) {
    code = Alarm::initAlarmSignaling();
    if(code != ret_t::Success) {
      DEBUGMSG("could not initialize alarm signaling" << endl);
      return code;
    }

    code = alarm.initialize(randomizePeriod, alarmCallback, nullptr);
    if(code != ret_t::Success)
      ERROR("could not initialize alarm: " << retText(code) << endl);
  }

  return ret_t::Success;
}

static ret_t addChild(pid_t pid) {
  ret_t code = ret_t::Success;

  if(pthread_mutex_lock(&childLock)) return ret_t::LockFailed;

  children.emplace_back(Process(pid), pthread_t());
  ChildHandler &child = children.back();
  if((code = child.first.initForkedChild()) != ret_t::Success) goto cleanup;
  if(pthread_create(&child.second, nullptr, forkedChildLoop, &child.first)) {
    code = ret_t::ChildHandlerSetupFailed;
    goto cleanup;
  }
  if((code = child.first.detachHandoff()) != ret_t::Success) goto cleanup;
  __atomic_add_fetch(&numChildren, 1, __ATOMIC_RELEASE);
cleanup:
  if(pthread_mutex_unlock(&childLock)) return ret_t::LockFailed;

  return code;
}

static ret_t cleanupChild(const Process *proc) {
  ret_t code = ret_t::Success;
  list<ChildHandler>::iterator it;

  if(pthread_mutex_lock(&childLock)) return ret_t::LockFailed;

  // Find the entry containing the Process object & handler, add the handler to
  // be joined and remove the child entry
  for(it = children.begin(); it != children.end(); it++) {
    if(&it->first == proc) {
      if(pthread_mutex_lock(&joinLock)) {
        code = ret_t::LockFailed;
        break;
      }

      toJoin.emplace_back(it->second);
      children.erase(it);
      if(__atomic_add_fetch(&numChildren, -1, __ATOMIC_ACQ_REL) == 0)
        syncWake(&numChildren);

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
    ret_t retVal;
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
    code = tmp.retVal;

    if(code != ret_t::Success) {
      // TODO print PID of exiting process
      WARN("handler exited with error: " << retText(code) << endl);
      code = ret_t::Success;
    }
  }
  toJoin.clear();

  joining = false;
  if(pthread_mutex_unlock(&joinLock)) return ret_t::LockFailed;

  return code;
}

static Process::status_t handleEvent(CodeTransformer &CT) {
  Process &child = CT.getProcess();
  pid_t pid = child.getPid();
  ret_t code;
  uintptr_t pc;
#ifdef DEBUG_BUILD
  long syscall;

  if(traceFilename) code = child.singleStep();
  else if(verboseDebug) code = child.continueToNextSignalOrSyscall();
  else
#endif
  code = child.continueToNextSignal();
  if(code != ret_t::Success)
    ERROR(pid << ": could not continue to next event: " << retText(code)
          << endl);

  // We're a big happy family, distribute cleanup work between handlers (any
  // thread is joinable by any other thread) because we don't want to rely only
  // on the main thread to join children as it may be waiting for a while.
  code = joinHandlers();
  if(code != ret_t::Success)
    WARN(pid << ": could not join handler: " << retText(code) << endl);

  switch(child.getStatus()) {
  default: INFO(pid << ": unknown status"); return Process::Unknown;
  case Process::Stopped:
#ifdef DEBUG_BUILD
    if(traceFilename && child.getSignal() == SIGTRAP)
      traceFile << dec << pid << " " << hex << child.getPC() << endl;
    else
#endif
    DEBUGMSG(pid << ": stopped with signal " << child.getSignal() << " @ 0x"
             << hex << child.getPC() << endl);
    DEBUG_VERBOSE(
      if(child.getSignal() == SIGTRAP &&
         child.getSyscallNumber(syscall) == ret_t::Success)
        DEBUGMSG_VERBOSE(pid << ": system call number " << syscall << endl);
    )

    switch(child.getStopReason()) {
    default:
      DEBUG_VERBOSE(if(child.getSignal() != SIGTRAP) child.dumpRegs();)
      code = ret_t::Success;
      break;
    case stop_t::Exec:
      // TODO implement creating a new Binary and remapping code section
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
    INFO(pid << ": terminated with signal " << child.getSignal() << " at 0x"
         << hex << child.getPC() << endl);
    return Process::SignalExit;
  case Process::Interrupted:
    pc = child.getPC();
    DEBUGMSG_VERBOSE(pid << ": interrupted child at 0x" << hex << pc << endl);

    if(randomize) {
      code = CT.rerandomize();
      if(code != ret_t::Success) {
        if(code == ret_t::NoTransformMetadata) {
           WARN(pid << ": skipping re-randomization, no metadata at 0x" << hex
                << pc << endl);
        }
        else ERROR(pid << ": could not re-randomize child: " << retText(code)
                   << std::endl);
      }
    }
    return Process::Stopped;
  }
}

static void *forkedChildLoop(void *proc) {
  Process *child = (Process *)proc;
  pid_t cpid = child->getPid();
  Process::status_t status;
  ret_t code = ret_t::Success;

  // Note: cleanupChild() removes the process &handler from the children list,
  // which destroys the Process object pointed to by child.  After the call,
  // child is no longer valid - do not use!

  // Become the child's tracer
  if((code = child->attachHandoff()) != ret_t::Success) {
    DEBUGMSG(cpid << ": could not attach from handoff" << endl);
    child->detach();
    cleanupChild(child);
    return (void *)code;
  }

  // Initialize transformation machinery.  Note that we don't have to re-map
  // child's code - the re-mapped VMA should be inherited from the parent.
  CodeTransformer transformer(*child, *binary);
  code = transformer.initialize(randomize, false);
  if(code != ret_t::Success) {
    DEBUGMSG(cpid << ": could not set up code transformer" << endl);
    transformer.cleanup();
    cleanupChild(child);
    return (void *)code;
  }

  INFO(cpid << ": beginning forked child" << endl);

  do {
    status = handleEvent(transformer);
  } while(status != Process::Exited && status != Process::SignalExit);

  INFO(cpid << ": cleaning up forked child" << endl);
  if(transformer.cleanup() != ret_t::Success)
    WARN(cpid << ": problem cleaning up code transformer" << endl);
  cleanupChild(child);

  return (void *)code;
}

int main(int argc, char **argv) {
  int remaining;
  ret_t code;
  Process::status_t status;
  Alarm alarm;
  Timer t;

  t.start();

  DEBUGMSG("initializing chameleon" << endl);
  if(!checkCompatibility()) ERROR("incompatible system" << endl);
  masterPID = getpid();
  parseArgs(argc, argv);
  if((code = setupSignalsAndAlarm(alarm)) != ret_t::Success)
    ERROR("could not initialize chameleon signaling: " << retText(code) << endl);
#ifdef DEBUG_BUILD
  if(traceFilename) {
    DEBUGMSG("tracing output to '" << traceFilename << "'" << endl);
    traceFile.open(traceFilename);
    if(!traceFile.is_open())
      ERROR("could not open trace file '" << traceFilename << "': "
            << strerror(errno) << endl);
  }
#endif
  DEBUG(printChameleonInfo())

  t.end();
  INFO("chameleon setup: " << t.elapsed(Timer::Micro) << " us" << endl);

  INFO("Starting '" << childArgv[0] << "'" << endl);
  t.start();

  // Initialize libelf/disassembler, load the binary (including all metadata)
  code = Binary::initLibELF();
  if(code != ret_t::Success)
    ERROR("could not initialize libelf: " << retText(code) << endl);
  code = arch::initDisassembler();
  if(code != ret_t::Success)
    ERROR("could not initialize disassembler: " << retText(code) << endl);
  binary.reset(new Binary(childArgv[0]));
  code = binary->initialize();
  if(code != ret_t::Success)
    ERROR("could not initialize binary: " << retText(code) << endl);

  // Initialize the main child process & it's transformer
  DEBUG(parasite::initializeLog(verboseDebug));
  Process child(childArgc, childArgv);
  code = child.forkAndExec();
  if(code != ret_t::Success)
    ERROR("could not set up child for tracing: " << retText(code) << endl);
  CodeTransformer::initialize();
  CodeTransformer transformer(child, *binary);
  code = transformer.initialize(randomize, true);
  if(code != ret_t::Success)
    ERROR("could not set up state transformer: " << retText(code) << endl);

  t.end();
  INFO(child.getPid() << ": application startup: " << t.elapsed(Timer::Micro)
       << " us" << endl);
  INFO(child.getPid() << ": beginning main child" << endl);

  if(randomizePeriod) {
    code = alarm.start();
    if(code != ret_t::Success)
      ERROR("could not start alarm: " << retText(code) << endl);
  }

  do {
    status = handleEvent(transformer);
  } while(status != Process::Exited && status != Process::SignalExit);

  INFO(child.getPid() << ": cleaning up main child " << endl);
  code = transformer.cleanup();
  if(code != ret_t::Success)
    ERROR("could not clean up clean up transformer" << retText(code) << endl);

  // We need to wait for all children to finish up, as exiting the main thread
  // will kill the handlers and their handled children
  while((remaining = __atomic_load_n(&numChildren, __ATOMIC_ACQUIRE))) {
    DEBUGMSG("waiting for all children to join" << endl);
    if(syncWait(&numChildren, remaining))
      ERROR("could not wait for children to exit: " << strerror(errno) << endl);
    joinHandlers();
  }

  if(randomizePeriod) {
    code = alarm.stop();
    if(code != ret_t::Success)
      ERROR("could not stop alarm: " << retText(code) << endl);
    DEBUGMSG("rang " << alarmsRung << " alarms" << endl);
  }

  return 0;
}

