#include <iostream>
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

static bool checkCompatibility() {
  // TODO check we're on a supported architecture, i.e., AArch64 or x86-64
  // TODO check that page size is a multiple of 4k
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
  while((c = getopt(argc, argv, "hv")) != -1) {
    switch(c) {
    default:
    case 'h': printHelp(argv[0]); exit(0); break;
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

int main(int argc, char **argv) {
  ret_t code;

  if(!checkCompatibility()) ERROR("incompatible system" << endl);
  masterPID = getpid();
  DEBUG(printChameleonInfo())
  parseArgs(argc, argv);

  // Initialize the child process
  Process child(childArgc, childArgv);
  code = child.forkAndExec();
  if(code != ret_t::Success)
    ERROR("could not set up child for tracing: " << retText(code) << endl);

  // Initialize libelf and set up the state transformer
  code = Binary::initLibELF();
  if(code != ret_t::Success)
    ERROR("could not initialize libelf: " << retText(code) << endl);
  CodeTransformer transformer(childArgv[0], child.getUserfaultfd());
  code = transformer.initialize();
  if(code != ret_t::Success)
    ERROR("could not set up state transformer: " << retText(code) << endl);

  do {
    code = child.continueToNextEvent();
    if(code != ret_t::Success) {
      child.detach();
      ERROR("could not continue to next event: " << retText(code) << endl);
    }

    switch(child.getStatus()) {
    default: INFO("unknown child status"); break;
    case Process::Stopped:
      INFO("child stopped with signal " << child.getSignal() << endl);
      break;
    case Process::Exited:
      INFO("child exited with code " << child.getExitCode() << endl);
      break;
    case Process::SignalExit:
      INFO("child terminated with signal " << child.getSignal() << endl);
      break;
    }
  } while(child.getStatus() != Process::Exited &&
          child.getStatus() != Process::SignalExit);

  return 0;
}

