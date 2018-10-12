#include <iostream>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "config.h"
#include "log.h"
#include "process.h"
#include "types.h"

using namespace std;
using namespace chameleon;

pid_t masterPID;
static int childArgc;
static char **childArgv;

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
    ERRMSG("did not specify a binary" << endl);
    printHelp(argv[0]);
    exit(1);
  }

  DEBUG(
    DEBUGMSG("Child arguments:");
    for(i = 0; i < childArgc; i++)
      DEBUGMSG_RAW(" " << childArgv[i]);
    DEBUGMSG_RAW(endl);
  )
}

int main(int argc, char **argv) {
  ret_t code;

  masterPID = getpid();
  DEBUG(printChameleonInfo())
  parseArgs(argc, argv);

  Process child(childArgc, childArgv);
  code = child.forkAndExec();
  if(code != ret_t::Success) {
    ERRMSG("could not set up child for tracing: " << retText(code) << endl);
    exit(1);
  }

  do {
    code = child.continueToNextEvent();
    if(code != ret_t::Success) {
      ERRMSG("could not continue to next event: " << retText(code) << endl);
      child.detach();
      exit(1);
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

