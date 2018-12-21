/**
 * Helpers for logging & debugging implementation.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _LOG_H
#define _LOG_H

#include <iostream>
#include <iomanip>
#include <sys/types.h>

extern pid_t masterPID;

/* Print information to the console */
#define INFO( ... ) \
  do { std::cout << "[ chameleon " << masterPID << " ] " \
                 << __VA_ARGS__ << std::dec; } while(0);

#define WARN( ... ) \
  do { std::cerr << "[ chameleon " << masterPID << " ] WARNING: " \
                 << __VA_ARGS__ << std::dec; } while(0);

/* Print an error message and exit */
#define ERROR( ... ) \
  do { std::cerr << "[ chameleon " << masterPID << " ] ERROR: " \
                 << __VA_ARGS__; exit(1); } while(0);

#ifndef NDEBUG
/* I can't ever remember how to use NDEBUG, define an easier-to-use macro */
#define DEBUG_BUILD 1

/* Debug printing */
# define DEBUGMSG( ... ) \
  do { \
    std::cerr << "[ " << std::right << std::setw(20) << __FILENAME__ << ":" \
              << std::left << std::setw(3) << __LINE__ << " ] DEBUG: " \
              << __VA_ARGS__ << std::dec; \
  } while(0);
# define DEBUGMSG_RAW( ... ) \
  do { std::cerr << __VA_ARGS__ << std::dec; } while(0);
# define DEBUGMSG_INSTR( msg, instr ) \
  do { \
    DEBUGMSG(msg); \
    instr_disassemble(GLOBAL_DCONTEXT, instr, STDERR); \
    DEBUGMSG_RAW(std::endl); \
  } while(0);

/* Functionality to be executed only in debug builds */
# define DEBUG( ... ) do { __VA_ARGS__; } while(0);

/* Verbose debugging - only enable if requested at command-line */
extern bool verboseDebug;
# define DEBUGMSG_VERBOSE( ... ) if(verboseDebug) DEBUGMSG( __VA_ARGS__ )
# define DEBUGMSG_VERBOSE_RAW( ... ) if(verboseDebug) DEBUGMSG_RAW( __VA_ARGS__ )
# define DEBUG_VERBOSE( ... ) if(verboseDebug) DEBUG( __VA_ARGS__ )
#else
# define DEBUGMSG( ... ) {}
# define DEBUGMSG_RAW( ... ) {}
# define DEBUGMSG_INSTR( instr ) {}
# define DEBUG( ... ) {}
# define DEBUGMSG_VERBOSE( ... ) {}
# define DEBUGMSG_VERBOSE_RAW( ... ) {}
# define DEBUG_VERBOSE( ... ) {}
#endif

#endif /* _LOG_H */

