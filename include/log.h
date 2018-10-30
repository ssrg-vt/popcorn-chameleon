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
/* Debug printing */
# define DEBUGMSG( ... ) \
  do { \
    std::cerr << "[ " << std::right << std::setw(20) << __FILENAME__ << ":" \
              << std::left << std::setw(3) << __LINE__ << " ] DEBUG: " \
              << __VA_ARGS__ << std::dec; \
  } while(0);
# define DEBUGMSG_RAW( ... ) \
  do { std::cerr << __VA_ARGS__ << std::dec; } while(0);

/* Functionality to be executed only in debug builds */
# define DEBUG( ... ) do { __VA_ARGS__; } while(0);
#else
# define DEBUGMSG( ... ) {}
# define DEBUGMSG_RAW( ... ) {}
# define DEBUG( ... ) {}
#endif

#endif /* _LOG_H */

