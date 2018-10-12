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

#define INFO( ... ) \
  do { std::cout << "[ chameleon " << masterPID << " ] " \
                 << __VA_ARGS__; } while(0);

#define ERRMSG( ... ) \
  do { std::cerr << "[ chameleon " << masterPID << " ] ERROR: " \
                 << __VA_ARGS__; } \
  while(0);

#ifndef NDEBUG
/* Debug printing */
# define DEBUGMSG( ... ) \
  do { \
    std::cerr << "[ " << std::left << std::setw(20) << __FILENAME__ \
              << ", line " << std::right << std::setw(4) << __LINE__ \
              << " ] DEBUG: " << __VA_ARGS__; \
  } while(0);
# define DEBUGMSG_RAW( ... ) do { std::cerr << __VA_ARGS__; } while(0);

/* Functionality to be executed only in debug builds */
# define DEBUG( ... ) do { __VA_ARGS__; } while(0);
#else
# define DEBUGMSG( ... ) {}
# define DEBUGMSG_RAW( ... ) {}
# define DEBUG( ... ) {}
#endif

#endif /* _LOG_H */

