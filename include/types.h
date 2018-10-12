/**
 * Useful types for Popcorn Chameleon.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _TYPES_H
#define _TYPES_H

namespace chameleon {

/* Process control error codes */
#define PROCESS_RETCODES \
  X(ForkFailed, "fork() returned an error") \
  X(SetupFailed, "process setup failed") \
  X(WaitFailed, "wait() returned an error") \
  X(PtraceFailed, "ptrace() returned an error") \
  X(Exists, "process already exists") \
  X(DoesNotExist, "process exited or terminated")

enum ret_t {
  Success = 0,
#define X(code, desc) code, 
  PROCESS_RETCODES
#undef X
};

const char *retText(ret_t retcode);

}

#endif /* _TYPES_H */

