/**
 * Useful types for Popcorn Chameleon.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _TYPES_H
#define _TYPES_H

namespace chameleon {

/* Binary file access error codes */
#define BINARY_RETCODES \
  X(OpenFailed, "could not open binary") \
  X(ElfFailed, "could not initialize libelf") \
  X(ElfReadError, "could not read ELF metadata") \
  X(NoSuchSection, "could not find ELF section")

/* Process control error codes */
#define PROCESS_RETCODES \
  X(ForkFailed, "fork() returned an error") \
  X(RecvUFFDFailed, "could not receive userfaultfd descriptor from child") \
  X(TraceSetupFailed, "setting up tracing of child from parent failed") \
  X(WaitFailed, "wait() returned an error") \
  X(PtraceFailed, "ptrace() returned an error") \
  X(Exists, "process already exists") \
  X(DoesNotExist, "process exited or terminated")

/* State transformation error codes */
#define TRANSFORM_RETCODES \
  X(UffdHandshakeFailed, "userfaultfd API handshake failed") \
  X(UffdRegisterFailed, "userfaultfd register region failed")

enum ret_t {
  Success = 0,
#define X(code, desc) code, 
  BINARY_RETCODES
  PROCESS_RETCODES
  TRANSFORM_RETCODES
#undef X
};

const char *retText(ret_t retcode);

}

#endif /* _TYPES_H */

