/**
 * Useful types for Popcorn Chameleon.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/11/2018
 */

#ifndef _TYPES_H
#define _TYPES_H

#include <utility>
#include <cstddef>
#include <cstdint>

namespace chameleon {

/* Binary file access error codes */
#define BINARY_RETCODES \
  X(ElfFailed, "could not initialize libelf") \
  X(OpenFailed, "could not open binary") \
  X(ElfReadError, "could not read ELF metadata") \
  X(InvalidElf, "invalid ELF file/format") \
  X(NoSuchSection, "could not find ELF section/segment") \
  X(BadMetadata, "invalid metadata encoded in binary")

/* Process control error codes */
#define PROCESS_RETCODES \
  X(ForkFailed, "fork() returned an error") \
  X(RecvUFFDFailed, "could not receive userfaultfd descriptor from child") \
  X(TraceSetupFailed, "setting up tracing of child from parent failed") \
  X(WaitFailed, "wait() returned an error") \
  X(PtraceFailed, "ptrace() returned an error") \
  X(Exists, "process already exists") \
  X(DoesNotExist, "process exited or terminated") \
  X(InvalidState, "operation not allowed in current process state")

/* State transformation error codes */
#define TRANSFORM_RETCODES \
  X(InvalidTransformConfig, "invalid transformation configuration") \
  X(DisasmSetupFailed, "setting up disassembler failed") \
  X(RemapCodeFailed, "could not remap code section for userfaulfd setup") \
  X(AnalysisFailed, "could not analyze code to ensure correctness") \
  X(RandomizeFailed, "could not randomize code section") \
  X(FaultHandlerFailed, "could not start fault handling thread") \
  X(UffdHandshakeFailed, "userfaultfd API handshake failed") \
  X(UffdRegisterFailed, "userfaultfd register region failed") \
  X(UffdCopyFailed, "userfaultfd copy failed") \
  X(EncodeFailed, "re-encoding transformed instruction failed") \
  X(BadFault, "kernel delivered unexpected or unhandled fault") \
  X(MarshalDataFailed, "failed to marshal data to handle fault") \
  X(BadMarshal, "invalid view of memory, found overlapping regions")

enum ret_t {
  Success = 0,
#define X(code, desc) code, 
  BINARY_RETCODES
  PROCESS_RETCODES
  TRANSFORM_RETCODES
#undef X
};

const char *retText(ret_t retcode);

/**
 * Iterate over contiguous entries of a given type.  Useful for providing a
 * sliced view of an array with bounds checking.
 */
template<typename T>
class iterator {
public:
  iterator(T *entries, size_t len) : cur(0), len(len), entries(entries) {}

  size_t getLength() const { return len; }
  bool end() const { return cur >= len; }

  void reset() { cur = 0; }
  void operator++() { cur++; }

  T *operator[](size_t idx) const {
    if(idx < len) return &entries[idx];
    else return nullptr;
  }

  const T *operator*() const {
    if(cur < len) return &this->entries[cur];
    else return nullptr;
  }
private:
  size_t cur, len;
  T *entries;
};

typedef iterator<unsigned char> byte_iterator;

/* A range of values.  The first element *must* be smaller than the second. */
typedef std::pair<int64_t, int64_t> range;

}

#endif /* _TYPES_H */

