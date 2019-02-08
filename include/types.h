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
#include <ctime>

namespace chameleon {

/* Binary file access error codes */
#define BINARY_RETCODES \
  X(ElfFailed, "could not initialize libelf") \
  X(OpenFailed, "could not open binary") \
  X(ElfReadError, "could not read ELF metadata") \
  X(InvalidElf, "invalid ELF file/format") \
  X(NoSuchSection, "could not find ELF section/segment") \
  X(BadTransformMetadata, "invalid transformation metadata encoded in binary") \
  X(NoTransformMetadata, "could not find transformation metadata for function")

/* Process control error codes */
#define PROCESS_RETCODES \
  X(ForkFailed, "fork() returned an error") \
  X(TraceSetupFailed, "setting up tracing of child from parent failed") \
  X(WaitFailed, "wait() returned an error") \
  X(PtraceFailed, "ptrace() returned an error") \
  X(InterruptFailed, "could not interrupt task") \
  X(SignalFailed, "could not send signal to process") \
  X(HandoffFailed, "handing off tracing to another thread failed") \
  X(Exists, "process already exists") \
  X(DoesNotExist, "process exited or terminated") \
  X(InvalidState, "operation not allowed in current process state") \
  X(CompelInitFailed, "compel initialization failed") \
  X(CompelSyscallFailed, "compel child system call failed") \
  X(CompelInfectFailed, "compel infect failed") \
  X(CompelActionFailed, "compel action in child failed") \
  X(CompelCureFailed, "compel cure failed") \
  X(ReadFailed, "reading from child memory failed") \
  X(WriteFailed, "writing to child memory failed") \
  X(TruncatedAccess, "read/write of region truncated - out of space in child")

/* State transformation error codes */
#define TRANSFORM_RETCODES \
  X(InvalidTransformConfig, "invalid transformation configuration") \
  X(DisasmSetupFailed, "setting up disassembler failed") \
  X(RemapCodeFailed, "could not remap code section for userfaulfd setup") \
  X(DropCodeFailed, "dropping code to force new page faults failed") \
  X(AnalysisFailed, "could not analyze code to ensure correctness") \
  X(RandomizeFailed, "could not randomize code section") \
  X(TransformFailed, "could not transform stack to match randomization") \
  X(ChildHandlerSetupFailed, "creating child handler thread failed") \
  X(ChildHandlerCleanupFailed, "cleaning up child handler thread failed") \
  X(FaultHandlerFailed, "could not start fault handling thread") \
  X(ScramblerFailed, "could not start code randomization thread") \
  X(UffdHandshakeFailed, "userfaultfd API handshake failed") \
  X(UffdRegisterFailed, "userfaultfd register region failed") \
  X(UffdCopyFailed, "userfaultfd copy failed") \
  X(MarshalDataFailed, "failed to marshal data to handle fault") \
  X(BadMarshal, "invalid view of memory, found overlapping regions")

/* Other miscellaneous error codes */
#define MISC_RETCODES \
  X(BadFormat, "bad input format") \
  X(LockFailed, "locking/unlocking mutex failed") \
  X(FutexFailed, "futex operation failed") \
  X(NotImplemented, "not implemented") \
  X(FileOpenFailed, "could not open file") \
  X(NoTimestamp, "could not get timestamp") \
  X(InvalidAlarm, "invalid alarm configuration") \
  X(AlarmInitFailed, "alarm initialization failed") \
  X(AlarmStartFailed, "could not start alarm") \
  X(AlarmStopFailed, "could not stop alarm") \
  X(AlarmHandlerStartFailed, "could not start alarm handler") \
  X(AlarmHandlerWaitFailed, "alarm handler could not wait for alarm") \
  X(ChameleonSignalFailed, "inter-thread signaling failed")

enum ret_t {
  Success = 0,
#define X(code, desc) code, 
  BINARY_RETCODES
  PROCESS_RETCODES
  TRANSFORM_RETCODES
  MISC_RETCODES
#undef X
};

const char *retText(ret_t retcode);

/* Reasons a tracee was stopped */
enum stop_t {
  Other = 0, /* child is stopped for unhandled reason */
  Clone,     /* child is stopped on clone() syscall */
  Exec,      /* chlid is stopped on execve() syscall */
  Fork       /* child is stopped on fork() syscall */
};

/**
 * Iterate over contiguous entries of a given type.  Useful for providing a
 * sliced view of an array with bounds checking.
 */
template<typename T>
class iterator {
public:
  iterator() : cur(0), len(0), entries(nullptr) {}
  iterator(T *entries, size_t len) : cur(0), len(len), entries(entries) {}

  /**
   * Return a sentinal empty iterator.
   * @return an empty iterator
   */
  static iterator empty() { return iterator(); }

  /**
   * Get the number of entries made available by the iterator.
   * @return the number of available entries
   */
  size_t getLength() const { return len; }

  /**
   * Return whether or not the iterator has reached the end.
   * @return true if the iterator has visited all entries or false otherwise
   */
  bool end() const { return cur >= len; }

  /**
   * Reset the iterator to the beginning of the entries.
   */
  void reset() { cur = 0; }

  /**
   * Advance to the next entry.
   */
  void operator++() { cur++; }

  /**
   * Return the entry at a given index.
   * @param idx the index
   * @return the entry at idx or nullptr if idx is out of bounds
   */
  T *operator[](size_t idx) const {
    if(idx < len) return &entries[idx];
    else return nullptr;
  }

  /**
   * Return the entry at the current iterator index.
   * @return the entry at the iterator's current index or nullptr if there
   *         are no more entries
   */
  const T *operator*() const {
    if(cur < len) return &this->entries[cur];
    else return nullptr;
  }

  /**
   * Return whether the iterator has valid entries to traverse.
   * @return true if the iterator has entries available for traversal or false
   *         otherwise
   */
  bool operator!() const { return entries == nullptr; }
private:
  size_t cur, len;
  T *entries;
};

typedef iterator<unsigned char> byte_iterator;

/* A range of values.  The first element *must* be smaller than the second. */
typedef std::pair<int64_t, int64_t> range_t;
typedef std::pair<uint64_t, uint64_t> urange_t;

/**
 * Timer utility for measuring execution times.
 */
class Timer {
public:
  /* Unit of elapsed time. */
  enum Unit {
    Nano,
    Micro,
    Milli,
    Second,
  };

  Timer() : s(0), e(0), accum(0) {}

  /**
   * Convert a struct timespec to nanoseconds.
   * @param ts a struct timespec
   * @return time in nanoseconds
   */
  static uint64_t timespecToNano(struct timespec &ts)
  { return (ts.tv_sec * 1000000000ULL) + ts.tv_nsec; }

  /**
   * Get a timestamp in nanoseconds.
   * @return timestamp in nanoseconds or UINT64_MAX if timestamp API failed
   */
  static uint64_t timestamp() {
    struct timespec ts;
    if(clock_gettime(CLOCK_MONOTONIC, &ts) == -1) return UINT64_MAX;
    else return timespecToNano(ts);
  }

  /**
   * Take a starting timestamp.
   * @return a return code describing the outcome
   */
  ret_t start() {
    s = timestamp();
    return s != UINT64_MAX ? ret_t::Success : ret_t::NoTimestamp;
  }

  /**
   * Take an ending timestamp & accumulate elapsed time if requested.  Users
   * should have already called start(), otherwise subsequent calls to the
   * timer (or accumulations) may return garbage.
   *
   * @param doAccumulate whether or not to accumulate elapsed time
   * @return a return code describing the outcome
   */
  ret_t end(bool doAccumulate = false) {
    e = timestamp();
    if(e != UINT64_MAX) {
      if(doAccumulate) accum += e - s;
      return ret_t::Success;
    }
    else return ret_t::NoTimestamp;
  }

  /**
   * Convert elapsed time in nanoseconds to another unit.
   * @param nano elapsed time in nanoseconds
   * @param unit preferred unit type
   * @return elapsed time in new units
   */
  static uint64_t toUnit(uint64_t nano, Unit unit) {
    switch(unit) {
    default: /* fall through */
    case Nano: return nano;
    case Micro: return nano / 1000ULL;
    case Milli: return nano / 1000000ULL;
    case Second: return nano / 1000000000ULL;
    }
  }

  /**
   * Return the time elapased between calls to start() and end().
   * @param u preferred unit type
   * @return elapsed time in nanoseconds
   */
  uint64_t elapsed(Unit u) { return toUnit(e - s, u); }

  /**
   * Return the total elapsed time from all calls to elapsed().
   * @param u preferred unit type
   * @return total elapsed time in nanoseconds
   */
  uint64_t totalElapsed(Unit u) { return toUnit(accum, u); }

private:
  uint64_t s, e;  /* starting & ending timestamps */
  uint64_t accum; /* accumulated time */
};

}

#endif /* _TYPES_H */

