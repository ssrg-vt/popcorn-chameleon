/**
 * class CodeTransformer
 *
 * Implements reading & transforming code as read in through the userfaulfd
 * mechanism.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/15/2018
 */

#ifndef _TRANSFORM_H
#define _TRANSFORM_H

#include <random>
#include <utility>
#include <unordered_map>
#include <pthread.h>

#include "binary.h"
#include "memoryview.h"
#include "process.h"
#include "types.h"
#include "userfaultfd.h"

namespace chameleon {

class CodeTransformer {
public:
  /**
   * Construct a code transformer for a given process.  Does not initialize the
   * transformer; users must call initialize().
   * @param proc a process
   * @param batchedFaults maximum number of faults handled at once
   */
  CodeTransformer(Process &proc,
                  size_t batchedFaults = 1,
                  size_t slotPadding = 128)
    : proc(proc), binary(proc.getArgv()[0]), faultHandlerPid(-1),
      batchedFaults(batchedFaults), slotPadding(slotPadding) {}
  CodeTransformer() = delete;
  ~CodeTransformer();

  /**
   * Initialize the code transformer object.
   * @return a return code describing the outcome
   */
  ret_t initialize();

  /**
   * Project the transformed code into the buffer.
   * @param address page address at which to fill
   * @param buffer a buffer into which the MemoryRegion's contents are copied
   * @return a return code describing the outcome
   */
  ret_t project(uintptr_t address, std::vector<char> &buffer) const
  { return codeWindow.project(address, buffer); }

  /**
   * Return the userfaultfd file descriptor for the attached process.
   * @return the userfaultfd file descriptor or -1 if there was an error
   */
  int getUserfaultfd() const { return proc.getUserfaultfd(); }

  /**
   * Return the number of page faults batched together and handled at once by
   * the fault handling thread for every call to read() on the descriptor.
   * @return the number of faults handled at once
   */
  size_t getNumFaultsBatched() const { return batchedFaults; }

  /**
   * Return the fault handling thread's PID.  Only valid after successful calls
   * to initialize().
   * @return the fault handling thread's PID or -1 if not initialized
   */
  pid_t getFaultHandlerPid() const { return faultHandlerPid; }

  /**
   * Set the PID of the fault handling thread.  Should only be called from the
   * fault handling thread.
   * @param pid the fault handling thread's PID
   */
  void setFaultHandlerPid(pid_t pid) { faultHandlerPid = pid; }

private:
  /**
   * Metadata describing where function activation information (i.e., on the
   * stack and in registers) is placed in a randomized version of the function.
   */
  class RandomizedFunction {
  public:
    RandomizedFunction() : frameSize(UINT32_MAX) {}

    /**
     * Randomize a function.  If it was previously randomized, drop all
     * previous information.
     *
     * @param binary a Binary object for reading function metadata
     * @param func a function record
     * @param seed random number generator seed
     * @param maxPadding maximum randomized padding added between stack slots
     * @return a return code describing the outcome
     */
    ret_t randomize(const Binary &binary,
                    const function_record *func,
                    int seed,
                    size_t maxPadding);
  private:
    /*
     * Random number generator.  Because we may generate a large number of
     * random numbers and have limited entropy, use a pseudo-RNG seeded with a
     * true random number passed to randomize().
     */
    std::default_random_engine gen;

    /* Stack slot padding */
    typedef std::uniform_int_distribution<int>::param_type slotBounds;
    std::uniform_int_distribution<int> slotDist;

    /* Mapping types */
    typedef std::pair<int, int> SlotMap;

    /* Frame size after randomization */
    uint32_t frameSize;

    ///////////////////////////////////////////////////////////////////////////
    // Note: maintain information as vectors because we interface with C and //
    // thus need to pass raw arrays.                                         //
    ///////////////////////////////////////////////////////////////////////////

    /*
     * Remapping of slots, indexed by their offset from the canonical frame
     * address (CFA).
     */
    std::vector<SlotMap> slots;

    /**
     * Generate a randomized stack slot padding value.
     * @return a random number to be used to pad between stack slots
     */
    int slotPadding() { return slotDist(gen); }

    /**
     * Randomize the stack slot offsets for a given function.
     * @param si stack slot iterator for function
     * @param func a function record
     * @return a return code describing the outcome
     */
    ret_t randomizeSlots(Binary::slot_iterator &si,
                         const function_record *func);
  };
  typedef std::unordered_map<uintptr_t, RandomizedFunction>
    RandomizedFunctionMap;

  /* A previously instantiated process */
  Process &proc;

  /* Binary containing transformation metadata */
  Binary binary;

  /* An abstract view of the code segment, used to randomize code */
  MemoryWindow codeWindow;

  /* Randomization machinery */
  RandomizedFunctionMap funcMaps; /* Per-function randomization information */
  size_t slotPadding; /* Maximum padding between subsequent stack slots */
  // Note: from http://www.pcg-random.org/posts/cpps-random_device.html:
  //   "std::random_device provides an entropy member function...But popular
  //    libraries (both GCC's libstdc++ and LLVM's libc++) always return zero"
  std::random_device rng;

  /* Thread responsible for reading & responding to page faults */
  pthread_t faultHandler;
  pid_t faultHandlerPid;
  size_t batchedFaults; /* Number of faults to handle at once */

  /**
   * Remap the code section of the binary to be an anonymous private region
   * suitable for attaching by userfaultfd.
   *
   * Note: this is unnecessary if userfaultfd lets us attach to the code
   * segment mapped in at application startup.
   *
   * @param start starting address of code section
   * @param len length of code section
   * @return a return code describing the outcome
   */
  ret_t remapCodeSegment(uintptr_t start, uint64_t len);

  /**
   * Decode, randomize and re-encode a function.
   * @param func a function record
   * @return a return code describing the outcome
   */
  ret_t rewriteFunction(const function_record *func,
                        const RandomizedFunction &info);

  /**
   * Load the code segment from disk into the memory window and randomize
   * all functions.
   *
   * @param codeSection the code section from the binary
   * @param codeSegment the code segment from the binary
   * @return a return code describing the outcome
   */
  ret_t randomizeFunctions(const Binary::Section &codeSection,
                           const Binary::Segment &codeSegment);
};

}

#endif /* _TRANSFORM_H */

