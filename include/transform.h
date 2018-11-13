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

/* Note: arch.h includes DynamoRIO APIs */
#include "arch.h"
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
    RandomizedFunction() : calleeSaveSize(0), frameSize(UINT32_MAX) {}

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

    /**
     * Function information - return what you ask for.
     */
    uint32_t getCalleeSaveSize() const { return calleeSaveSize; }
    uint32_t getFrameSize() const { return frameSize; }

    /**
     * Get frame space for non-callee-saved frame space.
     * @return frame space not devoted to callee-saved registers
     */
    uint32_t getNonCalleeSaveSize() const
    { return frameSize - calleeSaveSize; }

    /**
     * Return whether an offset is contained in the function's callee-saved
     * area.
     * @param offset a canonicalized offset
     * @return true if contained in the callee-saved area, false otherwise
     */
    bool inCalleeSaved(int offset) const
    { return (-offset) <= calleeSaveSize; }

    /**
     * Get the randomized offset for a stack slot
     *
     * Note: the original stack slot offset must be canonicalized (i.e.,
     * converted to offset from CFA) before passing to the function
     *
     * @param orig the original stack slot offset (canonicalized)
     * @return the canonicalized randomized offset, or INT32_MAX if orig
     *         doesn't correspond to any stack slot
     */
    int getRandomizedOffset(int orig) const;
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
    uint32_t calleeSaveSize;
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
     * Comparison function for sorting & searching.
     * @param a first slot mapping
     * @param a second slot mapping
     * @return true if a's first element is less than b's first element
     */
    static bool slotCmp(const SlotMap &a, const SlotMap &b)
    { return a.first < b.first; }

    /**
     * Get the size, in bytes, of the callee-saved register area.
     * @param ui an iterator over the unwinding records
     * @return size in bytes of callee-saved register area
     */
    static uint32_t getCalleeSaveSize(Binary::unwind_iterator &ui);

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
  //
  //   "std::random_device provides an entropy member function...But popular
  //    libraries (both GCC's libstdc++ and LLVM's libc++) always return zero"
  //
  // Hence we can't check if it's a true RNG from the entropy() function.
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
   * Rewrite stack slot reference operands to refer to the randomized location.
   * Templated because DynamoRIO differentiates between source & destination
   * operands, but we do the same operations regardless.
   *
   * @template NumOp function to get the number of operands
   * @template GetOp function to get an operand
   * @template SetOp function to set an operand
   * @param info randomization information for a function
   * @param frameSize currently calculated frame size
   * @param instr an instruction
   * @param doEncode output argument set to true if instruction needs to be
   *                 re-encoded (i.e., we rewrote an operand)
   * @return a return code describing the outcome
   */
  template<int (*NumOp)(instr_t *),
           opnd_t (*GetOp)(instr_t *, unsigned),
           void (*SetOp)(instr_t *, unsigned, opnd_t)>
  ret_t rewriteOperands(const RandomizedFunction &info,
                        uint32_t frameSize,
                        instr_t &instr,
                        bool &doEncode);

  /**
   * Decode, randomize and re-encode a function.
   * @param func a function record
   * @param info randomization information for a function
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

