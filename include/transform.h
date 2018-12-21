/**
 * class CodeTransformer
 *
 * Implements reading, randomizing & transforming code.  Code pages randomized
 * by the CodeTransformer are mapped into the target application by handling
 * faults through the userfaulfd file descriptor.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/15/2018
 */

#ifndef _TRANSFORM_H
#define _TRANSFORM_H

#include <random>
#include <unordered_map>
#include <pthread.h>

/* Note: arch.h includes DynamoRIO APIs */
#include "arch.h"
#include "binary.h"
#include "memoryview.h"
#include "process.h"
#include "randomize.h"
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
    : proc(proc), binary(proc.getArgv()[0]), slotPadding(slotPadding),
      faultHandlerPid(-1), batchedFaults(batchedFaults) {}
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

  /**
   * DynamoRIO operand size in bytes.
   * @param op an operand
   * @return the size of the operand in bytes, or UINT32_MAX if unknown
   */
  static unsigned getOperandSize(opnd_t op)
  { return opnd_size_in_bytes(opnd_get_size(op)); }

  /**
   * Convert a stack slot (base register + offset) to an offset from the
   * canonical frame address (CFA), defined as the highest stack address of a
   * function activation for stacks that grow down.
   *
   * @param frameSize size of the frame in bytes
   * @param reg the base register
   * @param offset the displacement from the base register
   * @return offset from the CFA, or INT32_MAX if not a valid stack reference
   */
  static int32_t canonicalizeSlotOffset(uint32_t framesize,
                                        arch::RegType reg,
                                        int16_t offset);

  /**
   * Convert an offset from the canonical frame address (CFA) to an offset from
   * a base register.
   *
   * @param frameSize size of the frame in bytes
   * @param reg the base register
   * @param offset canonicalized frame offset
   * @return offset from the base register, or INT32_MAX if not a valid stack
   *         reference
   */
  static int32_t slotOffsetFromRegister(uint32_t frameSize,
                                        arch::RegType reg,
                                        int16_t offset);

private:
  /* A previously instantiated process */
  Process &proc;

  /* Binary containing transformation metadata */
  Binary binary;

  /* Code section start & end addresses */
  uintptr_t codeStart, codeEnd;

  /* An abstract view of the code segment, used to randomize code */
  MemoryWindow codeWindow;

  /* Randomization machinery */
  typedef std::unordered_map<uintptr_t, RandomizedFunctionPtr>
    RandomizedFunctionMap;
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
   * Create memory window for the application's code.  The window will be used
   * both as a buffer for randomization and as the source of data used to
   * handle page faults.
   *
   * @param codeSection the code section from the binary
   * @param codeSegment the code segment from the binary
   */
  ret_t populateCodeWindow(const Binary::Section &codeSection,
                           const Binary::Segment &codeSegment);

  /**
   * Analyze the operands of an instruction in order to determine any
   * randomization restrictions.
   *
   * @template NumOp function to get the number of operands
   * @template GetOp function to get an operand
   * @param info randomization information for a function
   * @param frameSize currently calculated frame size
   * @param instr an instruction
   * @return a return code describing the outcome
   */
  template<int (*NumOp)(instr_t *),
           opnd_t (*GetOp)(instr_t *, unsigned)>
  ret_t analyzeOperands(RandomizedFunctionPtr &info,
                        uint32_t frameSize,
                        instr_t *instr);

  /**
   * Disassemble a function's code and analyze for randomization restrictions.
   * @param info randomization information for a function
   * @return a return code describing the outcome
   */
  ret_t analyzeFunction(RandomizedFunctionPtr &info);

  /**
   * Disassemble all functions and analyze for randomization restrictions.
   * Instantiates all randomization machinery but does *not* perform actual
   * randomization
   *
   * @return a return code describing the outcome
   */
  ret_t analyzeFunctions();

  /**
   * Rewrite stack slot reference operands to refer to the randomized location.
   * Templated because DynamoRIO differentiates between source & destination
   * operands, but we do the same operations regardless.
   *
   * @template NumOp function to get the number of operands
   * @template GetOp function to get an operand
   * @template SetOp function to set an operand
   * @param info randomization information for a function
   * @param frameSize currently calculated original frame size
   * @param randFrameSize currently calculated randomized frame size
   * @param instr an instruction
   * @param changed output argument set to true if instruction was changed
   * @return a return code describing the outcome
   */
  template<int (*NumOp)(instr_t *),
           opnd_t (*GetOp)(instr_t *, unsigned),
           void (*SetOp)(instr_t *, unsigned, opnd_t)>
  ret_t randomizeOperands(const RandomizedFunctionPtr &info,
                          uint32_t frameSize,
                          uint32_t randFrameSize,
                          instr_t *instr,
                          bool &changed);

  /**
   * Randomize and re-encode a function.
   * @param info randomization information for a function
   * @return a return code describing the outcome
   */
  ret_t randomizeFunction(RandomizedFunctionPtr &info);

  /**
   * Load the code segment from disk into the memory window and randomize
   * all functions.
   * @return a return code describing the outcome
   */
  ret_t randomizeFunctions();
};

}

#endif /* _TRANSFORM_H */

