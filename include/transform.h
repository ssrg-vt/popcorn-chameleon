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
#include "log.h"
#include "memoryview.h"
#include "parasite.h"
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
                  Binary &binary,
                  size_t batchedFaults = 1,
                  size_t slotPadding = 128)
    : proc(proc), binary(binary), codeStart(0), codeEnd(0),
      slotPadding(slotPadding), faultHandlerPid(-1), faultHandlerExit(false),
      batchedFaults(batchedFaults) {}
  CodeTransformer() = delete;

  /**
   * Initialize the code transformer object.  Callers can selectively
   * enable/disable randomization (if disabled, act just like the OS mapping
   * pages from disk).  If remap is true, remap the child's code section to be
   * suitable for attaching userfaultfd file descriptors.  If false, it's
   * assumed the child's code is already set up for attaching userfaultfd -
   * just drop the existing pages to force new page faults.
   *
   * @param randomize if true, randomize the code
   * @param remap if true, remap the process' code section for userfaultfd,
   *              otherwise just drop the existing code pages
   * @return a return code describing the outcome
   */
  ret_t initialize(bool randomize, bool remap);

  /**
   * Clean up the state transformer, including stopping handling faults.  Users
   * should not call any other APIs after a call to cleanup().
   *
   * Note: calls Process::detach() in order to close the userfaultfd file
   * descriptor & exit the fault handling thread.
   *
   * @return a return code describing the outcome
   */
  ret_t cleanup();

  /**
   * Drop the child's code pages, forcing them to be brought back in by faults.
   * @return a return code describing the outcome
   */
  ret_t dropCode();

#ifdef DEBUG_BUILD
  /**
   * Return the Process object to which the CodeTransformer is attached.
   * @return the attached Process object
   */
  Process &getProcess() { return proc; }
#endif

  /**
   * Return the PID of the process being transformed.
   * @return the PID of the process being transformed
   */
  pid_t getProcessPid() const { return proc.getPid(); }

  /**
   * Return the address of a buffer which can be directly passed to the kernel
   * to handle a fault for an address, or 0 if none can be used for zero-copy.
   *
   * @param address faulting page address
   * @return address of page buffer used to handle fault or 0 if zero-copy is
   *         not possible
   */
  uintptr_t zeroCopy(uintptr_t address) const
  { return codeWindow.zeroCopy(address); }

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
   * Return whether the fault handling thread should exit.
   * @return true if the fault handler should exit, false otherwise
   */
  bool shouldFaultHandlerExit() const { return faultHandlerExit; }

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
   * function activation for stacks that grow down or the lowest stack address
   * of a function activation for stacks that grow up.  Note that as part of
   * the canonicalization process, all offsets are converted to positive
   * values.
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
   * a base register.  Performs the reverse operation from
   * canonicalizeSlotOffset().
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
  Binary &binary;

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
  bool faultHandlerExit;
  size_t batchedFaults; /* Number of faults to handle at once */

  /**
   * Write a page using the ptrace interface rather than via userfaultfd.
   * Needed as compel may touch pages during parasite operation; trying to
   * correctly synchronize compel and userfaultfd to serve what's needed
   * without causing further problems is not worth the effort.
   *
   * @param start address of page
   * @return a return code describing the outcome
   */
  ret_t writePage(uintptr_t start);

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

