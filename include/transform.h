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
#include <stack_transform.h>

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
   * Initialize data required by all CodeTransformer objects.  If non-null,
   * open the blacklist file and populate with addresses of functions that will
   * not be randomized.
   *
   * @param blacklistFilename file containing addresses of functions which
   *                          should not be randomized
   * @param badSitesFilename file containing call site addresses known to cause
   *                         problems and hence should be avoided
   */
  static void initialize(const char *blacklistFilename,
                         const char *badSitesFilename);

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
      rewriteMetadata(nullptr), slotPadding(slotPadding), faultHandlerPid(-1),
      faultHandlerExit(false), batchedFaults(batchedFaults), intPageAddr(0),
      scramblerPid(-1), scramblerExit(false), numRandomizations(0),
      rerandomizeTime(0)
#ifdef DEBUG_BUILD
      , curStackBase(0x400000000000)
#endif
      {}
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
   * Re-randomize the child process.  This generates a new stack layout,
   * rewrites threads of the child process using the new layout and drops all
   * existing code pages.
   *
   * @return a return code describing the outcome
   */
  ret_t rerandomize();

  /**
   * Return the Process object to which the CodeTransformer is attached.
   * @return the attached Process object
   */
  Process &getProcess() { return proc; }

  /**
   * Return the PID of the process being transformed.
   * @return the PID of the process being transformed
   */
  pid_t getProcessPid() const { return proc.getPid(); }

  /**
   * Get the randomization information for the function enclosing a given
   * program counter value.
   *
   * @param pc a program counter value
   * @return randomized function information for the function closing pc, or
   *         nullptr if not found
   */
  RandomizedFunction *getRandomizedFunctionInfo(uintptr_t pc) const;

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
   * Return the code re-randomization ("scrambler") thread's PID.  Only valid
   * after successful calls to initialize().
   * @return the scrambler thread's PID or -1 if not initialized
   */
  pid_t getScramblerPid() const { return scramblerPid; }

  /**
   * DynamoRIO operand size in bytes.
   * @param op an operand
   * @return the size of the operand in bytes, or UINT32_MAX if unknown
   */
  static unsigned getOperandSize(const opnd_t &op)
  { return opnd_size_in_bytes(opnd_get_size(op)); }

  /**
   * Convert a stack slot (base register + offset) to an offset from the
   * canonical frame address (CFA), defined as the highest stack address of a
   * function activation for stacks that grow down or the lowest stack address
   * of a function activation for stacks that grow up.  As part of the
   * canonicalization process, all offsets are converted to positive values.
   *
   * @param frameSize size of the frame in bytes
   * @param reg the base register
   * @param offset the displacement from the base register
   * @return offset from the CFA, or INT32_MAX if not a valid stack reference
   */
  static int32_t canonicalizeSlotOffset(uint32_t framesize,
                                        arch::RegType reg,
                                        int32_t offset);

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
                                        int32_t offset);

  /**
   * Randomize all functions contained in the memory window.
   * @param buffer buffer into which randomized code will be written
   * @return a return code describing the outcome
   */
  ret_t randomizeFunctions(MemoryWindow &buffer);

  /**
   * Dump the process' backtrace to the stack transformation log.
   */
  void dumpBacktrace();

  /* The following APIs should *only* be called by the fault-handling thread */

  /**
   * Set the PID of the fault handling thread.  Should only be called from the
   * fault handling thread.
   * @param pid the fault handling thread's PID
   */
  void setFaultHandlerPid(pid_t pid) { faultHandlerPid = pid; }

  /**
   * Lock the code window during page fault handling to avoid inconsistent code
   * pages in the child application.
   * @return a return code describing the outcome
   */
  ret_t lockCodeWindow();

  /**
   * Unlock the code window after finished handling a page fault.
   * @return a return code describing the outcome
   */
  ret_t unlockCodeWindow();

  /**
   * Get the address of the page that should be filled with interrupt
   * instructions by the fault handling thread.
   *
   * @return address of page to be filled with interrupt instructions
   */
  uintptr_t getIntPageAddr() const { return intPageAddr; }

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
   * Return whether the fault handling thread should exit.
   * @return true if the fault handler should exit, false otherwise
   */
  bool shouldFaultHandlerExit() const { return faultHandlerExit; }

  /* The following APIs should *only* be called by the scrambling thread */

  /**
   * Set the scrambler thread's PID.
   * @param pid the scrambler thread's PID
   */
  void setScramberPid(pid_t pid) { scramblerPid = pid; }

  /**
   * Get the semaphore signaling the scrambler thread should generate a new
   * randomized version of the code.
   * @return the semaphore signaling to randomized code
   */
  sem_t *getScrambleSem() { return &scramble; }

  /**
   * Get the semaphore used by the scrambler thread to signal that it has
   * finished a randomization.
   * @return the semaphore signaling randomization has finished
   */
  sem_t *getFinishedScrambleSem() { return &finishedScrambling; }

  /**
   * Return the transformer's code buffer.
   * @return the memory window object representing the code segment
   */
  const MemoryWindow &getCodeWindow() const { return codeWindow; }

  /**
   * Return the transformer's code buffer for the next randomized version.
   * @return the memory window object representing the code segment
   */
  MemoryWindow &getNextCodeWindow() { return nextCodeWindow; }

  /**
   * Return whether the scrambler thread should exit.
   * @return true if the scrambler thread should exit or false otherwise
   */
  bool shouldScramblerExit() const { return scramblerExit; }

private:
  /* A previously instantiated process */
  Process &proc;

  /* Binary containing transformation metadata */
  Binary &binary;

  /* Code section start & end addresses */
  uintptr_t codeStart, codeEnd;

  /* An abstract view of the code segment, used to randomize code */
  MemoryWindow codeWindow, nextCodeWindow;

  /* Child stack transformation buffer & metadata */
  std::unique_ptr<unsigned char> stackMem;
  st_handle rewriteMetadata;

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

  /* Reading & responding to page faults */
  pthread_t faultHandler;
  pid_t faultHandlerPid;
  bool faultHandlerExit;
  size_t batchedFaults; /* Number of faults to handle at once */
  pthread_mutex_t windowLock;
  uintptr_t intPageAddr; /* Address of page that should be filled with
                            interrupt instructions by fault handler thread */

  /* Re-randomization */
  pthread_t scrambler;
  pid_t scramblerPid;
  bool scramblerExit;
  sem_t scramble, /* Begin generating a new set of randomized code */
        finishedScrambling; /* Scrambler has finished randomizing */
  size_t numRandomizations;
  uint64_t rerandomizeTime;

#ifdef DEBUG_BUILD
  /* Current transformed stack base */
  uintptr_t curStackBase;
#endif

  /**
   * Insert breakpoints where chameleon can perform a transformation.
   *
   * @param info randomization information for a function
   * @param origData output argument populated with original data at the
   *                 inserted breakpoint locations
   * @param interruptSize output argument set to the size of the inserted
   *                      interrupt instruction
   * @return a return code describing the outcome
   */
  ret_t sprayTransformBreakpoints(const RandomizedFunction *info,
                      std::unordered_map<uintptr_t, uint64_t> &origData,
                      size_t &interruptSize) const;

  /**
   * Restore original instruction bytes clobbered by inserting transformation
   * breakpoints.
   *
   * @param info randomization information for a function
   * @param origData original data at the inserted breakpoint locations
   * @return a return code describing the outcome
   */
  ret_t
  restoreTransformBreakpoints(const RandomizedFunction *info,
                const std::unordered_map<uintptr_t, uint64_t> &origData) const;

  /**
   * Advance the child process to a transformation point.
   *
   * @param ty output argument set to the type of transformation point at which
   *           the child was stopp
   * @param t a running timer which will be paused while advancing forward
   * @return a return code describing the outcome
   */
  ret_t advanceToTransformationPoint(RandomizedFunction::TransformType &Ty,
                                     Timer &t) const;

  /**
   * Calculate the stack bounds of both the stack in the child's memory and
   * Chameleon's buffer used for transformation.
   *
   * @param sp the current stack pointer
   * @param childSrcBase output argument set to the base of the current stack
   *                     in the child
   * @param bufSrcBase output argument set to the base of the current stack in
   *                   the buffer
   * @param childDstBase output argument set to the base of the transformed
   *                     stack in the child
   * @param bufDstBase output argument set to the base of the transformed stack
   *                   in the child
   * @param an iterator to space in Chameleon's buffer for reading in the
   *        current stack
   */
  byte_iterator calcStackBounds(uintptr_t sp,
                                uintptr_t &childSrcBase,
                                uintptr_t &bufSrcBase,
                                uintptr_t &childDstBase,
                                uintptr_t &bufDstBase);

#ifdef DEBUG_BUILD
  /**
   * Map in the new stack region and unmap the current stack region.
   *
   * @param childSrcBase base of current stack region in child
   * @param childDstBase base of transformed stack region in child
   * @param stackSize size of transformed stack
   * @param an iterator to space in Chameleon's buffer used to set the
   *        transformed stack region or an empty iterator if the mapping failed
   */
  byte_iterator mapInNewStackRegion(uintptr_t childSrcBase,
                                    uintptr_t childDstBase,
                                    size_t stackSize);
#endif

  /**
   * Get the IR-level instruction for a given program counter value, enclosed
   * in the function represented by the specified randomization information.
   * The instruction is part of an instrlist_t for the enclosing function.
   *
   * Note: users can supply the info object using getRandomizedFunctionInfo()
   *
   * @return a pointer to the IR-level instruction or nullptr if it could not
   *         be found
   */
  instr_t *getInstruction(uintptr_t pc, RandomizedFunction *info) const;

  /**
   * Write a code page using the process interface rather than via userfaultfd.
   * Needed as compel may touch pages during parasite operation; trying to
   * correctly synchronize compel and userfaultfd to serve what's needed
   * without causing further problems is not worth the effort.
   *
   * @param start address of page
   * @return a return code describing the outcome
   */
  ret_t writeCodePage(uintptr_t start) const;

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
  ret_t remapCodeSegment(uintptr_t start, size_t len) const;

  /**
   * Map a region of memory in the child with the given set of protections and
   * flags.
   *
   * @param start starting address of the region
   * @param len length of the region
   * @param prot memory protection flags
   * @param flags other memory mapping flags
   * @return a return code describing the outcome
   */
  ret_t mapMemory(uintptr_t start, size_t len, int prot, int flags) const;

  /**
   * Unmap a region of memory in the child.
   * @param start starting address of the region
   * @param len length of the region
   * @return a return code describing the outcome
   */
  ret_t unmapMemory(uintptr_t start, size_t len) const;

  /**
   * Change memory protections for a region of memory in the child.  Note that
   * start & len will be updated to be page-aligned if not already so.
   *
   * @param start the starting address
   * @param len the length of the region
   * @param prot type of protections to apply to the region
   * @return a return code describing the outcome
   */
  ret_t changeProtection(uintptr_t start, size_t len, int prot) const;

  /**
   * Drop the child's code pages, forcing them to be brought back in by faults.
   * @return a return code describing the outcome
   */
  ret_t dropCode();

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
  template<int (*NumOp)(instr_t *), opnd_t (*GetOp)(instr_t *, unsigned)>
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
   * @param buffer buffer into which randomized code will be written
   * @return a return code describing the outcome
   */
  ret_t randomizeFunction(RandomizedFunctionPtr &info, MemoryWindow &buffer);
};

}

#endif /* _TRANSFORM_H */

