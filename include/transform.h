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

#include <pthread.h>
#include <capstone/capstone.h>

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
  CodeTransformer(Process &proc, size_t batchedFaults = 1)
    : proc(proc), binary(proc.getArgv()[0]), faultHandlerPid(-1),
      batchedFaults(batchedFaults) {}
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
  /* A previously instantiated process */
  Process &proc;

  /* Binary containing transformation metadata */
  Binary binary;

  /* An abstract view of the code segment, used to randomize code */
  MemoryWindow codeWindow;

  /* Handle for the disassembly framework */
  csh disasm;

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

