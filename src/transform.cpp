#include <algorithm>
#include <cstring>
#include <csignal>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#define LINUX
#define X86_64
#include <dr_api.h>

#include "arch.h"
#include "log.h"
#include "memoryview.h"
#include "transform.h"
#include "userfaultfd.h"
#include "utils.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// Fault handling
///////////////////////////////////////////////////////////////////////////////

static volatile bool faultHandlerExit = false;
static size_t faultsHandled = 0;

/**
 * Set up signal handler for SIGINT.  Required because the calls to read() in
 * handleFaultsAsync are blocking.
 * @return true if successfully initialized or false otherwise
 */
static inline bool setSignalHandler() {
  auto sigHandler = [](int signal) {};
  struct sigaction handler;
  handler.sa_handler = sigHandler;
  if(sigaction(SIGINT, &handler, nullptr) == -1) return false;
  return true;
}

/**
 * Handle a fault, including mapping in the correct data and randomizing any
 * code pieces.
 *
 * @param CT code transformer
 * @param uffd userfaultfd file descriptor for user-space fault handling
 * @param msg description of faulting region
 * @return a return code describing the outcome
 */
static std::vector<char> pageBuf(PAGESZ);
static inline ret_t
handleFault(CodeTransformer *CT, int uffd, const struct uffd_msg &msg) {
  uintptr_t pageAddr = PAGE_DOWN(msg.arg.pagefault.address);
  ret_t code = ret_t::Success;

  assert(msg.event == UFFD_EVENT_PAGEFAULT && "Invalid message type");
  DEBUGMSG("handling fault @ 0x" << std::hex << msg.arg.pagefault.address
           << ", flags=" << msg.arg.pagefault.flags << ", ptid=" << std::dec
           << msg.arg.pagefault.feat.ptid << std::endl);

  CT->project(PAGE_DOWN(msg.arg.pagefault.address), pageBuf);
  if(!uffd::copy(uffd, (uintptr_t)&pageBuf[0], pageAddr))
    code = ret_t::UffdCopyFailed;

  return code;
}

/**
 * Fault handling event loop.  Runs asynchronously to main application.
 * @param arg pointer to CodeTransformer object
 * @return nullptr always
 */
static void *handleFaultsAsync(void *arg) {
  CodeTransformer *CT = (CodeTransformer *)arg;
  int uffd = CT->getUserfaultfd();
  size_t nfaults = CT->getNumFaultsBatched(), toHandle, i;
  ssize_t bytesRead;
  pid_t me = syscall(SYS_gettid);
  struct uffd_msg *msg = new struct uffd_msg[nfaults];

  assert(CT && "Invalid CodeTransformer object");
  assert(uffd >= 0 && "Invalid userfaultfd file descriptor");
  assert(msg && "Page fault message buffer allocation failed");

  if(!setSignalHandler())
    ERROR("could not initialize cleanup signal handler" << std::endl);
  CT->setFaultHandlerPid(me);

  DEBUGMSG("fault handler " << me << ": reading from uffd=" << uffd
           << ", batching " << nfaults << " fault(s)" << std::endl);

  while(!faultHandlerExit) {
    bytesRead = read(uffd, msg, sizeof(struct uffd_msg) * nfaults);
    if(bytesRead >= 0) {
      toHandle = bytesRead / sizeof(struct uffd_msg);
      for(i = 0; i < toHandle; i++) {
        // TODO for Linux 4.11+, handle UFFD_EVENT_FORK, UFFD_EVENT_REMAP,
        // UFFD_EVENT_REMOVE, UFFD_EVENT_UNMAP
        if(msg[i].event != UFFD_EVENT_PAGEFAULT) continue;
        if(handleFault(CT, uffd, msg[i]) != ret_t::Success) {
          INFO("could not handle fault, limping ahead..." << std::endl);
        }
      }
    }
    else if(errno != EINTR) DEBUGMSG("read failed (return=" << bytesRead
                                     << "), trying again..." << std::endl);
  }
  delete [] msg;

  DEBUGMSG("fault handler " << me << " exiting" << std::endl);

  return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// CodeTransformer implementation
///////////////////////////////////////////////////////////////////////////////

CodeTransformer::~CodeTransformer() {
  faultHandlerExit = true;
  proc.detach(); // detaching closes the userfaultfd file descriptor
  if(faultHandlerPid > 0) {
    // Interrupt the fault handling thread if the thread was already blocking
    // on a read before closing the userfaultfd file descriptor
    syscall(SYS_tgkill, masterPID, faultHandlerPid, SIGINT);
    pthread_join(faultHandler, nullptr);
  }
}

ret_t CodeTransformer::initialize() {
  ret_t retcode;

  if(batchedFaults != 1) {
    DEBUGMSG("Currently can only handle 1 fault at a time" << std::endl);
    return ret_t::InvalidTransformConfig;
  }

  if((retcode = binary.initialize()) != ret_t::Success) return retcode;
  if((retcode = arch::initDisassembler()) != ret_t::Success)
    return retcode;
  const Binary::Section &code = binary.getCodeSection();

  retcode = remapCodeSegment(code.address(), code.size());
  if(retcode != ret_t::Success) return retcode;
  retcode = randomizeFunctions(code, binary.getCodeSegment());
  if(retcode != ret_t::Success) return retcode;

  if(!uffd::api(proc.getUserfaultfd(), nullptr, nullptr))
    return ret_t::UffdHandshakeFailed;
  if(!uffd::registerRegion(proc.getUserfaultfd(), code.address(), code.size()))
    return ret_t::UffdRegisterFailed;

  if(pthread_create(&faultHandler, nullptr, handleFaultsAsync, this))
    return ret_t::FaultHandlerFailed;

  return ret_t::Success;
}

static inline uint64_t getMask(size_t bytes) {
  uint64_t mask = 0;
  for(size_t i = 0; i < bytes; i++) mask |= (0xff << (i * 8));
  return ~mask;
}

ret_t CodeTransformer::remapCodeSegment(uintptr_t start, uint64_t len) {
  uintptr_t startPC, pageStart;
  uint64_t bytes, newBytes, syscall, mask;
  size_t syscallSize, roundedLen;
  int prot, flags, retval;

  DEBUGMSG("changing child's code section anonymous private mapping for "
           "userfaultfd" << std::endl);

  // Load the system call and starting address instruction bytes
  syscall = arch::syscall(syscallSize);
  if((startPC = proc.getPC()) == 0 ||
     proc.read(startPC, bytes) != ret_t::Success)
    return ret_t::RemapCodeFailed;

  // Set the lower byte(s) to the system call instruction
  mask = getMask(syscallSize);
  newBytes = (bytes & mask) | syscall;
  if(proc.write(startPC, newBytes) != ret_t::Success)
    return ret_t::RemapCodeFailed;

  DEBUGMSG("starting PC=0x" << std::hex << startPC << ": " << bytes << " -> "
           << newBytes << std::endl);

  // Marshal mmap arguments to change the mapping for the code section
  pageStart = PAGE_DOWN(start);
  roundedLen = PAGE_ALIGN_LEN(start, len);
  prot = PROT_EXEC | PROT_READ;
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
  if(proc.setSyscallRegs(SYS_mmap, pageStart, roundedLen, prot,
                         flags, -1, 0) != ret_t::Success)
    return ret_t::RemapCodeFailed;

  // Need to continue to second system call boundary to allow the mmap system
  // call to execute:
  //   1) going into kernel
  //   2) leaving kernel
  for(size_t i = 0; i < 2; i++) {
    if(proc.continueToNextEvent(true) != ret_t::Success ||
       proc.getStatus() != Process::Stopped) {
      DEBUGMSG("could not continue process to remap code" << std::endl);
      return ret_t::RemapCodeFailed;
    }

    // It's *possible* somebody managed to deliver a signal before entering the
    // kernel for the system call, although highly unlikely.  Continue past the
    // event if that's the case.  Note that after entering the kernel for a
    // system call ("syscall-enter-stop"), the *only* possible next event with
    // continueToNextEvent(true) is "syscall-exit-stop".
    if(!proc.stoppedAtSyscall()) {
      assert(i == 0 && "invalid stop mode for tracee");
      i--;
      continue;
    }
  }

  if(proc.getSyscallReturnValue(retval) != ret_t::Success ||
     retval != pageStart) {
    DEBUGMSG("mmap call to remap code section failed" << std::endl);
    return ret_t::RemapCodeFailed;
  }

  DEBUGMSG("remapped 0x" << std::hex << pageStart << " - 0x"
           << (pageStart + roundedLen) << std::endl);

  // Reset the PC to the entry point.  We don't need to restore the old bytes
  // as they'll get reloaded from disk upon faulting.
  if(proc.setPC(startPC) != ret_t::Success) {
    DEBUGMSG("could not reset PC to entry point" << std::endl);
    return ret_t::RemapCodeFailed;
  }

  return ret_t::Success;
}

ret_t CodeTransformer::randomizeFunctions(const Binary::Section &codeSection,
                                          const Binary::Segment &codeSegment) {
  uintptr_t segStart, segEnd, secStart, secEnd, curAddr;
  ssize_t len, filelen;
  const void *data;
  MemoryRegionPtr r;

  // Note that by construction of how we're adding regions we don't need to
  // call codeWindow.sort() to sort the regions within the window.

  // Calculate the first address we care about. Note that we *only* care about
  // pages with code, i.e., the code segment may contain other sections that
  // are on different pages that don't concern us.
  codeWindow.clear();
  segStart = codeSegment.address();
  secStart = codeSection.address();
  curAddr = std::max<uintptr_t>(PAGE_DOWN(secStart), segStart);

  // First, check if the segment contains data before the code section.  Note
  // that the region must be entirely contained on-disk (i.e., no zero-filled
  // region so file length = memory length) because segments can't have holes
  // and we know the subsequent code section *must* be on-disk.
  len = secStart - curAddr;
  if(len > 0) {
    if(binary.getRemainingFileSize(curAddr, codeSegment) <= len) {
      WARN("invalid file format - found holes in segment" << std::endl);
      return ret_t::InvalidElf;
    }
    data = binary.getData(curAddr, codeSegment);
    if(!data) return ret_t::MarshalDataFailed;
    r.reset(new FileRegion(curAddr, len, len, data));
    codeWindow.insert(r);
  }
  else if(len != 0) {
    WARN("invalid file format - segment start address is after code section "
         "start address" << std::endl);
    return ret_t::InvalidElf;
  }

  // Now, add a region for the code section
  len = codeSection.size();
  filelen = binary.getRemainingFileSize(secStart, codeSegment);
  if(filelen < len)
    WARN("code section on-disk smaller than in-memory representation ("
         << filelen << " vs " << codeSection.size() << " bytes)" << std::endl);
  data = binary.getData(secStart, codeSegment);
  if(!data) return ret_t::MarshalDataFailed;
  r.reset(new BufferedRegion(secStart, len, filelen, data));
  codeWindow.insert(r);

  // Finally, add any segment data after the code section
  secEnd = secStart + len;
  segEnd = segStart + codeSegment.memorySize();
  curAddr = std::min<uintptr_t>(PAGE_UP(secEnd), segEnd);
  len = curAddr - secEnd;
  filelen = binary.getRemainingFileSize(secEnd, codeSegment);
  data = binary.getData(secEnd, codeSegment);
  if(!data) return ret_t::MarshalDataFailed;
  r.reset(new FileRegion(secEnd, len, filelen, data));
  codeWindow.insert(r);

  // TODO go function by function & randomize
  Binary::func_iterator it = binary.getFunctions(secStart, secEnd);
  for(; !it.end(); ++it) {
    const function_record *func = *it;
    Binary::slot_iterator si = binary.getStackSlots(func);
    Binary::unwind_iterator ui = binary.getUnwindLocations(func);
    DEBUG(
      DEBUGMSG("function @ " << std::hex << func->addr << ", size = "
               << std::dec << func->code_size << ", " << si.getLength()
               << " stack slot(s), " << ui.getLength()
               << " callee-saved register(s)" << std::endl);
      for(; !si.end(); ++si) {
        const stack_slot *slot = *si;
        DEBUGMSG("  slot @ " << slot->base_reg << " + " << slot->offset
                 << ", size = " << slot->size
                 << ", alignment = " << slot->alignment << std::endl);
      }
      for(; !ui.end(); ++ui) {
        const unwind_loc *unwind = *ui;
        DEBUGMSG("  CSR " << unwind->reg << " at FBP + " << unwind->offset
                 << std::endl);
      }
      si.reset();
      ui.reset();
    )

    DEBUG(
      // TODO grab data from the code region rather than on-disk data
      size_t count = 0;
      byte *start = (byte *)binary.getData(func->addr),
           *end = start + func->code_size;
      instr_t instr;
      instr_init(GLOBAL_DCONTEXT, &instr);
      do {
        instr_reset(GLOBAL_DCONTEXT, &instr);
        start = decode(GLOBAL_DCONTEXT, start, &instr);
        DEBUGMSG(""); instr_disassemble(GLOBAL_DCONTEXT, &instr, 1);
        DEBUGMSG_RAW(std::endl);
        count++;
      } while(start < end);
      instr_free(GLOBAL_DCONTEXT, &instr);
    )
  }

  return ret_t::Success;
}

