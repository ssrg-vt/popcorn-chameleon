#include <algorithm>
#include <cstring>
#include <csignal>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#include "log.h"
#include "transform.h"
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
// RandomizedFunction implementation
///////////////////////////////////////////////////////////////////////////////

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
static inline int32_t
canonicalizeSlotOffset(uint32_t frameSize, arch::RegType reg, int16_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer: return offset + arch::framePointerOffset();
  case arch::RegType::StackPointer: return -(frameSize - offset);
  default: return INT32_MAX;
  }
}

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
static inline int32_t
slotOffsetFromRegister(uint32_t frameSize, arch::RegType reg, int16_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer: return offset - arch::framePointerOffset();
  case arch::RegType::StackPointer: return frameSize - (-offset);
  default: return INT32_MAX;
  }
}

uint32_t
CodeTransformer::RandomizedFunction::getCalleeSaveSize(Binary::unwind_iterator &ui) {
  uint32_t total = 0;
  for(; !ui.end(); ++ui) total += arch::getCalleeSaveSize((*ui)->reg);
  ui.reset();
  return total;
}

ret_t
CodeTransformer::RandomizedFunction::randomizeSlots(Binary::slot_iterator &si,
                                                 const function_record *func) {
  size_t nslots = si.getLength(), slotIdx;
  int curOffset = calleeSaveSize;
  std::vector<int> workspace;

  slots.reserve(nslots);
  workspace.reserve(nslots);

  // TODO need to check for overflow, i.e., for functions with a bunch of slots
  // and large padding between, need to ensure we don't overflow memory
  // addressing constraints

  // TODO need preprocess function to determine any stack slots which cannot be
  // randomized, e.g., those that are created via push/pop instructions

  // Add the stack slots into the workspace & permute
  for(slotIdx = 0; !si.end(); ++si, slotIdx++) workspace.emplace_back(slotIdx);
  std::shuffle(workspace.begin(), workspace.end(), gen);

  DEBUG(if(si.getLength()) DEBUGMSG("Remapped stack slots:" << std::endl);)

  // Add mappings for the permuted slots
  for(slotIdx = 0; slotIdx < si.getLength(); slotIdx++) {
    const stack_slot *slot = si[workspace[slotIdx]];
    int origOffset = canonicalizeSlotOffset(func->frame_size,
                                            arch::getRegType(slot->base_reg),
                                            slot->offset);
    curOffset = ROUND_UP(curOffset + slot->size + slotPadding(),
                         slot->alignment);
    slots.emplace_back(origOffset, -curOffset);

    DEBUGMSG("  " << origOffset << " -> " << -curOffset << std::endl);
  }
  frameSize = curOffset;

  std::sort(slots.begin(), slots.end(), slotCmp);
  return ret_t::Success;
}

ret_t
CodeTransformer::RandomizedFunction::randomize(const Binary &binary,
                                               const function_record *func,
                                               int seed,
                                               size_t maxPadding) {
  ret_t retcode;
  Binary::slot_iterator si = binary.getStackSlots(func);
  Binary::unwind_iterator ui = binary.getUnwindLocations(func);
  gen.seed(seed);
  slotDist.param(slotBounds(0, maxPadding));

  DEBUG(
    DEBUGMSG("frame size = " << func->frame_size << " bytes, "
             << si.getLength() << " stack slot(s), " << ui.getLength()
             << " unwind location(s)" << std::endl);
    for(; !si.end(); ++si) {
      const stack_slot *slot = *si;
      DEBUGMSG("  slot @ " << slot->base_reg << " + " << slot->offset
               << ", size = " << slot->size
               << ", alignment = " << slot->alignment << std::endl);
    }
    for(; !ui.end(); ++ui) {
      const unwind_loc *unwind = *ui;
      DEBUGMSG("  Register " << unwind->reg << " at FBP + " << unwind->offset
               << std::endl);
    }
    si.reset();
    ui.reset();
  )

  calleeSaveSize = getCalleeSaveSize(ui);
  if((retcode = randomizeSlots(si, func)) != ret_t::Success) return retcode;

  return ret_t::Success;
}

int CodeTransformer::RandomizedFunction::getRandomizedOffset(int orig) const {
  SlotMap tmpSlot(orig, 0);
  std::vector<SlotMap>::const_iterator it =
    std::lower_bound(slots.begin(), slots.end(), tmpSlot, slotCmp);
  if(it == slots.end() || it->first != orig) return INT32_MAX;
  else return it->second;
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

  // Try to give the user some warning for excessive stack padding
  if(slotPadding >= PAGESZ)
    WARN("Large padding added between slots: " << slotPadding << std::endl);

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

/**
 * Return the canonicalized stack offset of an operand if it's a base +
 * displacement memory reference into the stack.  If it's not a memory
 * reference or not a reference to the stack, return >= 0.
 *
 * Note: this function assumes the stack grows down
 *
 * @param frameSize current frame size as we're walking through the function
 * @param op a DynamoRIO operand
 * @return the canonicalized offset represented as a negative number or >= 0 if
 *         not a stack slot reference
 */
static inline int getStackOffset(uint32_t frameSize, opnd_t op) {
  // TODO Note: from dr_ir_opnd.h about opnd_get_disp():
  //   "On ARM, the displacement is always a non-negative value, and the
  //   presence or absence of #DR_OPND_NEGATED in opnd_get_flags() determines
  //   whether to add or subtract from the base register"
  int offset = 0;
  enum arch::RegType type;
  if(opnd_is_base_disp(op)) {
    type = arch::getRegTypeDR(opnd_get_base(op));
    offset = opnd_get_disp(op);
    offset = canonicalizeSlotOffset(frameSize, type, offset);
    if(offset >= 0 || (-offset) > frameSize) offset = 0;
  }
  return offset;
}

template<int (*NumOp)(instr_t *),
         opnd_t (*GetOp)(instr_t *, unsigned),
         void (*SetOp)(instr_t *, unsigned, opnd_t)>
ret_t CodeTransformer::rewriteOperands(const RandomizedFunction &info,
                                       uint32_t frameSize,
                                       instr_t &instr,
                                       bool &doEncode) {
  size_t i;
  int32_t offset, randOffset, randRegOffset;
  opnd_t op;
  enum arch::RegType type;

  // TODO references into arrays & structs also include an index/scale
  // operand.  But we're only changing the beginning offset of the slot,
  // so those operands should be okay as-is.  Verify this is true.
  for(i = 0; i < NumOp(&instr); i++) {
    op = GetOp(&instr, i);
    offset = getStackOffset(frameSize, op);
    if(offset < 0 && !info.inCalleeSaved(offset)) {
      randOffset = info.getRandomizedOffset(offset);
      if(randOffset == INT32_MAX) return ret_t::BadMetadata;
      type = arch::getRegTypeDR(opnd_get_base(op));
      randRegOffset = slotOffsetFromRegister(frameSize, type, randOffset);
      opnd_set_disp(&op, randRegOffset);
      SetOp(&instr, i, op);
      doEncode = true;
      DEBUGMSG_VERBOSE(" -> Remap source stack offset " << offset << " -> "
                       << randOffset << std::endl);
    }
  }

  return ret_t::Success;
}

ret_t CodeTransformer::rewriteFunction(const function_record *func,
                                       const RandomizedFunction &info) {
  bool doEncode;
  int32_t offset, randOffset;
  uint32_t frameSize = arch::initialFrameSize();
  size_t count = 0;
  byte_iterator funcData = codeWindow.getData(func->addr);
  byte *start = funcData[0], *end = start + func->code_size, *instStart;
  instr_t instr;
  ret_t code;

  if(funcData.getLength() < func->code_size) {
    DEBUGMSG("Code length encoded in metadata larger than available size: "
             << funcData.getLength() << " vs. " << func->code_size
             << std::endl);
    return ret_t::BadMetadata;
  }

  if(!start) {
    DEBUGMSG("Invalid code iterator" << std::endl);
    return ret_t::RandomizeFailed;
  }

  // Note: we need to keep track of the frame's size as it gets expanded
  // (through the prologue) and shrunk (epilogue) so that we can canonicalize
  // stack slot references depending on the current offset

  instr_init(GLOBAL_DCONTEXT, &instr);
  do {
    instr_reset(GLOBAL_DCONTEXT, &instr);
    instStart = start;
    start = decode(GLOBAL_DCONTEXT, start, &instr);
    doEncode = false;

    DEBUG_VERBOSE(
      DEBUGMSG_VERBOSE(""); instr_disassemble(GLOBAL_DCONTEXT, &instr, 1);
      DEBUGMSG_VERBOSE_RAW(std::endl);
    )

    // Rewrite stack slot reference operands to their randomized locations
    code = rewriteOperands<instr_num_srcs, instr_get_src, instr_set_src>
                          (info, frameSize, instr, doEncode);
    if(code != ret_t::Success) return code;
    code = rewriteOperands<instr_num_dsts, instr_get_dst, instr_set_dst>
                          (info, frameSize, instr, doEncode);
    if(code != ret_t::Success) return code;

    // Keep track of updates to stack pointer (see note above) & rewrite stack
    // frame resizing operands to account for randomized slots
    if(instr_writes_to_reg(&instr,
                           arch::getDRRegType(arch::RegType::StackPointer),
                           DR_QUERY_DEFAULT)) {
      offset = arch::getFrameSizeUpdate(instr,
                                        info.getNonCalleeSaveSize(),
                                        doEncode);
      frameSize += offset;
      if(offset) DEBUGMSG_VERBOSE(" -> stack pointer update: " << offset
                                  << " (current size = " << frameSize << ")"
                                  << std::endl);
    }

    if(doEncode) {
      instStart = instr_encode(GLOBAL_DCONTEXT, &instr, instStart);
      if(instStart != start) return ret_t::EncodeFailed;
      count++;
    }
  } while(start < end);
  instr_free(GLOBAL_DCONTEXT, &instr);

  DEBUGMSG("Rewrote " << count << " instruction(s)" << std::endl);

  return ret_t::Success;
}

ret_t CodeTransformer::randomizeFunctions(const Binary::Section &codeSection,
                                          const Binary::Segment &codeSegment) {
  uintptr_t segStart, segEnd, secStart, secEnd, curAddr;
  ssize_t len, filelen;
  const void *data;
  ret_t code;
  MemoryRegionPtr r;

  // First order of business - set up the memory window to handle page faults.
  // Note: by construction of how we're adding regions we don't need to call
  // codeWindow.sort() to sort the regions within the window.

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

  // Finally, add any segment data/zeroed memory after the code section
  secEnd = secStart + len;
  curAddr = PAGE_UP(secEnd);
  len = curAddr - secEnd;
  filelen = binary.getRemainingFileSize(secEnd, codeSegment);
  data = binary.getData(secEnd, codeSegment);
  r.reset(new FileRegion(secEnd, len, filelen, data));
  codeWindow.insert(r);

  // Randomize every function for which we have transformation metadata
  Binary::func_iterator it = binary.getFunctions(secStart, secEnd);
  for(; !it.end(); ++it) {
    const function_record *func = *it;

    DEBUGMSG("Randomizing function @ " << std::hex << func->addr << ", size = "
             << std::dec << func->code_size << std::endl);

    RandomizedFunctionMap::iterator it =
      funcMaps.emplace(func->addr, RandomizedFunction()).first;
    code = it->second.randomize(binary, func, rng(), slotPadding);
    if(code != ret_t::Success) return code;
    code = rewriteFunction(func, it->second);
    if(code != ret_t::Success) return code;
  }

  return ret_t::Success;
}

