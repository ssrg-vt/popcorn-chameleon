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

int32_t CodeTransformer::canonicalizeSlotOffset(uint32_t frameSize,
                                                arch::RegType reg,
                                                int16_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer: return offset + arch::framePointerOffset();
  case arch::RegType::StackPointer: return -(frameSize - offset);
  default: return INT32_MAX;
  }
}

int32_t CodeTransformer::slotOffsetFromRegister(uint32_t frameSize,
                                                arch::RegType reg,
                                                int16_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer: return offset - arch::framePointerOffset();
  case arch::RegType::StackPointer: return frameSize - (-offset);
  default: return INT32_MAX;
  }
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
 * @param type output operand specifying base register type
 * @return the canonicalized offset represented as a negative number or >= 0 if
 *         not a stack slot reference
 */
static inline int getStackOffset(uint32_t frameSize,
                                 opnd_t op,
                                 arch::RegType &type) {
  // TODO Note: from dr_ir_opnd.h about opnd_get_disp():
  //   "On ARM, the displacement is always a non-negative value, and the
  //   presence or absence of #DR_OPND_NEGATED in opnd_get_flags() determines
  //   whether to add or subtract from the base register"
  int offset = 0;
  if(opnd_is_base_disp(op)) {
    type = arch::getRegTypeDR(opnd_get_base(op));
    offset = opnd_get_disp(op);
    offset = CodeTransformer::canonicalizeSlotOffset(frameSize, type, offset);
    if(offset >= 0 || (-offset) > frameSize) offset = 0;
  }
  return offset;
}

ret_t CodeTransformer::analyzeOperands(RandomizedFunctionPtr &info,
                                       uint32_t frameSize,
                                       instr_t *instr) {
  size_t i;
  int offset;
  opnd_t op;
  arch::RegType type;
  RandRestriction res;
  ret_t code = ret_t::Success;

  for(i = 0; i < instr_num_srcs(instr); i++) {
    op = instr_get_src(instr, i);
    offset = getStackOffset(frameSize, op, type);
    if(offset && arch::getRestriction(instr, op, res)) {
      res.offset = offset;
      if((code = info->addRestriction(res)) != ret_t::Success) return code;
    }
  }

  for(i = 0; i < instr_num_dsts(instr); i++) {
    op = instr_get_dst(instr, i);
    offset = getStackOffset(frameSize, op, type);
    if(offset && arch::getRestriction(instr, op, res)) {
      res.offset = offset;
      if((code = info->addRestriction(res)) != ret_t::Success) return code;
    }
  }

  return code;
}

// TODO 1: we currently assume the compiler generates references to stack slots
// independently of other stack slots, i.e., it doesn't generate intermediate
// values which are then used to generate references to 2 or more slots.  This
// may not be true with increasing optimization levels, see X86OptimizeLEAs.cpp
// in newer versions of LLVM.
// TODO 2: references into arrays & structs also include an index and scale
// operand.  But we're only changing the beginning offset of the slot, so those
// operands should be okay as-is.  Verify this is true.
template<int (*NumOp)(instr_t *),
         opnd_t (*GetOp)(instr_t *, unsigned),
         void (*SetOp)(instr_t *, unsigned, opnd_t)>
ret_t CodeTransformer::rewriteOperands(const RandomizedFunctionPtr &info,
                                       uint32_t frameSize,
                                       uint32_t newFrameSize,
                                       instr_t *instr,
                                       bool &changed) {
  size_t i;
  int32_t offset, randOffset, randRegOffset;
  opnd_t op;
  enum arch::RegType type;

  for(i = 0; i < NumOp(instr); i++) {
    op = GetOp(instr, i);
    offset = getStackOffset(frameSize, op, type);
    if(offset && info->transformOffset(offset)) {
      randOffset = info->getRandomizedOffset(offset);
      if(randOffset == INT32_MAX) {
        DEBUG(
          DEBUGMSG("Couldn't find slot for offset " << offset << " in ");
          instr_disassemble(GLOBAL_DCONTEXT, instr, STDERR);
          DEBUGMSG_RAW(std::endl);
        )
        return ret_t::BadMetadata;
      }
      randRegOffset = slotOffsetFromRegister(newFrameSize, type, randOffset);
      opnd_set_disp_ex(&op, randRegOffset, false, false, false);
      SetOp(instr, i, op);
      changed = true;

      DEBUGMSG(" -> remap stack offset " << offset << " -> " << randOffset
               << std::endl);
    }
  }

  return ret_t::Success;
}

ret_t CodeTransformer::rewriteFunction(const function_record *func,
                                       RandomizedFunctionPtr &info) {
  bool doEncode, changed;
  int32_t update, offset, randOffset;
  uint32_t frameSize = arch::initialFrameSize(),
           rewrittenFrameSize = arch::initialFrameSize(),
           count = 0;
  RandRestriction res;
  byte_iterator funcData = codeWindow.getData(func->addr);
  byte *start = funcData[0], *end = start + func->code_size;
  instrlist_t *instrs;
  instr_t *instr;
  reg_id_t drsp;
  ret_t code = ret_t::Success;

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

  // Construct a list of instructions & analyze for restrictions
  instrs = instrlist_create(GLOBAL_DCONTEXT);
  drsp = arch::getDRRegType(arch::RegType::StackPointer);
  while(start < end) {
    instr = instr_create(GLOBAL_DCONTEXT);
    instr_init(GLOBAL_DCONTEXT, instr);
    start = decode(GLOBAL_DCONTEXT, start, instr);
    instrlist_append(instrs, instr);

    code = analyzeOperands(info, frameSize, instr);
    if(code != ret_t::Success) goto out;

    // Check if possible to rewrite frame allocation instructions with a random
    // size; if not, mark the associated stack slot as immovable.  To determine
    // the associated slot, keep track of the frame's size as it's expanded
    // (prologue) and shrunk (epilogue) to canonicalize stack slot references.
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        DEBUG (
          DEBUGMSG("");
          instr_disassemble(GLOBAL_DCONTEXT, instr, STDERR);
          DEBUGMSG_RAW(std::endl);
          DEBUGMSG(" -> stack pointer update: " << update
                   << " (current size = " << frameSize + update << ")"
                   << std::endl);
        )

        if(arch::getRestriction(instr, res)) {
          // If growing the frame, the referenced slot includes the update
          // whereas if we're shrinking the frame it doesn't.
          offset = (update > 0) ? update : 0;
          offset = canonicalizeSlotOffset(frameSize + offset,
                                          arch::RegType::StackPointer, 0);
          res.offset = offset;
          res.size = abs(update);
          res.alignment = update;
          if((code = info->addRestriction(res)) != ret_t::Success) goto out;
        }
        frameSize += update;
      }
    }
  }

  if(frameSize != arch::initialFrameSize()) {
    DEBUGMSG("Function at 0x" << std::hex << func->addr
             << " does not clean up frame (not intended to return?)" << std::endl);
    frameSize = arch::initialFrameSize();
  }

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("");
    instrlist_disassemble(GLOBAL_DCONTEXT, (app_pc)func->addr, instrs, STDERR);
  )

  // Randomize the function's layout according to the metadata
  code = info->randomize(rng(), slotPadding);
  if(code != ret_t::Success) goto out;

  // Apply the randomization by rewriting instructions
  instr = instrlist_first(instrs);
  doEncode = false;
  while(instr) {
    changed = false;

    // Rewrite stack slot reference operands to their randomized locations
    code = rewriteOperands<instr_num_srcs, instr_get_src, instr_set_src>
                          (info, frameSize, rewrittenFrameSize, instr, changed);
    if(code != ret_t::Success) goto out;
    code = rewriteOperands<instr_num_dsts, instr_get_dst, instr_set_dst>
                          (info, frameSize, rewrittenFrameSize, instr, changed);
    if(code != ret_t::Success) goto out;

    // Keep track of stack pointer updates & rewrite frame update instructions
    // with randomized size
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        offset = (update > 0) ? update : 0;
        offset = canonicalizeSlotOffset(frameSize + offset,
                                        arch::RegType::StackPointer, 0);
        if(info->transformBulkFrameUpdate(offset)) {
          assert((-offset) <= func->frame_size);
          offset = info->getRandomizedBulkFrameUpdate();
          offset = update > 0 ? offset : -offset;
          code = arch::rewriteFrameUpdate(instr, offset, changed);
          if(code != ret_t::Success) goto out;
          rewrittenFrameSize += offset;

          DEBUGMSG(" -> rewrite frame update: " << update << " -> " << offset
                   << std::endl);
        }
        else rewrittenFrameSize += update;
        frameSize += update;
      }
    }

    if(changed) {
      count++;
      DEBUG(
        DEBUGMSG(" -> rewrote: ");
        instr_disassemble(GLOBAL_DCONTEXT, instr, STDERR);
        DEBUGMSG_RAW(std::endl);
      )
    }

    doEncode |= changed;
    instr = instr_get_next(instr);
  }

  DEBUGMSG("Rewrote " << count << " instruction(s)" << std::endl);

  if(doEncode) {
    // TODO should has_instr_jmp_targets (last argument) be true?
    start = instrlist_encode(GLOBAL_DCONTEXT, instrs, funcData[0], false);
    if(!start || start != end) {
      DEBUGMSG("Expected end = " << std::hex << (void *)end << " but got "
               << (void *)start << std::endl);
      code = ret_t::RandomizeFailed;
    }
  }

out:
  instrlist_clear_and_destroy(GLOBAL_DCONTEXT, instrs);
  return code;
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

    RandomizedFunctionPtr info = arch::getRandomizedFunction(binary, func);
    RandomizedFunctionMap::iterator it =
      funcMaps.emplace(func->addr, std::move(info)).first;
    code = rewriteFunction(func, it->second);
    if(code != ret_t::Success) return code;
  }

  return ret_t::Success;
}

