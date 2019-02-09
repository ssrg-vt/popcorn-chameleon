#include <csignal>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/userfaultfd.h>

#include "transform.h"
#include "utils.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// Fault handling
///////////////////////////////////////////////////////////////////////////////

static std::vector<unsigned char> intPage(PAGESZ);

/**
 * Handle a fault, including mapping in the correct data and randomizing any
 * code pieces.
 *
 * @param CT code transformer
 * @param uffd userfaultfd file descriptor for user-space fault handling
 * @param msg description of faulting region
 * @param pageBuf a page-sized buffer used to hold page data
 * @return a return code describing the outcome
 */
static inline ret_t handleFault(CodeTransformer *CT,
                                int uffd,
                                const struct uffd_msg &msg,
                                std::vector<char> &pageBuf) {
  uintptr_t pageAddr = msg.arg.pagefault.address, data;
  ret_t code = ret_t::Success;

  assert(msg.event == UFFD_EVENT_PAGEFAULT && "Invalid message type");
  assert(!(pageAddr & (PAGESZ - 1)) && "Fault address not page-aligned");
  DEBUGMSG(CT->getProcessPid() << ": handling fault @ 0x" << std::hex
           << pageAddr << ", flags=" << msg.arg.pagefault.flags << ", ptid="
           << std::dec << msg.arg.pagefault.feat.ptid << std::endl);

  DEBUG_VERBOSE(
    // Print the PC causing the fault.  We can't directly interrupt/read child
    // state (handler isn't the tracer), so poke the child with a signal to get
    // the tracer to print information (SIGTRAP will get masked by chameleon).
    Process &theProc = CT->getProcess();
    if(theProc.signalProcess(SIGTRAP) == ret_t::Success);
    // TODO ROB the main thread's printing races with the fault handler's
    // printing, leading to garbled output.  Synchronize better than sleeping.
    struct timespec time = { 0, 10000000 };
    nanosleep(&time, nullptr);
  )

  if(CT->shouldServeIntPage()) data = (uintptr_t)&intPage[0];
  else if(!(data = CT->zeroCopy(pageAddr))) {
    if((code = CT->project(pageAddr, pageBuf)) != ret_t::Success) return code;
    data = (uintptr_t)&pageBuf[0];
  }

  if(!uffd::copy(uffd, data, pageAddr)) code = ret_t::UffdCopyFailed;

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
  size_t nfaults = CT->getNumFaultsBatched(), toHandle, i, handled = 0;
  ssize_t bytesRead;
  pid_t me = syscall(SYS_gettid), cpid = CT->getProcessPid();
  struct uffd_msg *msg = new struct uffd_msg[nfaults];
  Timer t;
  std::vector<char> pageBuf(PAGESZ);

  assert(CT && "Invalid CodeTransformer object");
  assert(uffd >= 0 && "Invalid userfaultfd file descriptor");
  assert(msg && "Page fault message buffer allocation failed");
  CT->setFaultHandlerPid(me);

  DEBUGMSG("chameleon thread " << me << " is handling faults for " << cpid
           << ", reading from uffd=" << uffd << ", batching " << nfaults
           << " fault(s)" << std::endl);

  while(!CT->shouldFaultHandlerExit()) {
    bytesRead = read(uffd, msg, sizeof(struct uffd_msg) * nfaults);
    if(bytesRead >= 0) {
      t.start();
      toHandle = bytesRead / sizeof(struct uffd_msg);
      for(i = 0; i < toHandle; i++) {
        // TODO for Linux 4.11+, handle UFFD_EVENT_FORK, UFFD_EVENT_REMAP,
        // UFFD_EVENT_REMOVE, UFFD_EVENT_UNMAP
        if(msg[i].event != UFFD_EVENT_PAGEFAULT) continue;
        if(handleFault(CT, uffd, msg[i], pageBuf) != ret_t::Success) {
          INFO("could not handle fault, limping ahead..." << std::endl);
          continue;
        }
        handled++;
      }
      t.end(true);
      DEBUGMSG_VERBOSE("fault handling time: " << t.elapsed(Timer::Micro)
                       << " us for " << toHandle << " fault(s)" << std::endl);
    }
    else if(errno != EINTR) DEBUGMSG("read failed (return=" << bytesRead
                                     << "), trying again..." << std::endl);
  }
  delete [] msg;

  DEBUGMSG("fault handler " << me << " exiting" << std::endl);
  INFO(cpid << ": fault handling: " << t.totalElapsed(Timer::Micro)
       << " us for " << handled << " fault(s)" << std::endl);

  return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// Re-randomizing code
///////////////////////////////////////////////////////////////////////////////

void *randomizeCodeAsync(void *arg) {
  size_t scrambles = 0;
  CodeTransformer *CT = (CodeTransformer *)arg;
  sem_t *randomize = CT->getScrambleSem(),
        *finished = CT->getFinishedScrambleSem();
  pid_t me = syscall(SYS_gettid), cpid = CT->getProcessPid();
  MemoryWindow &nextCode = CT->getNextCodeWindow();
  Timer t;
  ret_t code;

  CT->setScramberPid(me);
  sem_wait(randomize);

  DEBUGMSG("chameleon thread " << me << " is scrambling code for " << cpid
           << std::endl);

  while(!CT->shouldScramblerExit()) {
    t.start();

    nextCode.copy(CT->getCodeWindow());
    code = CT->randomizeFunctions(nextCode);
    // TODO need to signal handler something bad happened, this will deadlock
    if(code != ret_t::Success) break;
    scrambles++;

    t.end(true);
    DEBUGMSG_VERBOSE("code randomization time: " << t.elapsed(Timer::Micro)
                     << std::endl);

    sem_post(finished);
    sem_wait(randomize);
  }

  DEBUGMSG("scrambler " << me << " exiting" << std::endl);
  INFO(cpid << ": async code randomization: " << t.totalElapsed(Timer::Micro)
       << " us for " << scrambles << " randomization(s)" << std::endl);

  return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// CodeTransformer implementation
///////////////////////////////////////////////////////////////////////////////

void CodeTransformer::initialize() { arch::setInterruptInstructions(intPage); }

ret_t CodeTransformer::initialize(bool randomize, bool remap) {
  ret_t retcode;

  if(batchedFaults != 1) {
    DEBUGMSG("currently can only handle 1 fault at a time" << std::endl);
    return ret_t::InvalidTransformConfig;
  }

  // Try to give the user some warning for excessive stack padding
  if(slotPadding >= PAGESZ)
    WARN("Large padding added between slots: " << slotPadding << std::endl);

  // Initialize code & randomize (if requested) to serve initial faults
  const Binary::Section &codeSec = binary.getCodeSection();
  const Binary::Segment &codeSeg = binary.getCodeSegment();
  retcode = populateCodeWindow(codeSec, codeSeg);
  if(retcode != ret_t::Success) return retcode;
  if(randomize) {
    rewriteMetadata = st_init(binary.getFilename());
    if(!rewriteMetadata) return ret_t::BadTransformMetadata;
    retcode = analyzeFunctions();
    if(retcode != ret_t::Success) return retcode;
    retcode = randomizeFunctions(codeWindow);
    if(retcode != ret_t::Success) return retcode;
  }

  // Prepare the code region inside the child by setting up correct page
  // permissions and registering it with the userfaultfd file descriptor
  if(remap) retcode = remapCodeSegment(codeSec.address(), codeSec.size());
  else retcode = dropCode();
  if(retcode != ret_t::Success) return retcode;
  retcode = proc.stealUserfaultfd();
  if(retcode != ret_t::Success) return retcode;
  if(!uffd::api(proc.getUserfaultfd(), nullptr, nullptr))
    return ret_t::UffdHandshakeFailed;
  if(!uffd::registerRegion(proc.getUserfaultfd(),
                           codeSec.address(),
                           codeSec.size()))
    return ret_t::UffdRegisterFailed;

  // Set up a buffer for transforming the child's stack
  const urange_t &bounds = proc.getStackBounds();
  size_t stackSize = bounds.second - bounds.first;
  stackMem.reset(new unsigned char[stackSize]);

  // Initialize thread for handling faults
  if(pthread_create(&faultHandler, nullptr, handleFaultsAsync, this))
    return ret_t::FaultHandlerFailed;

  // Initialize thread re-randomizing code
  if(sem_init(&scramble, 0, 1) || sem_init(&finishedScrambling, 0, 0))
    return ret_t::ScramblerFailed;
  if(pthread_create(&scrambler, nullptr, randomizeCodeAsync, this))
    return ret_t::ScramblerFailed;

  return ret_t::Success;
}

ret_t CodeTransformer::cleanup() {
  pid_t pid = proc.getPid();

  faultHandlerExit = true;
  proc.detach(); // detaching closes the userfaultfd file descriptor
  if(faultHandlerPid > 0) {
    // Interrupt the fault handling thread if the thread was already blocking
    // on a read before closing the userfaultfd file descriptor
    pthread_kill(faultHandler, SIGINT);
    pthread_join(faultHandler, nullptr);
  }

  scramblerExit = true;
  if(scramblerPid > 0) {
    sem_post(&scramble);
    pthread_join(scrambler, nullptr);
  }

  INFO(pid << ": switching to new randomization: " << rerandomizeTime
       << " us for " << numRandomizations << " randomizations" << std::endl);

  return ret_t::Success;
}

static func_rand_info getFunctionInfoCallback(void *rawCT, uintptr_t addr) {
  CodeTransformer *CT = (CodeTransformer *)rawCT;
  RandomizedFunction *info;
  func_rand_info cinfo;
  cinfo.old_frame_size = UINT64_MAX;

  info = CT->getRandomizedFunctionInfo(addr);
  if(info) {
    auto &oldSlots = info->getPrevRandSlots();
    auto &newSlots = info->getRandomizedSlots();
    cinfo.old_frame_size = info->getPrevRandFrameSize();
    cinfo.new_frame_size = info->getRandomizedFrameSize();
    cinfo.num_old_slots = oldSlots.size();
    cinfo.old_rand_slots = (const slotmap *)&oldSlots[0];
    cinfo.num_new_slots = newSlots.size();
    cinfo.new_rand_slots = (const slotmap *)&newSlots[0];
  }
  else memset(&cinfo, 0, sizeof(cinfo));

  return cinfo;
}

ret_t CodeTransformer::rerandomize() {
  uintptr_t sp, rawBuf, mid, childSrcBase, bufSrcBase,
            childDstBase, bufDstBase;
  size_t stackSize;
  ret_t code;
  Timer t;

  assert(proc.traceable() && "Invalid process state");
  t.start();

  // We only have metadata at transformation points, advance the child to a
  // transformation point where the stack transformation can bootstrap.
  if((code = advanceToTransformationPoint(t)) != ret_t::Success) return code;

  // Read in the child's current stack.  We currently divide the stack into 2
  // halves and rewrite from one half to the other.
  if(!(sp = proc.getSP())) return ret_t::PtraceFailed;
  const urange_t &stackBounds = proc.getStackBounds();
  assert(sp >= stackBounds.first && sp < stackBounds.second
         && "Invalid stack pointer");
  stackSize = stackBounds.second - stackBounds.first;
  mid = (stackBounds.first + stackBounds.second) / 2;
  rawBuf = (uintptr_t)stackMem.get();
  if(sp >= mid) { // Currently using top half
    bufSrcBase = rawBuf + stackSize;
    childSrcBase = stackBounds.second;
    bufDstBase = rawBuf + (stackSize / 2);
    childDstBase = mid;
    stackSize = stackBounds.second - sp;
  }
  else { // Currently using bottom half
    bufSrcBase = rawBuf + (stackSize / 2);
    childSrcBase = mid;
    bufDstBase = rawBuf + stackSize;
    childDstBase = stackBounds.second;
    stackSize = mid - sp;
  }
  byte_iterator stackBuf((unsigned char *)rawBuf + (sp - stackBounds.first),
                         stackSize);
  code = proc.readRegion(sp, stackBuf);
  if(code != ret_t::Success) return code;

  // Wait for code re-randomizer to finish and set the current code buffer to
  // the newly randomized code
  if(sem_wait(&finishedScrambling)) return ret_t::RandomizeFailed;
  codeWindow = nextCodeWindow;

  // Transform the stack, including switching to the transformed stack
  code = arch::transformStack(this, getFunctionInfoCallback, rewriteMetadata,
                              childSrcBase, bufSrcBase,
                              childDstBase, bufDstBase, sp);
  if(code != ret_t::Success) return ret_t::TransformFailed;

  stackSize = childDstBase - sp;
  stackBuf = byte_iterator((unsigned char *)rawBuf + (sp - stackBounds.first),
                           stackSize);
  code = proc.writeRegion(sp, stackBuf);
  if(code != ret_t::Success) return code;

  if((code = dropCode()) != ret_t::Success) return code;
  if(sem_post(&scramble)) return ret_t::RandomizeFailed;

  t.end(true);
  numRandomizations++;
  rerandomizeTime += t.totalElapsed(Timer::Micro);

  return ret_t::Success;
}

RandomizedFunction *
CodeTransformer::getRandomizedFunctionInfo(uintptr_t pc) const {
  const function_record *fr;
  RandomizedFunctionMap::const_iterator func;

  fr = binary.getFunction(pc);
  if(fr) {
    func = funcMaps.find(fr->addr);
    if(func != funcMaps.end()) return func->second.get();
  }
  return nullptr;
}

/* Adjust offset based on stack growth direction */
#if STACK_DIRECTION == DOWN
# define DIRECTION( offset ) (-(offset))
#else
# define DIRECTION( offset ) (offset)
#endif

int32_t CodeTransformer::canonicalizeSlotOffset(uint32_t frameSize,
                                                arch::RegType reg,
                                                int32_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer:
    return DIRECTION(arch::framePointerOffset() + offset);
  case arch::RegType::StackPointer:
    return (int32_t)frameSize + DIRECTION(offset);
  default: return INT32_MAX;
  }
}

int32_t CodeTransformer::slotOffsetFromRegister(uint32_t frameSize,
                                                arch::RegType reg,
                                                int32_t offset) {
  switch(reg) {
  case arch::RegType::FramePointer:
    return DIRECTION(offset) - arch::framePointerOffset();
  case arch::RegType::StackPointer:
    return DIRECTION(offset - (int32_t)frameSize);
  default: return INT32_MAX;
  }
}

ret_t
CodeTransformer::sprayTransformBreakpoints(const RandomizedFunction *info,
                     std::unordered_map<uintptr_t, uint64_t> &origData,
                     size_t &interruptSize) const {
  uint64_t interrupt, mask, tmp;
  auto &addrs = info->getTransformAddrs();
  origData.clear();
  ret_t code;

  DEBUG(
    if(addrs.size() > 100)
      DEBUGMSG(addrs.size() << " transformation points in function at 0x"
               << std::hex << info->getFunctionRecord()->addr << ", may "
               "harm performance" << std::endl);
  )

  // TODO overwriting return instructions can inadvertently overwrite the start
  // of other functions, may race with other threads spraying start of function
  // (if added as transform point)
  interrupt = arch::getInterruptInst(mask, interruptSize);
  for(auto addr = addrs.begin(); addr != addrs.end(); addr++) {
    uint64_t &data = origData[addr->first];
    code = proc.read(addr->first, data);
    if(code != ret_t::Success) return code;
    tmp = (data & mask) | interrupt;
    code = proc.write(addr->first, tmp);
    if(code != ret_t::Success) return code;
  }

  return ret_t::Success;
}

ret_t
CodeTransformer::restoreTransformBreakpoints(const RandomizedFunction *info,
               const std::unordered_map<uintptr_t, uint64_t> &origData) const {
  ret_t code = ret_t::Success;
  for(auto data = origData.begin(); data != origData.end(); data++) {
    code = proc.write(data->first, data->second);
    if(code != ret_t::Success) break;
  }
  return code;
}

ret_t CodeTransformer::advanceToTransformationPoint(Timer &t) const {
  typedef chameleon::RandomizedFunction::TransformType TransformType;
  uintptr_t pc;
  size_t interruptSize;
  const RandomizedFunction *info;
  const function_record *fr;
  TransformType type;
  std::unordered_map<uintptr_t, uint64_t> origData;
  ret_t code;
#ifdef DEBUG_BUILD
  pid_t cpid = proc.getPid();
#endif

  if(!(pc = proc.getPC())) return ret_t::PtraceFailed;
  info = getRandomizedFunctionInfo(pc);
  if(!info) return ret_t::NoTransformMetadata;
  fr = info->getFunctionRecord();

  // Make sure the child is at a transformation point.  Either it's already
  // there (lucky!) or we have to forcibly advance it to one.  All
  // transformation points should be at the point where a function has just
  // been called or is returning, allowing us to bootstrap transformation.
  if(pc != fr->addr &&
     (type = info->getTransformationType(pc)) == TransformType::None) {
    DEBUGMSG_VERBOSE(cpid << ": inserting transformation breakpoints inside "
                     "function at 0x" << std::hex << fr->addr << std::endl);

    // Insert traps at transformation breakpoints & kick child towards them
    code = sprayTransformBreakpoints(info, origData, interruptSize);
    if(code != ret_t::Success) return code;

    t.end(true);
    if((code = proc.continueToNextSignal()) != ret_t::Success) return code;
    t.start();

    // Figure out where the child stopped and restore the original instructions
    if(code != ret_t::Success) return code;
    else if(!proc.traceable()) return ret_t::InvalidState;
    pc = proc.getPC() - interruptSize;
    type = info->getTransformationType(pc);
    if(type == TransformType::None) return ret_t::TransformFailed;
    if((code = proc.setPC(pc)) != ret_t::Success) return code;
    code = restoreTransformBreakpoints(info, origData);
    if(code != ret_t::Success) return code;

    DEBUGMSG_VERBOSE(cpid << ": stopped at transformation point at 0x"
                     << std::hex << pc << std::endl);

    // If we stopped at a call instruction, walk it into the called function
    // in preparation for transformation
    if(type == TransformType::CallSite)
      if((code = proc.singleStep()) != ret_t::Success) return code;
  }

  return ret_t::Success;
}

instr_t *
CodeTransformer::getInstruction(uintptr_t pc, RandomizedFunction *info) const {
  uintptr_t start;
  instr_t *instr;
  const function_record *fr;

  assert(info && "Invalid randomization information object");
  fr = info->getFunctionRecord();
  if(!funcContains(fr, pc)) return nullptr;

  start = fr->addr;
  instr = instrlist_first(info->getInstructions());
  while(instr && start < pc) {
    start += instr_length(GLOBAL_DCONTEXT, instr);
    instr = instr_get_next(instr);
  }
  if(start != pc) return nullptr;

  return instr;
}

ret_t CodeTransformer::writePage(uintptr_t start) {
  byte *pageData;
  std::vector<char> pageBuf;
  ret_t code;
#ifdef DEBUG_BUILD
  struct parasite_ctl *parasite = proc.getParasiteCtl();
  uintptr_t origStart = PAGE_DOWN(start);
#endif

  assert(parasite && "Invalid parasite control handle");

  start = PAGE_DOWN(start);
  if(!(pageData = (byte *)zeroCopy(start))) {
    pageBuf.resize(PAGESZ);
    if((code = project(start, pageBuf)) != ret_t::Success) return code;
    pageData = (byte *)&pageBuf[0];
  }

  byte_iterator buf(pageData, PAGESZ);
  if((code = proc.writeRegion(start, buf)) != ret_t::Success) return code;

  DEBUGMSG(proc.getPid() << ": manually rewrote page @ 0x" << std::hex
           << origStart << std::endl);

  return ret_t::Success;
}

ret_t CodeTransformer::remapCodeSegment(uintptr_t start, uint64_t len) {
  uintptr_t pageStart;
  size_t roundedLen;
  int prot, flags;
  long mmapRet;
  struct parasite_ctl *parasite = proc.getParasiteCtl();
  ret_t code;
  Timer t;

  assert(parasite && "Invalid parasite control handle");

  t.start();

  // TODO: for some reason mmap fails unless we do a dummy syscall.  The
  // syscall touches a page, maybe the page needs to be brought in before we
  // can do mmap? ¯\_(ツ)_/¯
  if(parasite::syscall(parasite, SYS_getpid, mmapRet) != ret_t::Success)
    return ret_t::CompelActionFailed;

  DEBUGMSG(proc.getPid() << ": changing code section to anonymous "
           "private mapping for userfaultfd" << std::endl);

  // compel injects instructions to cause a signal and regain control
  // post-syscall, but the mmap here causes the kernel to clobber the those
  // instructions with a zero page.  Upon returning to user-space, the child
  // causes a segfault; just mask the error.
  pageStart = PAGE_DOWN(start);
  roundedLen = PAGE_ALIGN_LEN(start, len);
  prot = PROT_EXEC | PROT_READ;
  flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
  parasite::syscall(parasite, SYS_mmap, mmapRet, pageStart, roundedLen, prot,
                    flags, -1, 0);
  if((uintptr_t)mmapRet != pageStart) return ret_t::RemapCodeFailed;

  DEBUGMSG(proc.getPid() << ": remapped 0x" << std::hex << pageStart << " - 0x"
           << (pageStart + roundedLen) << std::endl);

  // compel touched a page by injecting instructions, so it won't get served
  // by userfaultfd (the kernel served a zero page); manually rewrite it here.
  code = writePage(PAGE_DOWN(parasite::infectAddress(parasite)));
  if(code != ret_t::Success) return code;

  t.end();
  INFO(proc.getPid() << ": code re-mapping: " << t.elapsed(Timer::Micro)
       << " us" << std::endl);

  return ret_t::Success;
}

ret_t CodeTransformer::dropCode() {
  long ret;
  struct parasite_ctl *parasite = proc.getParasiteCtl();
  ret_t code;

  assert(parasite && "Invalid parasite control handle");

  DEBUGMSG(proc.getPid() << ": dropping code pages 0x" << std::hex
           << PAGE_DOWN(codeStart) << " - 0x" << PAGE_UP(codeEnd)
           << std::endl);

  // TODO BANDAGE! compel's APIs restore the thread context from when it was
  // initialized, not from when we do a syscall
  struct user_regs_struct regs;
  if((code = proc.readRegs(regs)) != ret_t::Success) return code;

  // The child executes madvise(), which drops the code pages.  When returning
  // to userspace, the child causes a page fault.  Because the code section has
  // been changed to use anonymous private pages, one of two things happens:
  //
  // 1. If we haven't yet attached a userfaultfd, the kernel serves a zero page
  // 2. If we have attached a userfaultfd, we get to handle the fault
  //
  // Regardless, we want the child to stop directly after the call.  In the
  // first case, the child will segfault, which we can mask.  In order to make
  // the second case look like the first, set a flag informing the fault
  // handling thread to serve a zero page similar to the first case.  Because
  // the child immediately segfaults after the page fault handling,
  // parasite::syscall() returns an error; just ignore it.
  __atomic_store_n(&serveInt, true, __ATOMIC_RELEASE);
  parasite::syscall(parasite, SYS_madvise, ret, PAGE_DOWN(codeStart),
                    PAGE_UP(codeEnd - codeStart), MADV_DONTNEED);
  if(ret) return ret_t::DropCodeFailed;
  __atomic_store_n(&serveInt, false, __ATOMIC_RELEASE);

  // TODO BANDAGE! compel's APIs restore the thread context from when it was
  // initialized, not from when we do a syscall
  if((code = proc.writeRegs(regs)) != ret_t::Success) return code;

  // As previously mentioned, the kernel served a zero page; manually rewrite
  // it with actual instructions.
  code = writePage(PAGE_DOWN(parasite::infectAddress(parasite)));
  if(code != ret_t::Success) return code;

  return ret_t::Success;
}

ret_t CodeTransformer::populateCodeWindow(const Binary::Section &codeSection,
                                          const Binary::Segment &codeSegment) {
  uintptr_t segStart, curAddr;
  ssize_t len, filelen;
  byte_iterator data;
  MemoryRegionPtr r;
  Timer t;

  DEBUGMSG("populating memory window with code for rewriting" << std::endl);
  t.start();

  // Note: by construction of how we're adding regions we don't need to call
  // codeWindow.sort() to sort the regions within the window.

  // Calculate the first address we care about. Note that we *only* care about
  // pages with code, i.e., the code segment may contain other sections that
  // are on different pages that don't concern us.
  codeWindow.clear();
  segStart = codeSegment.address();
  codeStart = codeSection.address();
  curAddr = std::max<uintptr_t>(PAGE_DOWN(codeStart), segStart);

  // First, check if the segment contains data before the code section.  Note
  // that the region must be entirely contained on-disk (i.e., no zero-filled
  // region so file length = memory length) because segments can't have holes
  // and we know the subsequent code section *must* be on-disk.
  len = codeStart - curAddr;
  if(len > 0) {
    if(binary.getRemainingFileSize(curAddr, codeSegment) <= (size_t)len) {
      WARN("Invalid file format - found holes in segment" << std::endl);
      return ret_t::InvalidElf;
    }
    data = binary.getData(curAddr, codeSegment);
    if(!data) return ret_t::MarshalDataFailed;
    r.reset(new FileRegion(curAddr, len, len, data));
    codeWindow.insert(r);
  }
  else if(len != 0) {
    WARN("Invalid file format - segment start address is after code section "
         "start address" << std::endl);
    return ret_t::InvalidElf;
  }

  // Now, add a region for the code section
  len = codeSection.size();
  filelen = binary.getRemainingFileSize(codeStart, codeSegment);
  if(filelen < len)
    WARN("Code section on-disk smaller than in-memory representation ("
         << filelen << " vs " << codeSection.size() << " bytes)" << std::endl);
  data = binary.getData(codeStart, codeSegment);
  if(!data) return ret_t::MarshalDataFailed;
  r.reset(new BufferedRegion(codeStart, len, filelen, data));
  codeWindow.insert(r);

  // Finally, add any segment data/zeroed memory after the code section
  codeEnd = codeStart + len;
  curAddr = PAGE_UP(codeEnd);
  len = curAddr - codeEnd;
  filelen = binary.getRemainingFileSize(codeEnd, codeSegment);
  data = binary.getData(codeEnd, codeSegment);
  r.reset(new FileRegion(codeEnd, len, filelen, data));
  codeWindow.insert(r);

  t.end();
  INFO(proc.getPid() << ": code buffer setup: " << t.elapsed(Timer::Micro)
       << " us" << std::endl);

  return ret_t::Success;
}

/**
 * Return the canonicalized stack offset of an operand if it's a base +
 * displacement memory reference into the stack.  If it's not a memory
 * reference or not a reference to the stack, return 0.
 *
 * @param frameSize current frame size as we're walking through the function
 * @param op a DynamoRIO operand
 * @param type output operand specifying base register type
 * @return the canonicalized offset or 0 if not a stack slot reference
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
    if(offset <= 0 || offset > (int)frameSize) offset = 0;
  }
  return offset;
}

template<int (*NumOp)(instr_t *),
         opnd_t (*GetOp)(instr_t *, unsigned)>
ret_t CodeTransformer::analyzeOperands(RandomizedFunctionPtr &info,
                                       uint32_t frameSize,
                                       instr_t *instr) {
  int i, offset;
  opnd_t op;
  arch::RegType type;
  RandRestriction res;
  ret_t code = ret_t::Success;

  for(i = 0; i < NumOp(instr); i++) {
    op = GetOp(instr, i);
    offset = getStackOffset(frameSize, op, type);
    if(offset && arch::getRestriction(instr, op, res)) {
      res.offset = offset;
      if((code = info->addRestriction(res)) != ret_t::Success) return code;
    }
  }

  return ret_t::Success;
}

ret_t CodeTransformer::analyzeFunction(RandomizedFunctionPtr &info) {
  int32_t update, offset;
  uint32_t frameSize = arch::initialFrameSize();
  size_t instrSize;
  const function_record *func = info->getFunctionRecord();
  byte_iterator funcData = codeWindow.getData(func->addr);
  byte *real = (byte *)func->addr, *cur = funcData[0], *prev,
       *end = cur + func->code_size;
  instrlist_t *instrs;
  instr_t *instr;
  reg_id_t drsp;
  RandRestriction res;
  ret_t code = ret_t::Success;

  if(funcData.getLength() < func->code_size) {
    DEBUGMSG("code length encoded in metadata larger than available size: "
             << funcData.getLength() << " vs. " << func->code_size
             << std::endl);
    return ret_t::BadTransformMetadata;
  }

  if(!cur) {
    DEBUGMSG("invalid code iterator" << std::endl);
    return ret_t::RandomizeFailed;
  }

  // Construct a list of instructions & analyze for restrictions.
  // instr_create() allocates the instruction on DynamoRIO's heap; the info
  // object will be given ownership of the instructions after analysis and will
  // free them as needed.
  instrs = instrlist_create(GLOBAL_DCONTEXT);
  drsp = arch::getDRRegType(arch::RegType::StackPointer);
  while(cur < end) {
    prev = cur;
    instr = instr_create(GLOBAL_DCONTEXT);
    instr_init(GLOBAL_DCONTEXT, instr);
    cur = decode_from_copy(GLOBAL_DCONTEXT, cur, real, instr);
    if(!cur) {
      code = ret_t::AnalysisFailed;
      goto out;
    }
    instrSize = cur - prev;
    instr_set_raw_bits(instr, prev, instrSize);
    instrlist_append(instrs, instr);

    DEBUG_VERBOSE(DEBUGMSG_INSTR("size = " << instrSize << ": ", instr);)

    // Record addresses of transformation points
    if(instr_is_call(instr)) {
      DEBUGMSG_VERBOSE(" -> transformation point (0x" << std::hex
                       << (uintptr_t)real << ")" << std::endl);
      info->addTransformAddr((uintptr_t)real, RandomizedFunction::CallSite);
    }
    else if(instr_is_return(instr)) {
      DEBUGMSG_VERBOSE(" -> transformation point (0x" << std::hex
                       << (uintptr_t)real << ")" << std::endl);
      info->addTransformAddr((uintptr_t)real, RandomizedFunction::Return);
    }

    real += instrSize;

    code = analyzeOperands<instr_num_srcs, instr_get_src>
                          (info, frameSize, instr);
    if(code != ret_t::Success) goto out;
    code = analyzeOperands<instr_num_dsts, instr_get_dst>
                          (info, frameSize, instr);
    if(code != ret_t::Success) goto out;

    // Check if possible to rewrite frame allocation instructions with a random
    // size; if not, mark the associated stack slot as immovable.  To determine
    // the associated slot, keep track of the frame's size as it's expanded
    // (prologue) and shrunk (epilogue) to canonicalize stack slot references.
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        DEBUGMSG_VERBOSE(" -> stack pointer update: " << update
                         << " (current size = " << frameSize + update << ")"
                         << std::endl);

        if(arch::getRestriction(instr, res)) {
          // If growing the frame, the referenced slot includes the update
          // whereas if we're shrinking the frame it doesn't.
          offset = (update > 0) ? update : 0;
          offset = canonicalizeSlotOffset(frameSize + offset,
                                          arch::RegType::StackPointer, 0);
          res.offset = offset;
          res.alignment = res.size = abs(update);
          if((code = info->addRestriction(res)) != ret_t::Success) goto out;
        }
        frameSize += update;
      }
    }
  }

  // Add the remaining slots, i.e., those that don't have any restrictions
  code = info->populateSlots();

  DEBUG_VERBOSE(
    if(frameSize != arch::initialFrameSize())
      DEBUGMSG(" -> function does not clean up frame (not intended to return?)"
               << std::endl);
  )

out:
  if(code == ret_t::Success) info->setInstructions(instrs);
  else instrlist_clear_and_destroy(GLOBAL_DCONTEXT, instrs);
  return code;
}

ret_t CodeTransformer::analyzeFunctions() {
  Timer t;
  ret_t code;

  // Analyze every function for which we have transformation metadata
  Binary::func_iterator it = binary.getFunctions(codeStart, codeEnd);
  for(; !it.end(); ++it) {
    const function_record *func = *it;

    DEBUGMSG("analyzing function @ " << std::hex << func->addr << ", size = "
             << std::dec << func->code_size << std::endl);
    t.start();

    RandomizedFunctionPtr info = arch::getRandomizedFunction(binary, func);
    RandomizedFunctionMap::iterator it =
      funcMaps.emplace(func->addr, std::move(info)).first;
    code = analyzeFunction(it->second);
    if(code != ret_t::Success) return code;

    t.end(true);
    DEBUGMSG_VERBOSE("analyzing function took " << t.elapsed(Timer::Micro)
                     << " us" << std::endl);
  }

  INFO(proc.getPid() << ": analysis: " << t.totalElapsed(Timer::Micro)
       << " us" << std::endl);

  return ret_t::Success;
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
ret_t CodeTransformer::randomizeOperands(const RandomizedFunctionPtr &info,
                                         uint32_t frameSize,
                                         uint32_t randFrameSize,
                                         instr_t *instr,
                                         bool &changed) {
  int i, prevOffset, origOffset, newOffset, regOffset;
  opnd_t op;
  enum arch::RegType type;

  for(i = 0; i < NumOp(instr); i++) {
    // At this point, the instruction's operands have been rewritten with a
    // previous randomization; translate from the previous to the current
    // randomization.  First, get the previously randomized offset (if this
    // operand is a stack offset).
    op = GetOp(instr, i);
    prevOffset = getStackOffset(frameSize, op, type);
    if(!prevOffset) continue;

    // Next, convert the previously-randomized offset to the original offset &
    // check if it's a randomizable slot
    origOffset = info->getOriginalOffset(prevOffset);
    if(origOffset == INT32_MAX) {
      DEBUGMSG_INSTR("couldn't find previous slot for offset " << prevOffset <<
                     " in ", instr);
      continue;
    }
    else if(!info->shouldTransformSlot(origOffset)) continue;

    // Finally, convert the original offset to the new randomized offset & set
    // the operand
    newOffset = info->getRandomizedOffset(origOffset);
    if(newOffset == INT32_MAX) {
      DEBUGMSG_INSTR("couldn't find slot for offset " << origOffset << " in ",
                     instr);
      return ret_t::BadTransformMetadata;
    }

    regOffset = slotOffsetFromRegister(randFrameSize, type, newOffset);
    opnd_set_disp_ex(&op, regOffset, false, false, false);
    SetOp(instr, i, op);
    changed = true;

    DEBUGMSG_VERBOSE(" -> remap stack offset " << prevOffset << " -> "
                     << newOffset << std::endl);
  }

  return ret_t::Success;
}

#ifdef DEBUG_BUILD
/**
 * Compare original instructions to transformed version and print any size
 * differences.
 *
 * @param pointer to real address of original instructions
 * @param pointer to starting address of original instructions
 * @param pointer to ending address of original instructions
 * @param transformedInstrs transformed instructions
 */
static void compareInstructions(byte *real,
                                byte *start,
                                byte *end,
                                instrlist_t *transformedInstrs) {
  int origLen, transLen;
  instr_t orig, *trans;
  byte *prev;

  instr_init(GLOBAL_DCONTEXT, &orig);
  trans = instrlist_first(transformedInstrs);
  while(start < end) {
    prev = start;
    instr_reset(GLOBAL_DCONTEXT, &orig);
    start = decode_from_copy(GLOBAL_DCONTEXT, start, real, &orig);
    if(!start) {
      DEBUGMSG("couldn't decode in compareInstructions()" << std::endl);
      return;
    }
    origLen = start - prev;
    instr_set_raw_bits(&orig, prev, origLen);
    real += origLen;
    transLen = instr_length(GLOBAL_DCONTEXT, trans);
    if(transLen != origLen) {
      DEBUGMSG_INSTR("Changed size: " << transLen << " bytes, ", trans);
      DEBUGMSG_INSTR("              " << origLen << " bytes, ", &orig);
    }
    trans = instr_get_next(trans);
  }
}
#endif

ret_t CodeTransformer::randomizeFunction(RandomizedFunctionPtr &info,
                                         MemoryWindow &buffer) {
  bool changed;
  int32_t update, offset, instrSize;
  uint32_t frameSize = arch::initialFrameSize(),
           randFrameSize = arch::initialFrameSize(),
           count = 0;
  const function_record *func = info->getFunctionRecord();
  byte_iterator funcData = buffer.getData(func->addr);
  byte *real = (byte *)func->addr, *cur = funcData[0], *prev;
  instrlist_t *instrs = info->getInstructions();
  instr_t *instr;
  reg_id_t drsp;
  ret_t code;

  // Randomize the function's layout according to the metadata
  code = info->randomize(rng(), slotPadding);
  if(code != ret_t::Success) return code;

  // Apply the randomization by rewriting instructions
  instr = instrlist_first(instrs);
  drsp = arch::getDRRegType(arch::RegType::StackPointer);
  while(instr) {
    changed = false;
    instrSize = instr_length(GLOBAL_DCONTEXT, instr);

    DEBUG_VERBOSE(DEBUGMSG_INSTR("size = " << instrSize << ": ", instr);)

    // Rewrite stack slot reference operands to their randomized locations
    code = randomizeOperands<instr_num_srcs, instr_get_src, instr_set_src>
                            (info, frameSize, randFrameSize, instr, changed);
    if(code != ret_t::Success) return code;
    code = randomizeOperands<instr_num_dsts, instr_get_dst, instr_set_dst>
                            (info, frameSize, randFrameSize, instr, changed);
    if(code != ret_t::Success) return code;

    // Allow each ISA-specific randomized function to have its way
    code = info->transformInstr(frameSize, randFrameSize, instr, changed);
    if(code != ret_t::Success) return code;

    // Keep track of stack pointer updates & rewrite frame update instructions
    // with randomized size
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        offset = (update > 0) ? update : 0;
        offset = canonicalizeSlotOffset(frameSize + offset,
                                        arch::RegType::StackPointer, 0);
        if(info->isBulkFrameUpdate(offset) &&
           offset <= (int)info->getPrevRandFrameSize()) {
          offset = info->getRandomizedBulkFrameUpdate();
          offset = update > 0 ? offset : -offset;
          code = arch::rewriteFrameUpdate(instr, offset, changed);
          if(code != ret_t::Success) return code;
          randFrameSize += offset;

          DEBUGMSG_VERBOSE(" -> rewrite frame update: " << update << " -> "
                           << offset << std::endl);
        }
        else randFrameSize += update;
        frameSize += update;
      }
    }

    // If we changed anything, re-encode the instruction.  Note that
    // randomization *may* change the size of individual instructions; the net
    // code size *must* be identical.
    if(changed) {
      // The instruction's raw bits are currently pointing to the last version
      // of the buffer.  We need to do the following things:
      //
      //   1. Point the instruction's raw bits to the current buffer and mark
      //      them as invalid so that DynamoRIO *actually* re-encodes them
      //   2. Encode the changed instruction into the buffer
      //   3. Reset the bits with the instruction's new length, because
      //      apparently re-encoding does not do this (probably because we're
      //      encoding to a copy).
      //
      // The last task is required because at the next randomization when we
      // call instr_length() above, if the bits are not marked valid DynamoRIO
      // will re-encode the instruction (potentially in a different format) and
      // may change the instruction's size.
      prev = cur;
      instr_set_raw_bits(instr, cur, instrSize);
      instr_set_raw_bits_valid(instr, false);
      cur = instr_encode_to_copy(GLOBAL_DCONTEXT, instr, cur, real);
      if(!cur) return ret_t::RandomizeFailed;
      instr_set_raw_bits(instr, prev, cur - prev);

      DEBUG_VERBOSE(
        if(instrSize != (cur - prev))
          DEBUGMSG_VERBOSE(" -> changed size of instruction: " << instrSize
                           << " vs. " << (cur - prev) << std::endl);
        DEBUGMSG_INSTR(" -> rewrote: ", instr)
      );

      count++;
      instrSize = cur - prev;
    }
    else cur += instrSize;
    real += instrSize;

    instr = instr_get_next(instr);
  }

  if((uintptr_t)real != (func->addr + func->code_size)) {
    WARN("changed size of function's instructions, ended with 0x" << std::hex
         << (uintptr_t)real << " but expected 0x"
         << (uintptr_t)(func->addr + func->code_size) << std::endl);
    DEBUG(compareInstructions((byte *)func->addr, funcData[0],
                              funcData[0] + func->code_size, instrs));
    return ret_t::RandomizeFailed;
  }

  DEBUGMSG("rewrote " << count << " instruction(s)" << std::endl);

  return ret_t::Success;
}

ret_t CodeTransformer::randomizeFunctions(MemoryWindow &buffer) {
  ret_t code;
#ifdef DEBUG_BUILD
  Timer t;
#endif

  for(auto &it : funcMaps) {
    RandomizedFunctionPtr &info = it.second;

    DEBUG(
      const function_record *func = info->getFunctionRecord();
      DEBUGMSG("randomizing function @ " << std::hex << func->addr
               << ", size = " << std::dec << func->code_size << std::endl);
    )
    DEBUG_VERBOSE(t.start());

    code = randomizeFunction(info, buffer);
    if(code != ret_t::Success) return code;

    DEBUG_VERBOSE(
      t.end(true);
      DEBUGMSG_VERBOSE("randomizing function took " << t.elapsed(Timer::Micro)
                       << " us" << std::endl);
    )
  }

  return ret_t::Success;
}

