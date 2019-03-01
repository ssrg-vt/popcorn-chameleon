#include <fstream>
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
 * Handle a fault by passing a previously-randomized code page pointer to the
 * kernel.
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
                                std::vector<char> &pageBuf,
                                uintptr_t intPageAddr) {
  uintptr_t pageAddr = PAGE_DOWN(msg.arg.pagefault.address), data;
  ret_t code = ret_t::Success;

  assert(msg.event == UFFD_EVENT_PAGEFAULT && "Invalid message type");
  DEBUGMSG(CT->getProcessPid() << ": handling fault @ 0x" << std::hex
           << pageAddr << ", flags=" << msg.arg.pagefault.flags << ", ptid="
           << std::dec << msg.arg.pagefault.feat.ptid
           << (pageAddr == intPageAddr ? " (interrupt page)" : "")
           << std::endl);

  DEBUG_VERBOSE(
    // Print the PC causing the fault.  We can't directly interrupt/read child
    // state (we're not the tracer), so poke the child with a signal to get the
    // tracer to print information (SIGTRAP will get masked by chameleon).
    Process &theProc = CT->getProcess();
    if(theProc.signalProcess(SIGTRAP) == ret_t::Success);
    // TODO ROB the main thread's printing races with the fault handler's
    // printing, leading to garbled output.  Synchronize better than sleeping.
    struct timespec time = { 0, 10000000 };
    nanosleep(&time, nullptr);
  )

  // Lock the code window so that if a re-randomization occurs while we're
  // handling the fault we don't accidentally serve stale code
  if((code = CT->lockCodeWindow()) != ret_t::Success) return code;

  if(pageAddr != intPageAddr) {
    if(!(data = CT->zeroCopy(pageAddr))) {
      if((code = CT->project(pageAddr, pageBuf)) != ret_t::Success)
        return code;
      data = (uintptr_t)&pageBuf[0];
    }
  }
  else data = (uintptr_t)&intPage[0];

  if(!uffd::copy(uffd, data, pageAddr)) code = ret_t::UffdCopyFailed;
  if((code = CT->unlockCodeWindow()) != ret_t::Success) return code;

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
  uintptr_t intPage = CT->getIntPageAddr();
  pid_t me = syscall(SYS_gettid), cpid = CT->getProcessPid();
  struct uffd_msg *msg = new struct uffd_msg[nfaults];
  std::vector<char> pageBuf(PAGESZ);
  Timer t;

  assert(CT && "Invalid CodeTransformer object");
  assert(uffd >= 0 && "Invalid userfaultfd file descriptor");
  assert(msg && "Page fault message buffer allocation failed");

  // TODO race condition - if child handler calls cleanup() before we can set
  // our PID, we may be orphaned.  Need to signal child handler we've finished
  // initialization
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
        if(handleFault(CT, uffd, msg[i], pageBuf, intPage) != ret_t::Success) {
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
  sem_t *scramble = CT->getScrambleSem(),
        *finishedScrambling = CT->getFinishedScrambleSem();
  pid_t me = syscall(SYS_gettid), cpid = CT->getProcessPid();
  MemoryWindow &nextCode = CT->getNextCodeWindow();
  Timer t;
  ret_t code;

  // TODO race condition - if child handler calls cleanup() before we can set
  // our PID, we may be orphaned.  Need to signal child handler we've finished
  // initialization
  CT->setScramberPid(me);
  if(MASK_INT(sem_wait(scramble))) {
    DEBUGMSG(cpid << ": scramber could not wait for re-randomization signal"
             << std::endl);
    return nullptr;
  }

  DEBUGMSG("chameleon thread " << me << " is scrambling code for " << cpid
           << std::endl);

  while(!CT->shouldScramblerExit()) {
    t.start();

    nextCode.copy(CT->getCodeWindow());
    code = CT->randomizeFunctions(nextCode);
    if(code != ret_t::Success) {
      // We need to signal to the child handler that the scrambler exited due
      // to a failure.  Destroy the semaphore so at the next call to
      // rerandomize(), the child handler's call to sem_wait() fails.
      sem_destroy(finishedScrambling);
      break;
    }
    scrambles++;

    t.end(true);
    DEBUGMSG_VERBOSE("code randomization time: " << t.elapsed(Timer::Micro)
                     << " us" << std::endl);

    if(sem_post(finishedScrambling)) {
      DEBUGMSG(cpid << ": scrambler could not signal finished randomizing"
               << std::endl);
      break;
    }
    if(MASK_INT(sem_wait(scramble))) {
      DEBUGMSG(cpid << ": scrambler could not wait for re-randomization signal"
               << std::endl);
      sem_destroy(finishedScrambling);
      break;
    }
  }

  DEBUGMSG("scrambler " << me << " exiting" << std::endl);
  INFO(cpid << ": async code randomization: " << t.totalElapsed(Timer::Micro)
       << " us for " << scrambles << " randomization(s)" << std::endl);

  return nullptr;
}

///////////////////////////////////////////////////////////////////////////////
// CodeTransformer implementation
///////////////////////////////////////////////////////////////////////////////

// TODO badSites should be removed
static std::unordered_set<uintptr_t> blacklist, badSites;

void CodeTransformer::globalInitialize(const char *blacklistFilename,
                                       const char *badSitesFilename) {
  uintptr_t addr;

  arch::setInterruptInstructions(intPage);

  // Read in addresses of functions (in hex) which should *not* be randomized
  if(blacklistFilename) {
    std::ifstream fs(blacklistFilename);
    if(fs.is_open()) {
      std::string line;
      while(std::getline(fs, line)) {
        if(line.empty()) continue;
        try {
          addr = std::stoul(line, nullptr, 16);
          blacklist.insert(addr);
        } catch(std::invalid_argument& ia) {
          DEBUG(WARN("Skipping invalid function address '" << line << "'"
                     << std::endl));
        } catch(std::out_of_range &oor) {
          DEBUG(WARN("Function address " << line << " out of range"
                     << std::endl));
        }
      }
      DEBUGMSG("blacklisted " << blacklist.size() << " function(s)"
               << std::endl);
    }
    else DEBUG(WARN("Could not open blacklist file '" << blacklistFilename
                    << "'" << std::endl));
  }

  // TODO this should be removed
  // Read in addresses of bad call sites
  if(badSitesFilename) {
    std::ifstream fs(badSitesFilename);
    if(fs.is_open()) {
      std::string line;
      while(std::getline(fs, line)) {
        if(line.empty()) continue;
        try {
          addr = std::stoul(line, nullptr, 16);
          badSites.insert(addr);
        } catch(std::invalid_argument& ia) {
          DEBUG(WARN("Skipping invalid bad site address '" << line << "'"
                     << std::endl));
        } catch(std::out_of_range &oor) {
          DEBUG(WARN("Bad site address " << line << " out of range"
                     << std::endl));
        }
      }
      DEBUGMSG("banishing " << badSites.size() << " bad site(s)"
               << std::endl);
    }
    else DEBUG(WARN("Could not open bad site file '" << badSitesFilename
                    << "'" << std::endl));
  }
}

ret_t CodeTransformer::initialize(bool randomize) {
  ret_t retcode;
  Timer t;

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
    // Initialize transformation metadata, analyze code & do initial
    // randomization
    rewriteMetadata =
        std::shared_ptr<struct _st_handle>(st_init(binary.getFilename()),
                                           st_destroy);
    if(!rewriteMetadata) return ret_t::BadTransformMetadata;
    retcode = analyzeFunctions();
    if(retcode != ret_t::Success) return retcode;
    t.start();
    retcode = randomizeFunctions(codeWindow);
    if(retcode != ret_t::Success) return retcode;
    t.end();
    INFO(proc.getPid() << ": initial randomization: "
         << t.elapsed(Timer::Micro) << " us" << std::endl);

    // Set up a buffer for transforming the child's stack & kick of the
    // re-randomization thread
    const urange_t &bounds = proc.getStackBounds();
    stackMem.reset(new unsigned char[bounds.second - bounds.first]);
    if(sem_init(&scramble, 0, 1) || sem_init(&finishedScrambling, 0, 0))
      return ret_t::ScramblerFailed;
    if(pthread_create(&scrambler, nullptr, randomizeCodeAsync, this))
      return ret_t::ScramblerFailed;
  }

  // Prepare the code region inside the child by setting up correct page
  // permissions and registering it with the userfaultfd file descriptor
  intPageAddr = PAGE_DOWN(parasite::infectAddress(proc.getParasiteCtl()));
  retcode = remapCodeSegment(codeSec.address(), codeSec.size());
  if(retcode != ret_t::Success) return retcode;
  retcode = proc.stealUserfaultfd();
  if(retcode != ret_t::Success) return retcode;
  if(!uffd::api(proc.getUserfaultfd(), nullptr, nullptr))
    return ret_t::UffdHandshakeFailed;
  if(!uffd::registerRegion(proc.getUserfaultfd(),
                           codeSec.address(),
                           codeSec.size()))
    return ret_t::UffdRegisterFailed;

  // Initialize thread for handling faults
  if(pthread_mutex_init(&windowLock, nullptr)) return ret_t::LockFailed;
  if(pthread_create(&faultHandler, nullptr, handleFaultsAsync, this))
    return ret_t::FaultHandlerFailed;

  return ret_t::Success;
}

ret_t CodeTransformer::initializeFromExisting(const CodeTransformer &rhs,
                                              bool randomize) {
  ret_t retcode;

  // Copy existing code & randomization information (if requested)
  codeWindow.copy(rhs.codeWindow);
  if(randomize) {
    rewriteMetadata = rhs.rewriteMetadata;
    for(auto &RF : rhs.functions)
      functions.emplace(RF.first, RF.second->copy(codeWindow));

    const urange_t &bounds = proc.getStackBounds();
    stackMem.reset(new unsigned char[bounds.second - bounds.first]);
    if(sem_init(&scramble, 0, 1) || sem_init(&finishedScrambling, 0, 0))
      return ret_t::ScramblerFailed;
    if(pthread_create(&scrambler, nullptr, randomizeCodeAsync, this))
      return ret_t::ScramblerFailed;
  }

  // Drop the existing code pages to force the new child to bring in pages from
  // the new buffer
  intPageAddr = rhs.intPageAddr;
  if((retcode = dropCode()) != ret_t::Success) return retcode;
  retcode = proc.stealUserfaultfd();
  if(retcode != ret_t::Success) return retcode;
  if(!uffd::api(proc.getUserfaultfd(), nullptr, nullptr))
    return ret_t::UffdHandshakeFailed;
  const Binary::Section &codeSec = binary.getCodeSection();
  if(!uffd::registerRegion(proc.getUserfaultfd(),
                           codeSec.address(),
                           codeSec.size()))
    return ret_t::UffdRegisterFailed;

  if(pthread_mutex_init(&windowLock, nullptr)) return ret_t::LockFailed;
  if(pthread_create(&faultHandler, nullptr, handleFaultsAsync, this))
    return ret_t::FaultHandlerFailed;

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
  pthread_mutex_destroy(&windowLock);

  scramblerExit = true;
  if(scramblerPid > 0) {
    // Unblock if scrambler was blocked waiting for the re-randomization signal
    sem_post(&scramble);
    pthread_join(scrambler, nullptr);
    sem_destroy(&scramble);
    sem_destroy(&finishedScrambling);
  }

  DEBUG(
    codeStart = codeEnd = 0;
    functions.clear();
    slotPadding = 0;
    faultHandlerPid = scramblerPid = 0;
    batchedFaults = 0;
    intPageAddr = 0;
    curStackBase = 0;
  )

  if(numRandomizations)
    INFO(pid << ": switching to new randomization: " << rerandomizeTime
         << " us for " << numRandomizations << " switches" << std::endl);

  return ret_t::Success;
}

static func_rand_info getFunctionInfoCallback(void *rawCT, uintptr_t addr) {
  CodeTransformer *CT = (CodeTransformer *)rawCT;
  RandomizedFunction *info;
  func_rand_info cinfo;
  cinfo.old_frame_size = UINT64_MAX;

  // Skip sites explicitly marked as evil
  // TODO this is a hack that should be removed
  if(badSites.count(addr)) {
    DEBUGMSG_VERBOSE(" -> preventing transforming bad site at 0x" << std::hex
                     << addr << std::endl);
    memset(&cinfo, 0, sizeof(cinfo));
    return cinfo;
  }

  info = CT->getRandomizedFunctionInfo(addr);
  if(info) {
    cinfo.found = true;
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

// TODO BANDAGE! compel's APIs restore the thread context from when it was
// initialized, not from when we do a syscall (applies to the following 2 APIs)

ret_t CodeTransformer::mapMemory(uintptr_t start,
                                 size_t len,
                                 int prot,
                                 int flags) const {
  long ret;
  ret_t code;
  struct user_regs_struct regs;
  if((code = proc.readRegs(regs)) != ret_t::Success) return code;
  code = parasite::syscall(proc.getParasiteCtl(), SYS_mmap, ret, start, len,
                           prot, flags, -1, 0);
  if(code != ret_t::Success || (uintptr_t)ret != start)
    return ret_t::CompelSyscallFailed;
  if((code = proc.writeRegs(regs)) != ret_t::Success) return code;
  return ret_t::Success;
}

ret_t CodeTransformer::unmapMemory(uintptr_t start, size_t len) const {
  long ret;
  ret_t code;
  struct user_regs_struct regs;
  if((code = proc.readRegs(regs)) != ret_t::Success) return code;
  code = parasite::syscall(proc.getParasiteCtl(), SYS_munmap, ret, start, len);
  if(code != ret_t::Success) return ret_t::CompelSyscallFailed;
  if((code = proc.writeRegs(regs)) != ret_t::Success) return code;
  return ret_t::Success;
}

ret_t CodeTransformer::changeProtection(uintptr_t start,
                                        size_t len,
                                        int prot) const {
  long ret;
  ret_t code;
  struct parasite_ctl *parasite = proc.getParasiteCtl();

  len = PAGE_UP(start + len) - PAGE_DOWN(start);
  start = PAGE_DOWN(start);

  DEBUGMSG_VERBOSE("changing protections from 0x" << std::hex << start
                   << " -> " << start + len << " to " << prot << std::endl);

  // TODO BANDAGE! compel's APIs restore the thread context from when it was
  // initialized, not from when we do a syscall
  struct user_regs_struct regs;
  if((code = proc.readRegs(regs)) != ret_t::Success) return code;

  code = parasite::syscall(parasite, SYS_mprotect, ret, start, len, prot);
  if(code != ret_t::Success || ret) return ret_t::CompelSyscallFailed;

  // TODO BANDAGE! compel's APIs restore the thread context from when it was
  // initialized, not from when we do a syscall
  if((code = proc.writeRegs(regs)) != ret_t::Success) return code;

  return ret_t::Success;
}

#ifdef DEBUG_BUILD

#define FOURMB (4 * 1024 * 1024)

byte_iterator CodeTransformer::calcStackBounds(uintptr_t sp,
                                               uintptr_t &childSrcBase,
                                               uintptr_t &bufSrcBase,
                                               uintptr_t &childDstBase,
                                               uintptr_t &bufDstBase) {
  uintptr_t rawBuf;
  size_t stackSize;

  // TODO maybe roll this back to the beginning after 1000 switches or so
  if(sp > 0x5fffff000000) { // First re-randomization
    const urange_t &stackBounds = proc.getStackBounds();
    childSrcBase = stackBounds.second;
  }
  else childSrcBase = curStackBase;
  childDstBase = curStackBase + FOURMB;
  stackSize = childSrcBase - sp;
  rawBuf = (uintptr_t)stackMem.get();
  bufSrcBase = rawBuf + FOURMB;
  bufDstBase = rawBuf + (2 * FOURMB);
  return byte_iterator((unsigned char *)rawBuf + FOURMB - stackSize,
                       stackSize);
}

byte_iterator CodeTransformer::mapInNewStackRegion(uintptr_t childSrcBase,
                                                   uintptr_t childDstBase,
                                                   size_t stackSize) {
  ret_t code;
  unsigned char *rawBuf = stackMem.get();

  // Map in the new stack space and unmap the old
  code = mapMemory(childDstBase - FOURMB, FOURMB, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED);
  if(code != ret_t::Success) return byte_iterator::empty();
  code = unmapMemory(childSrcBase - FOURMB, FOURMB);
  if(code != ret_t::Success) return byte_iterator::empty();
  return byte_iterator(rawBuf + (2 * FOURMB) - stackSize, stackSize);
}

#else

byte_iterator CodeTransformer::calcStackBounds(uintptr_t sp,
                                               uintptr_t &childSrcBase,
                                               uintptr_t &bufSrcBase,
                                               uintptr_t &childDstBase,
                                               uintptr_t &bufDstBase) {
  uintptr_t mid, rawBuf;
  size_t stackSize;
  const urange_t &stackBounds = proc.getStackBounds();

  assert(sp >= stackBounds.first && sp < stackBounds.second &&
         "Invalid stack pointer");

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
  return byte_iterator((unsigned char *)rawBuf + (sp - stackBounds.first),
                       stackSize);
}

#endif

ret_t CodeTransformer::rerandomize() {
  typedef RandomizedFunction::TransformType TransformType;
  uintptr_t sp, childSrcBase, bufSrcBase, childDstBase, bufDstBase;
  size_t stackSize;
  TransformType StopTy;
  ret_t code;
  Timer t;

  assert(proc.traceable() && "Invalid process state");
  t.start();

  // We only have metadata at transformation points, advance the child to a
  // transformation point where the stack transformation can bootstrap.
  code = advanceToTransformationPoint(StopTy, t);
  if(code != ret_t::Success) return code;

  // Read in the child's current stack.  We currently divide the stack into 2
  // halves and rewrite from one half to the other.
  if(!(sp = proc.getSP())) return ret_t::PtraceFailed;
  byte_iterator stackBuf = calcStackBounds(sp, childSrcBase, bufSrcBase,
                                           childDstBase, bufDstBase);
  code = proc.readRegion(sp, stackBuf);
  if(code != ret_t::Success) return code;

  DEBUGMSG_VERBOSE("child stack pointer: 0x" << std::hex << sp << std::endl);

  // Wait for code scrambler to finish next set of code
  if(MASK_INT(sem_wait(&finishedScrambling))) return ret_t::RandomizeFailed;

  DEBUGMSG_VERBOSE("switching stack base from 0x" << std::hex << childSrcBase
                   << " -> 0x" << childDstBase << std::endl);

  // Transform the stack; transformStack() internally sets the register set
  // (including swinging the SP) to the transformed registers
  code = arch::transformStack(this, getFunctionInfoCallback,
                              rewriteMetadata.get(),
                              StopTy == TransformType::Return,
                              childSrcBase, bufSrcBase,
                              childDstBase, bufDstBase, sp);
  if(code != ret_t::Success) {
    // We didn't switch the stack because the transform failed.  Restore
    // previously-consumed semaphore to avoid deadlocking when trying to
    // re-randomize again.
    sem_post(&finishedScrambling);
    return ret_t::TransformFailed;
  }

  // TODO if any of the following actions fail before switching to the new code
  // window we need to sem_post(&finishedScrambling) so we don't deadlock

  stackSize = childDstBase - sp;
#ifdef DEBUG_BUILD
  stackBuf = mapInNewStackRegion(childSrcBase, childDstBase, stackSize);
  if(!stackBuf.getLength()) return ret_t::RandomizeFailed;
  curStackBase += FOURMB;
#else
  const urange_t &stackBounds = proc.getStackBounds();
  stackBuf = byte_iterator(stackMem.get() + (sp - stackBounds.first),
                           stackSize);
#endif

  // Write the transformed stack into the child's memory
  code = proc.writeRegion(sp, stackBuf);
  if(code != ret_t::Success) return code;

  // Switch the code window to the new randomized code, drop the existing code
  // pages (forcing fresh page faults) and kick off the next code randomization
  if((code = lockCodeWindow()) != ret_t::Success) return code;
  codeWindow = nextCodeWindow;
  if((code = unlockCodeWindow()) != ret_t::Success) return code;
  if((code = dropCode()) != ret_t::Success) return code;
  if(sem_post(&scramble)) return ret_t::RandomizeFailed;

  t.end(true);
  numRandomizations++;
  rerandomizeTime += t.totalElapsed(Timer::Micro);

  DEBUGMSG_VERBOSE(proc.getPid() << ": switching to new randomization took "
                   << t.elapsed(Timer::Micro) << " us" << std::endl);

  return ret_t::Success;
}

RandomizedFunction *
CodeTransformer::getRandomizedFunctionInfo(uintptr_t pc) const {
  const function_record *fr;
  RandomizedFunctionMap::const_iterator func;

  fr = binary.getFunction(pc);
  if(fr) {
    func = functions.find(fr->addr);
    if(func != functions.end()) return func->second.get();
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

static inline uint64_t replaceBits(uint64_t origBits,
                                   uint64_t newBits,
                                   size_t position,
                                   size_t size) {
  uint64_t mask = 0;

  assert(position < sizeof(uint64_t) && size < sizeof(uint64_t) &&
         (position + size) <= sizeof(uint64_t) &&
         "Invalid interrupt bits - runs past end of buffer");

  // Generate the mask
  switch(size) {
  case 1: mask = 0xffUL; break;
  case 2: mask = 0xffffUL; break;
  case 3: mask = 0xffffffUL; break;
  case 4: mask = 0xffffffffUL; break;
  case 5: mask = 0xffffffffffUL; break;
  case 6: mask = 0xffffffffffffUL; break;
  case 7: mask = 0xffffffffffffffUL; break;
  case 8: mask = 0xffffffffffffffffUL; break;
  default: assert(false && "Invalid interrupt size"); return UINT64_MAX;
  }
  mask = ~(mask << (position * 8));

  // Mask out the old instruction bits and or in the new bits
  newBits <<= (position * 8);
  return (origBits & mask) | newBits;
}

ret_t
CodeTransformer::sprayTransformBreakpoints(const RandomizedFunction *info,
                     std::unordered_map<uintptr_t, uint64_t> &origData,
                     size_t &interruptSize) const {
  uint64_t interrupt, origBits, newBits;
  uintptr_t alignedAddr;
  size_t position;
  auto &addrs = info->getTransformAddrs();
  ret_t code;

  DEBUG(
    if(addrs.size() > 100)
      DEBUGMSG(addrs.size() << " transformation points in function at 0x"
               << std::hex << info->getFunctionRecord()->addr << ", may "
               "harm performance" << std::endl);
  )

  origData.clear();
  interrupt = arch::getInterruptInst(interruptSize);
  for(auto addr = addrs.begin(); addr != addrs.end(); addr++) {
    // Read & save original data, mask in interrupt instruction bits, and
    // write the instruction back to the child's address space.  Note that
    // ptrace requires reads/writes to be word aligned; make it so.
    // TODO overwriting return instructions can inadvertently overwrite the
    // start of other functions, may race with other threads spraying start of
    // function (if added as transform point)
    alignedAddr = ROUND_DOWN(addr->first, WORDSZ);
    code = proc.read(alignedAddr, origBits);
    if(code != ret_t::Success) {
      // ptrace fails with EIO if the page data isn't already mapped; just warn
      // the user & skip this randomization period rather than dying
      if(errno == EIO) return ret_t::UnmappedMemory;
      else return code;
    }

    origData[alignedAddr] = origBits;
    position = addr->first - alignedAddr;
    newBits = replaceBits(origBits, interrupt, position, interruptSize);
    code = proc.write(alignedAddr, newBits);
    if(code != ret_t::Success) return code;
  }

  return ret_t::Success;
}

ret_t
CodeTransformer::restoreTransformBreakpoints(const RandomizedFunction *info,
               const std::unordered_map<uintptr_t, uint64_t> &origData) const {
  ret_t code = ret_t::Success;
  for(auto data = origData.begin(); data != origData.end(); data++) {
    assert(data->first == ROUND_DOWN(data->first, WORDSZ) &&
           "Unaligned transformation address");
    code = proc.write(data->first, data->second);
    if(code != ret_t::Success) break;
  }
  return code;
}

ret_t
CodeTransformer::advanceToTransformationPoint(RandomizedFunction::TransformType &Ty,
                                                              Timer &t) const {
  typedef RandomizedFunction::TransformType TransformType;
  uintptr_t pc;
  size_t interruptSize;
  const RandomizedFunction *info;
  const function_record *fr;
  std::unordered_map<uintptr_t, uint64_t> origData;
  ret_t code, restoreCode;
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
  if(pc != fr->addr) {
    Ty = info->getTransformationType(pc);
    if(Ty == TransformType::None) {
      DEBUGMSG_VERBOSE(cpid << ": inserting transformation breakpoints inside "
                       "function at 0x" << std::hex << fr->addr <<
                       " (current address: 0x" << pc << ")" << std::endl);

      // Insert traps at transformation breakpoints & kick child towards them
      code = sprayTransformBreakpoints(info, origData, interruptSize);
      if(code != ret_t::Success) goto restore;

      t.end(true);
      // TODO child may stop due to other signal instead of our transformation
      // breakpoints; need to keep continuing until we hit a breakpoint
      if((code = proc.continueToNextSignal()) != ret_t::Success) goto restore;
      t.start();

      if(!proc.traceable() || !(pc = proc.getPC())) {
        code = ret_t::InvalidState;
        goto restore;
      }

      // Figure out where child stopped & reset instruction address.  Note that
      // if we did *not* stop at a transformation point, we do *not* want to
      // reset the instruction address - check that first.
      pc -= interruptSize;
      if((Ty = info->getTransformationType(pc)) == TransformType::None) {
        code = ret_t::AdvancingFailed;
        goto restore;
      }
      code = proc.setPC(pc);

restore:
      restoreCode = restoreTransformBreakpoints(info, origData);
      if(restoreCode != ret_t::Success) return restoreCode;
      else if(code != ret_t::Success) return code;
    }

    // If we stopped at a call instruction, walk it into the called function in
    // preparation for transformation
    if(Ty == TransformType::CallSite)
      if((code = proc.singleStep()) != ret_t::Success) return code;
  }
  else Ty = TransformType::CallSite;

  DEBUGMSG_VERBOSE(cpid << ": stopped at transformation point at 0x"
                   << std::hex << proc.getPC() << std::endl);

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

ret_t CodeTransformer::writeCodePage(uintptr_t start) const {
  byte *pageData;
  std::vector<char> pageBuf;
  ret_t code;
#ifdef DEBUG_BUILD
  uintptr_t origStart = PAGE_DOWN(start);
#endif

  start = PAGE_DOWN(start);
  if(!(pageData = (byte *)codeWindow.zeroCopy(start))) {
    pageBuf.resize(PAGESZ);
    code = codeWindow.project(start, pageBuf);
    if(code != ret_t::Success) return code;
    pageData = (byte *)&pageBuf[0];
  }

  byte_iterator buf(pageData, PAGESZ);
  if((code = proc.writeRegion(start, buf)) != ret_t::Success) return code;

  DEBUGMSG(proc.getPid() << ": manually rewrote page @ 0x" << std::hex
           << origStart << std::endl);

  return ret_t::Success;
}

ret_t CodeTransformer::remapCodeSegment(uintptr_t start, size_t len) const {
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

  // compel touched a page through syscall injection, so it won't get served by
  // userfaultfd (the kernel served a zero page); manually rewrite it here.
  code = writeCodePage(intPageAddr);
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

  // The child executes madvise(), which causes the kernel to drop the code
  // pages.  When returning to userspace, the child causes a page fault, giving
  // the fault handling thread a chance to serve a page.  We've already told
  // the fault handling thread to serve an interrupt page, allowing us to
  // regain control.
  parasite::syscall(parasite, SYS_madvise, ret, PAGE_DOWN(codeStart),
                    PAGE_UP(codeEnd - codeStart), MADV_DONTNEED);
  if(ret) return ret_t::DropCodeFailed;

  // TODO BANDAGE! compel's APIs restore the thread context from when it was
  // initialized, not from when we do a syscall
  if((code = proc.writeRegs(regs)) != ret_t::Success) return code;

  // Manually rewrite the interrupt page with actual instructions.
  code = writeCodePage(intPageAddr);
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
  assert(codeWindow.numRegions() == 0 && "Invalid code window");
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
 * Return whether an instruction is a transformation point, and if so, the type
 * of the transformation point.
 * @param instr an instruction
 * @return the type of transformation point if any
 */
static inline
RandomizedFunction::TransformType getTransformType(instr_t *instr) {
  if(instr_is_call(instr)) return RandomizedFunction::CallSite;
  else if(instr_is_return(instr)) return RandomizedFunction::Return;
  else return RandomizedFunction::None;
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
                                 const opnd_t &op,
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
    DEBUG_VERBOSE(
      if(offset != INT32_MAX) {
        DEBUGMSG_VERBOSE(" -> detected offset " << offset << std::endl);
        if(offset > (int)(frameSize + 8))
          DEBUG_VERBOSE(WARN("Offset outside stack bounds" << std::endl));
      }
    )
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
  uint32_t frameSize = arch::initialFrameSize(),
           maxFrameSize = arch::initialFrameSize();
  size_t instrSize;
  const function_record *func = info->getFunctionRecord();
  byte_iterator funcData = codeWindow.getData(func->addr);
  byte *real = (byte *)func->addr, *cur = funcData[0], *prev,
       *end = cur + func->code_size;
  instrlist_t *instrs;
  instr_t *instr;
  reg_id_t drsp;
  RandRestriction res;
  RandomizedFunction::TransformType TTy;
  ret_t code = ret_t::Success;

  if(funcData.getLength() < func->code_size) {
    DEBUGMSG("code length encoded in metadata larger than available size: "
             << funcData.getLength() << " vs. " << func->code_size
             << std::endl);
    return ret_t::BadTransformMetadata;
  }

  if(!cur) {
    DEBUGMSG("invalid code iterator" << std::endl);
    return ret_t::AnalysisFailed;
  }

  // Construct a list of instructions & analyze for restrictions.
  // instr_create() allocates the instruction on DynamoRIO's heap; the info
  // object will be given ownership of the instructions after analysis and will
  // free them as needed.
  instrs = instrlist_create(GLOBAL_DCONTEXT);
  drsp = arch::getDRRegType(arch::RegType::StackPointer);
  while(cur < end) {
    instr = instr_create(GLOBAL_DCONTEXT);
    instr_init(GLOBAL_DCONTEXT, instr);
    prev = cur;
    cur = decode_from_copy(GLOBAL_DCONTEXT, cur, real, instr);
    if(!cur) {
      code = ret_t::AnalysisFailed;
      goto out;
    }
    instrSize = cur - prev;
    instr_set_raw_bits(instr, prev, instrSize); // TODO figure out way to remove
    instrlist_append(instrs, instr);

    DEBUG_VERBOSE(DEBUGMSG_INSTR("size = " << instrSize << ": ", instr);)

    if((TTy = getTransformType(instr)) != RandomizedFunction::None) {
      DEBUGMSG_VERBOSE(" -> transformation point (0x" << std::hex
                       << (uintptr_t)real << ")" << std::endl);
      info->addTransformAddr((uintptr_t)real, TTy);
    }

    real += instrSize;

    // For functions whose epilogue is not at the end of the function's code or
    // that have multiple return instructions, the frame size may drop to zero
    // and screw up our analyses.  Restore to the observed maximum size.
    // Note: we're assuming the compiler didn't do anything silly like
    // partially clean up the frame mid-way through the function
    if(!frameSize) {
      DEBUGMSG_VERBOSE("found epilogue inside function body, restoring frame "
                       "size to " << maxFrameSize << std::endl);
      frameSize = maxFrameSize;
    }

    code = analyzeOperands<instr_num_srcs, instr_get_src>
                          (info, frameSize, instr);
    if(code != ret_t::Success) goto out;
    code = analyzeOperands<instr_num_dsts, instr_get_dst>
                          (info, frameSize, instr);
    if(code != ret_t::Success) goto out;

    // Keep track of current frame size as it's expanded (prologue) and shrunk
    // (epilogue) to determine offsets for operands in subsequent instructions.
    // Additionally, check if possible to rewrite frame allocation instructions
    // with a random size; if not, mark the frame size as fixed.
    // TODO this logic should be moved into arch.cpp and a function should only
    // return the frame update size
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        DEBUGMSG_VERBOSE(" -> stack pointer update: " << update
                         << " (current size = " << frameSize + update << ")"
                         << std::endl);

        if(arch::getStackUpdateRestriction(instr, update, res)) {
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
        maxFrameSize = std::max(frameSize, maxFrameSize);
      }
    }
  }

  // Add the remaining slots, i.e., those that don't have any restrictions
  code = info->finalizeAnalysis();

  DEBUG_VERBOSE(
    if(frameSize && frameSize != maxFrameSize)
      DEBUGMSG(" -> function does not clean up frame (not intended to return?)"
               << std::endl);
  )

out:
  if(code == ret_t::Success) info->setInstructions(instrs);
  else instrlist_clear_and_destroy(GLOBAL_DCONTEXT, instrs);
  return code;
}

ret_t CodeTransformer::analyzeFunctions() {
  std::unordered_set<uintptr_t> funcs;
  Timer t;
  ret_t code;

  // Analyze every function for which we have transformation metadata
  Binary::func_iterator it = binary.getFunctions(codeStart, codeEnd);
  for(; !it.end(); ++it) {
    const function_record *func = *it;

    // Due to static/templated functions in headers, we may get duplicate
    // function records; de-duplicate here to avoid problems later on.
    if(funcs.count(func->addr)) {
      DEBUGMSG("skipping duplicate function record @ " << std::hex
               << func->addr << std::endl);
      continue;
    }
    else if(blacklist.count(func->addr)) {
      DEBUGMSG("skipping blacklisted function @ " << std::hex << func->addr
               << std::endl);
      continue;
    }
    else funcs.insert(func->addr);

    DEBUGMSG("analyzing function @ " << std::hex << func->addr << ", size = "
             << std::dec << func->code_size << std::endl);
    t.start();

    RandomizedFunctionPtr info = arch::getRandomizedFunction(binary, func);
    RandomizedFunctionMap::iterator it =
      functions.emplace(func->addr, std::move(info)).first;
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
      DEBUGMSG_INSTR("missing original offset for ", instr);
      WARN("couldn't find original offset for previously-randomized slot at "
           "offset " << prevOffset  << std::endl);
      return ret_t::BadTransformMetadata;
    }
    else if(!info->shouldTransformSlot(origOffset)) continue;

    // Finally, convert the original offset to the new randomized offset & set
    // the operand
    newOffset = info->getRandomizedOffset(origOffset);
    if(newOffset == INT32_MAX) {
      DEBUGMSG_INSTR("missing new randomized offset for ", instr);
      WARN("couldn't find new randomized offset for slot originally at offset "
           << origOffset << std::endl);
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
           maxFrameSize = arch::initialFrameSize(),
           randFrameSize = arch::initialFrameSize(),
           maxRandFrameSize = arch::initialFrameSize();
  size_t count = 0;
  const function_record *func = info->getFunctionRecord();
  byte_iterator funcData = buffer.getData(func->addr);
  byte *real = (byte *)func->addr, *cur = funcData[0], *prev;
  instrlist_t *instrs = info->getInstructions();
  instr_t *instr;
  reg_id_t drsp;
  ret_t code;

  assert(cur && "Invalid code window");

  // Randomize the function's layout according to the metadata
  code = info->randomize(rng(), slotPadding);
  if(code != ret_t::Success) return code;

  // Apply the randomization by rewriting instructions
  instr = instrlist_first(instrs);
  drsp = arch::getDRRegType(arch::RegType::StackPointer);
  while(instr) {
    changed = false;
    assert(instr_raw_bits_valid(instr) && "Bits not set");
    instrSize = instr_length(GLOBAL_DCONTEXT, instr);

    DEBUG_VERBOSE(DEBUGMSG_INSTR("size = " << instrSize << ": ", instr);)

    // See frame size cleanup comment in analyzeFunction()
    if(!frameSize) {
      DEBUGMSG_VERBOSE("found epilogue in function body, restoring frame size "
                       "to " << maxFrameSize << " (previous), "
                       << maxRandFrameSize << " (current)" << std::endl);
      frameSize = maxFrameSize;
      randFrameSize = maxRandFrameSize;
    }

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
    // TODO this logic should be moved into arch.cpp and a function should only
    // return the frame update/randomized frame update size
    if(instr_writes_to_reg(instr, drsp, DR_QUERY_DEFAULT)) {
      update = arch::getFrameUpdateSize(instr);
      if(update) {
        offset = (update > 0) ? update : 0;
        offset = canonicalizeSlotOffset(frameSize + offset,
                                        arch::RegType::StackPointer, 0);
        if(info->isBulkFrameUpdate(instr, offset) &&
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
        maxFrameSize = std::max(frameSize, maxFrameSize);
        maxRandFrameSize = std::max(randFrameSize, maxRandFrameSize);
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
      //   2. Encode the changed instruction into the new buffer
      //   3. Point the instruction's raw bits back to the new buffer (which
      //      sets them as valid), because apparently re-encoding does not do
      //      this (probably because we're encoding to a copy).
      //
      // The last task is required because at the next randomization when we
      // call instr_length() above, if the bits are not marked valid DynamoRIO
      // will re-encode the instruction (potentially in a different format) and
      // may change the instruction's size.
      prev = cur;
      instr_set_raw_bits(instr, cur, instrSize);
      instr_set_raw_bits_valid(instr, false);
      cur = instr_encode_to_copy(GLOBAL_DCONTEXT, instr, cur, real);
      if(!cur) {
        WARN("re-encoding changed instruction failed" << std::endl);
        return ret_t::RandomizeFailed;
      }
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

  for(auto &it : functions) {
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

void CodeTransformer::dumpBacktrace() {
  uintptr_t sp, childSrc, bufSrc, childDst, bufDst;
  ret_t code;

  sp = proc.getSP();
  if(!sp) return;
  byte_iterator stackBuf = calcStackBounds(sp, childSrc, bufSrc,
                                           childDst, bufDst);
  code = proc.readRegion(sp, stackBuf);
  if(code != ret_t::Success) return;
  arch::dumpBacktrace(this,
                      getFunctionInfoCallback,
                      rewriteMetadata.get(),
                      childSrc,
                      bufSrc);
}

ret_t CodeTransformer::lockCodeWindow() {
  if(pthread_mutex_lock(&windowLock)) return ret_t::LockFailed;
  else return ret_t::Success;
}

ret_t CodeTransformer::unlockCodeWindow() {
  if(pthread_mutex_unlock(&windowLock)) return ret_t::LockFailed;
  else return ret_t::Success;
}

