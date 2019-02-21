#include "arch.h"
#include "log.h"
#include "transform.h"
#include "types.h"
#include "utils.h"

#include "regs.h"

using namespace chameleon;

#if defined __x86_64__

///////////////////////////////////////////////////////////////////////////////
// Miscellaneous
///////////////////////////////////////////////////////////////////////////////

bool arch::supportedArch(uint16_t arch) {
  DEBUGMSG("ISA: x86-64 = " << (arch == EM_X86_64 ? "yes" : "no")
           << std::endl);
  return arch == EM_X86_64;
}

uint64_t arch::getInterruptInst(size_t &size) {
  size = 1;
  return 0xcc;
}

void arch::setInterruptInstructions(std::vector<unsigned char> &buf)
{ memset(&buf[0], 0xcc, buf.size()); }

///////////////////////////////////////////////////////////////////////////////
// Register information & handling
///////////////////////////////////////////////////////////////////////////////

enum arch::RegType arch::getRegType(uint16_t reg) {
  switch(reg) {
  case RBP: return RegType::FramePointer;
  case RSP: return RegType::StackPointer;
  default: return RegType::None;
  }
}

const char *arch::getRegName(uint16_t reg) {
  switch(reg) {
  case RAX: return "rax";
  case RDX: return "rdx";
  case RCX: return "rcx";
  case RBX: return "rbx";
  case RSI: return "rsi";
  case RDI: return "rdi";
  case RBP: return "rbp";
  case RSP: return "rsp";
  case R8: return "r8";
  case R9: return "r9";
  case R10: return "r10";
  case R11: return "r11";
  case R12: return "r12";
  case R13: return "r13";
  case R14: return "r14";
  case R15: return "r15";
  case RIP: return "rip";
  case XMM0: return "xmm0";
  case XMM1: return "xmm1";
  case XMM2: return "xmm2";
  case XMM3: return "xmm3";
  case XMM4: return "xmm4";
  case XMM5: return "xmm5";
  case XMM6: return "xmm6";
  case XMM7: return "xmm7";
  case XMM8: return "xmm8";
  case XMM9: return "xmm9";
  case XMM10: return "xmm10";
  case XMM11: return "xmm11";
  case XMM12: return "xmm12";
  case XMM13: return "xmm13";
  case XMM14: return "xmm14";
  case XMM15: return "xmm15";
  default: return "unknown";
  }
}

uint16_t arch::getCalleeSaveSize(uint16_t reg) {
  switch(reg) {
  case RBX: case RBP: case R12: case R13: case R14: case R15: case RIP:
    return 8;
  default: return 0;
  }
}

uintptr_t arch::pc(const struct user_regs_struct &regs) { return regs.rip; }

void arch::pc(struct user_regs_struct &regs, uintptr_t newPC)
{ regs.rip = newPC; }

uintptr_t arch::sp(const struct user_regs_struct &regs) { return regs.rsp; }

void arch::sp(struct user_regs_struct &regs, uintptr_t newSP)
{ regs.rsp = newSP; }

long arch::syscallNumber(const struct user_regs_struct &regs)
{ return regs.orig_rax; }

void arch::marshalFuncCall(struct user_regs_struct &regs,
                           long a1, long a2, long a3,
                           long a4, long a5, long a6) {
  regs.rdi = a1;
  regs.rsi = a2;
  regs.rdx = a3;
  regs.rcx = a4;
  regs.r8 = a5;
  regs.r9 = a6;
}

#define DUMP_REG( regset, name ) \
  #name": " << std::dec << regset.name << " / 0x" << std::hex << regset.name

void arch::dumpRegs(std::ostream &os, struct user_regs_struct &regs) {
  os << "General-purpose registers:" << std::endl;
  os << DUMP_REG(regs, rax) << std::endl;
  os << DUMP_REG(regs, rbx) << std::endl;
  os << DUMP_REG(regs, rcx) << std::endl;
  os << DUMP_REG(regs, rdx) << std::endl;
  os << DUMP_REG(regs, rsi) << std::endl;
  os << DUMP_REG(regs, rdi) << std::endl;
  os << DUMP_REG(regs, rbp) << std::endl;
  os << DUMP_REG(regs, rsp) << std::endl;
  os << DUMP_REG(regs, r8) << std::endl;
  os << DUMP_REG(regs, r9) << std::endl;
  os << DUMP_REG(regs, r10) << std::endl;
  os << DUMP_REG(regs, r11) << std::endl;
  os << DUMP_REG(regs, r12) << std::endl;
  os << DUMP_REG(regs, r13) << std::endl;
  os << DUMP_REG(regs, r14) << std::endl;
  os << DUMP_REG(regs, r15) << std::endl;
  os << DUMP_REG(regs, rip) << std::endl;
  os << DUMP_REG(regs, cs) << std::endl;
  os << DUMP_REG(regs, ds) << std::endl;
  os << DUMP_REG(regs, es) << std::endl;
  os << DUMP_REG(regs, fs) << std::endl;
  os << DUMP_REG(regs, fs_base) << std::endl;
  os << DUMP_REG(regs, gs) << std::endl;
  os << DUMP_REG(regs, gs_base) << std::endl;
  os << DUMP_REG(regs, ss) << std::endl;
}

void arch::dumpFPRegs(std::ostream &os, struct user_fpregs_struct &regs) {
  size_t num;
  os << "Floating-point registers:" << std::endl;
  os << DUMP_REG(regs, cwd) << std::endl;
  os << DUMP_REG(regs, swd) << std::endl;
  os << DUMP_REG(regs, ftw) << std::endl;
  os << DUMP_REG(regs, fop) << std::endl;
  os << DUMP_REG(regs, rip) << std::endl;
  os << DUMP_REG(regs, rdp) << std::endl;
  os << DUMP_REG(regs, mxcsr) << std::endl;
  os << DUMP_REG(regs, mxcr_mask);
  num = sizeof(regs.st_space) / sizeof(regs.st_space[0]);
  for(size_t i = 0; i < num; i++) {
    if(i % 4 == 0) os << std::endl << "st" << (i / 4) << ": 0x";
    os << std::hex << std::setfill('0') << std::setw(8) << regs.st_space[i];
  }
  num = sizeof(regs.xmm_space) / sizeof(regs.xmm_space[0]);
  for(size_t i = 0; i < num; i++) {
    if(i % 4 == 0) {
      os << std::endl << "xmm" << (i / 4) << ": 0x";
    }
    os << std::hex << std::setfill('0') << std::setw(8) << regs.xmm_space[i];
  }
  os << std::endl;
}

///////////////////////////////////////////////////////////////////////////////
// Stack frame information & handling
///////////////////////////////////////////////////////////////////////////////

uint32_t arch::initialFrameSize() { return 8; }

uint32_t arch::alignFrameSize(uint32_t size) { return ROUND_UP(size, 16); }

int32_t arch::framePointerOffset() { return -16; }

///////////////////////////////////////////////////////////////////////////////
// Randomization implementation
///////////////////////////////////////////////////////////////////////////////

/* Restriction flags used to indicate the type of restriction */
enum x86Restriction {
  F_None = 0,
  F_Immovable,
  F_RangeLimited,
  F_CheckCallSlot,
  F_FrameSizeLimited
};

/*
 * x86 region indexes.  Only usable *before* randomization as empty regions may
 * be pruned.  Ordered by highest stack address.
 */
enum x86Region {
  R_CalleeSave = 0,
  R_FPLimited,
  R_Movable,
  R_SPLimited,
  R_Call,
  R_Alignment,
};

/* x86 region names (corresponds to indexs above) */
const char *x86RegionName[] {
  "callee-save",
  "FP-limited",
  "movable",
  "SP-limited",
  "call",
  "alignment",
};

/**
 * Region for x86's callee-saved register stack region.  Permutes the order in
 * which registers are pushed/popped in the function's prologue/epilogue.
 */
class x86CalleeSaveRegion : public StackRegion {
public:
  /* Location at which a register is saved */
  typedef std::pair<int, uint16_t> RegOffset;

  x86CalleeSaveRegion(int32_t flags) : StackRegion(flags) {}

  /**
   * Add mapping between callee-saved register and its save location.
   * @param offset a canonicalized offset
   * @param reg the register saved at the offset
   */
  void addRegisterSaveLoc(int offset, uint16_t reg)
  { registerLocs.emplace_back(offset, reg); }

  /**
   * Comparison function used to sort register save locations; sorts offsets
   * similarly to slotMapCmp().
   *
   * @param a first RegOffset
   * @param b second RegOffset
   * @return true if a comes before b in a sorted ordering of register save
   *         locations or false otherwise
   */
  static bool locCmp(const RegOffset &a, const RegOffset &b)
  { return a.first < b.first; }

  /**
   * Sort register save locations.  *Must* match 1:1 with slots vector so when
   * looking up stack offset we can use the same index to find which register
   * is saved at the offset.
   */
  void sortRegisterSaveLocs()
  { std::sort(registerLocs.begin(), registerLocs.end(), locCmp); }

  /**
   * Randomize the order callee-saved registers are pushed/popped from the
   * stack.
   *
   * @param start the starting offset of the region
   * @param ru a random number generator
   * @return a return code describing the outcome
   */
  virtual void randomize(int start, RandUtil &ru) override {
    ZeroPad pad;

    // We can't randomize the return address or saved FBP location; move them
    // to the front and randomize the remaining locations.
    sortSlots();
    std::shuffle(slots.begin() + 2, slots.end(), ru.gen);
    randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
    randomizedSize = origSize;
    sortSlots();
    sortRegisterSaveLocs();

    DEBUG_VERBOSE(
      size_t i;
      DEBUGMSG_VERBOSE("permuted callee-save slots:" << std::endl);
      for(i = 0; i < slots.size(); i++) {
        DEBUGMSG_VERBOSE("  " << slots[i].original << " ("
                         << arch::getRegName(registerLocs[i].second) << ") -> "
                         << slots[i].randomized << std::endl);
      }
    )
  }

  /**
   * Get the register to be saved at a particular slot after randomization.
   * @param offset a canonicalized stack offset
   * @return the DynamoRIO register ID of the register to be saved
   */
  reg_id_t getRandomizedCalleeSaveReg(int offset) const {
    size_t i;
    // TODO randomize() sorts registers by original offset, but we need to
    // search by randomized offset; sort by randomized offset instead?
    for(i = 0; i < slots.size(); i++)
      if(slots[i].randomized == offset)
        return dwarfToDR(registerLocs[i].second);
    return DR_REG_NULL;
  }

private:
  std::vector<RegOffset> registerLocs;

  /**
   * Return the DynamoRIO register ID corresponding to a DWARF-encoded
   * register ID.
   * @param dwarf dwarf-encoded register ID
   * @return corresponding DynamoRIO register ID
   */
  static reg_id_t dwarfToDR(uint16_t dwarf) {
    switch(dwarf) {
    default: return DR_REG_NULL;
    case RBX: return DR_REG_XBX;
    case RBP: return DR_REG_XBP;
    case R12: return DR_REG_R12;
    case R13: return DR_REG_R13;
    case R14: return DR_REG_R14;
    case R15: return DR_REG_R15;
    }
  }
};

#define REGION_TYPE( flags ) (flags & 0xf)

/**
 * x86-64-specific implementation of a randomized function.  The x86-64 stack
 * frame has the following layout:
 *
 * |-----------------------|
 * |                       | ^
 * |   Callee-save area    | | Permutable
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |    FP-limited area    | | Permutable
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |     Movable area      | | Randomizable
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |    SP-limited area    | | Permutable
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |       Call area       | | Immutable
 * |  (spilled arguments)  | |
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |    Alignment area     | | Immutable
 * |                       | v
 * |-----------------------|
 *
 * The regions above the call area are randomizable (with limitations).
 *
 * - Most compilers emit callee-saved register save/restore procedures as a
 *   series of push/pop instructions; the ordering of this procedure can be
 *   permuted but not fully randomized
 * - x86-64 allows 1-byte displacement encodings for base + displacement memory
 *   references; the displacement for these objects cannot fall outside
 *   -128 <-> 127 (as it will increase the encoding size), so the FP-limited
 *   and SP-limited stack slots are only permutable and not fully randomizable
 *
 * Note 1: we don't move stack objects between their original regions as it may
 * create incorrect behavior.  For example, moving a stack slot from the
 * completely randomizable area into a permutable area may violate the
 * restrictions on those objects.
 */
class x86RandomizedFunction : public RandomizedFunction {
public:
  x86RandomizedFunction(const Binary &binary, const function_record *func)
    : RandomizedFunction(binary, func), alignment(16) {
    int offset;
    size_t size, regionSize = 0;

    // Add the callee-save slots to the callee-save region
    Binary::unwind_iterator ui = binary.getUnwindLocations(func);
    x86CalleeSaveRegion *cs = new x86CalleeSaveRegion(x86Region::R_CalleeSave);
    for(; !ui.end(); ++ui) {
      // Note: currently all unwind locations are encoded as offsets from the
      // frame base pointer
      const unwind_loc *loc = *ui;
      size = arch::getCalleeSaveSize(loc->reg);
      offset =
        CodeTransformer::canonicalizeSlotOffset(func->frame_size,
                                                arch::RegType::FramePointer,
                                                loc->offset);
      cs->addSlot(offset, size, size);
      cs->addRegisterSaveLoc(offset, loc->reg);
      regionSize += size;
    }
    cs->setRegionOffset(regionSize);
    cs->setRegionSize(regionSize);

    // Add x86-specific regions ordered by highest stack address first.
    regions.push_back(StackRegionPtr(cs));
    regions.emplace_back(new PermutableRegion(x86Region::R_FPLimited));
    regions.emplace_back(new RandomizableRegion(x86Region::R_Movable));
    regions.back()->setMinRandOffset(144); // Don't spill into FP-limited
    regions.emplace_back(new PermutableRegion(x86Region::R_SPLimited));
    regions.emplace_back(new ImmutableRegion(x86Region::R_Call));
    regions.emplace_back(new ImmutableRegion(x86Region::R_Alignment));
  }

  virtual uint32_t getFrameAlignment() const override { return alignment; }

  void setMaxFrameSize() {
    const StackRegionPtr &cs = regions[x86Region::R_CalleeSave];
    maxFrameSize = ROUND_DOWN(cs->getOriginalRegionOffset() + INT8_MAX,
                              this->alignment);

    DEBUGMSG(" -> maximum frame size: " << maxFrameSize << std::endl);
  }

  virtual ret_t addRestriction(const RandRestriction &res) override {
    bool foundSlot = false;
    int offset = res.offset;
    uint32_t size = res.size, alignment = res.alignment;
    ret_t code = ret_t::Success;
    std::pair<int, const stack_slot *> slot;

    // Frame size restrictions are handled separately, as they don't apply to
    // any particular slot
    if(res.flags == x86Restriction::F_FrameSizeLimited) {
      setMaxFrameSize();
      return ret_t::Success;
    }

    // Convert offsets to their containing slots, if any, so that we can avoid
    // adding multiple restrictions for the same slot (e.g., different offsets
    // within the same slot)
    slot = findSlot(offset);
    if(slot.first != INT32_MAX) {
      offset = slot.first;
      size = slot.second->size;
      alignment = slot.second->alignment;
      foundSlot = true;
    }

    // Avoid adding multiple restrictions for a single slot
    // TODO what if there are multiple types of restrictions for a single stack
    // slot, e.g., one use causes a SP-limited displacement and another causes
    // the slot to be immutable?
    if(seen.count(offset)) {
      DEBUGMSG_VERBOSE(" -> previously handled offset " << offset
                       << std::endl);
      return code;
    }
    else seen.insert(offset);

    // Add to the appropriate region depending on the restriction type
    switch(res.flags) {
    case x86Restriction::F_Immovable:
      if(!regions[x86Region::R_CalleeSave]->contains(offset)) {
        // Some functions (e.g., Popcorn's migration library) access offsets
        // beyond the frame size in the metadata; ignore thoses accesses.
        // TODO what about red zone usage?
        if(offset <= (int)func->frame_size) {
          regions[x86Region::R_Alignment]->addSlot(offset, size, alignment);
          DEBUGMSG(" -> cannot randomize slot @ " << offset << " (size = "
                   << size << ")" << std::endl);
        }
      }
      else DEBUGMSG(" -> callee-saved register @ " << offset << " (size = "
                    << size << ")" << std::endl);
      break;
    case x86Restriction::F_RangeLimited:
      switch(res.base) {
      case arch::RegType::FramePointer:
        assert(foundSlot && "Invalid frame pointer restriction");
        regions[x86Region::R_FPLimited]->addSlot(offset, size, alignment);
        DEBUGMSG(" -> slot @ " << offset
                 << " limited to 1-byte displacements from FP" << std::endl);
        break;
      case arch::RegType::StackPointer:
        // The metadata doesn't contain slot information for the call area
        if(foundSlot) {
          regions[x86Region::R_SPLimited]->addSlot(offset, size, alignment);
          DEBUGMSG(" -> slot @ " << offset
                   << " limited to 1-byte displacements from SP" << std::endl);
        }
        else {
          regions[x86Region::R_Call]->addSlot(offset, 0, 0);
          DEBUGMSG(" -> call-area slot @ " << offset << std::endl);
        }
        break;
      default: code = ret_t::AnalysisFailed; break;
      }
      break;
    case x86Restriction::F_CheckCallSlot:
      if(!foundSlot) {
        regions[x86Region::R_Call]->addSlot(offset, 0, 0);
        DEBUGMSG(" -> call-area slot @ " << offset << std::endl);
      }
      break;
    default:
      DEBUGMSG("invalid x86 restriction type: " << res.flags << std::endl);
      code = ret_t::AnalysisFailed;
      break;
    }

    return code;
  }

  void populateMovable() {
    StackRegionPtr &r = regions[x86Region::R_Movable];
#ifdef DEBUG_BUILD
    const char *name = x86RegionName[x86Region::R_Movable];
#endif

    // Add stack slots to the movable region.  During analysis we should have
    // added any restricted slots to their appropriate sections; the remaining
    // slots are completely randomizable.
    for(auto &s : slots) {
      if(!seen.count(s.first)) {
        const stack_slot *slot = s.second;
        r->addSlot(s.first, slot->size, slot->alignment);
        DEBUGMSG(" -> slot @ " << s.first << " (size = " << slot->size
                 << ") is in " << name << " region" << std::endl);
      }
    }
  }

  void populateWithRestrictions() {
    // Swap the movable region with a permutable region in order to stay within
    // the maximum frame size
    StackRegion *newMov = new PermutableRegion(x86Region::R_Movable);
    regions[x86Region::R_Movable].reset(newMov);
    StackRegionPtr &fpLimited = regions[x86Region::R_FPLimited],
                   &movable = regions[x86Region::R_Movable];
#ifdef DEBUG_BUILD
    const char *fpLimitedName = x86RegionName[x86Region::R_FPLimited],
               *movableName = x86RegionName[x86Region::R_Movable];
#endif

    DEBUGMSG("changed movable to permutable region to stay within maximum "
             "frame size" << std::endl);

    // Sometimes, due to encoding restrictions, our frame size is limited to
    // 1-byte offsets (bulk frame update only uses 1 byte).  To avoid
    // accidentally forcing a larger encoding for the bulk frame update, put
    // slots in the FP-limited region.  However, sometimes the situation arises
    // where stack slots in the metadata are beyond what is addressable from
    // FBP + 128.  For these slots, throw them in the movable region - if we
    // put them in the FP-limited region, it's possible some slot that *is*
    // addressable from FBP + 128 would be placed out of range, forcing a
    // larger encoding.
    // TODO this doesn't handle SP-limited slots
    for(auto &s : slots) {
      if(!seen.count(s.first)) {
        const stack_slot *slot = s.second;
        if(s.first <= 144) {
          fpLimited->addSlot(s.first, slot->size, slot->alignment);
          DEBUGMSG(" -> slot @ " << s.first << " (size = " << slot->size
                   << ") is in " << fpLimitedName << " region" << std::endl);
        }
        else {
          movable->addSlot(s.first, slot->size, slot->alignment);
          DEBUGMSG(" -> slot @ " << s.first << " (size = " << slot->size
                   << ") is in " << movableName << " region" << std::endl);
        }
      }
    }
  }

  void fixupAlignmentRegion() {
    bool movedSlot = false;
    int curOffset, alignStart;
    size_t i;
    SlotMap tmp;

    StackRegionPtr &alignRegion = regions.back();
    if(REGION_TYPE(alignRegion->getFlags()) != x86Region::R_Alignment) return;

    assert(regions.size() > 1 && "Invalid stack regions");
    assert(regions.back()->getSlots().size() == 1 &&
           "Invalid alignment region");

    // TODO can the alignment overlap more than one region?
    StackRegionPtr &prevRegion = regions[regions.size() - 2];
    if(REGION_TYPE(prevRegion->getFlags()) == x86Region::R_CalleeSave) return;

    // Any slots that overlap with the alignment region must actually be moved
    // to the alignment region since the alignment was marked immovable (e.g.,
    // allocated by a push instruction)
    std::vector<SlotMap> &alignSlots = alignRegion->getSlots(),
                         &prevSlots = prevRegion->getSlots();
    const SlotMap &alignSlot = alignRegion->getSlots().front();
    alignStart = alignSlot.original - alignSlot.size;
    while(prevSlots.size() && prevSlots.back().original > alignStart) {
      tmp = prevSlots.back();
      prevSlots.pop_back();
      alignSlots.push_back(tmp);
      movedSlot = true;

      DEBUGMSG(" -> moving slot @ " << tmp.original << " to alignment region"
               << std::endl);
    }
    if(!movedSlot) return;
    assert(alignSlots.size() > 1 && "Couldn't move slots");

    // Sort the alignment region with the new slots and prune the padding slot
    // to not overlap with any other slots
    alignRegion->sortSlots();
    SlotMap &align = alignSlots.back(),
            &moved = alignSlots[alignSlots.size() - 2];
    assert(align.original != moved.original && "Unhandled complete overlap");
    if(moved.original > alignStart)
      align.size = align.original - moved.original;

    // Finally, re-calculate offsets of/prune any changed regions
    curOffset = regions[regions.size() - 3]->getOriginalRegionOffset();
    for(i = regions.size() - 2; i < regions.size(); i++) {
      if(regions[i]->numSlots() > 0) {
        StackRegionPtr &region = regions[i];
        const SlotMap &bottom = region->getSlots().back();
        region->setRegionOffset(bottom.original);
        region->setRegionSize(bottom.original - curOffset);
        curOffset = bottom.original;
      }
      else {
        DEBUGMSG_VERBOSE("removing empty "
                         << x86RegionName[REGION_TYPE(regions[i]->getFlags())]
                         << " region" << std::endl);
        regions.erase(regions.begin() + i);
        i--;
      }
    }
  }

  void fixupCallRegion() {
    size_t i, j;
    int curOffset;

    // The regions sizes for SP-based offsets may have been artificially
    // inflated due to frame alignment restrictions
    for(i = regions.size() - 1; i > 0; i--) {
      StackRegionPtr &region = regions[i];
      if(REGION_TYPE(region->getFlags()) != x86Region::R_SPLimited &&
         REGION_TYPE(region->getFlags()) != x86Region::R_Call) break;

      // We didn't know sizes of call region slots during analysis but now that
      // we've seen all slots, fix those up here
      if(REGION_TYPE(region->getFlags()) == x86Region::R_Call) {
        assert(i > 0 && "Invalid stack frame regions");
        std::vector<SlotMap> &crSlots = region->getSlots();
        curOffset = regions[i - 1]->getOriginalRegionOffset();
        for(j = 0; j < crSlots.size(); j++) {
          crSlots[j].size = crSlots[j].original - curOffset;
          crSlots[j].alignment = std::min<int>(crSlots[j].size, 8);
          curOffset = crSlots[j].original;
        }
        assert(curOffset == region->getOriginalRegionOffset() &&
               "Invalid slot sizes for call region");
      }

      const SlotMap &first = region->getSlots().front();
      region->setRegionSize(region->getOriginalRegionOffset() -
                            (first.original - first.size));

      DEBUGMSG_VERBOSE("updated region size for " <<
                       x86RegionName[REGION_TYPE(region->getFlags())]
                       << " region to " << region->getOriginalRegionSize()
                       << std::endl);
    }
  }

  virtual ret_t finalizeAnalysis() override {
    int curOffset = 0;
    size_t i;

    // Put the slots for which we did not detect a restriction into sections
    if(maxFrameSize == UINT32_MAX) populateMovable();
    else populateWithRestrictions();

    // Calculate section offsets & prune empty sections.
    curOffset = regions[0]->getOriginalRegionOffset();
    for(i = 1; i < regions.size(); i++) {
      if(regions[i]->numSlots() > 0) {
        StackRegionPtr &region = regions[i];
        // TODO is it faster to search through unsorted slots in each section
        // to find the bottom offset?
        region->sortSlots();
        const SlotMap &bottom = region->getSlots().back();
        region->setRegionOffset(bottom.original);
        region->setRegionSize(bottom.original - curOffset);
        curOffset = bottom.original;
      }
      else {
        DEBUGMSG_VERBOSE("removing empty "
                         << x86RegionName[REGION_TYPE(regions[i]->getFlags())]
                         << " region" << std::endl);
        regions.erase(regions.begin() + i);
        i--;
      }
    }

    fixupAlignmentRegion();
    fixupCallRegion();

    assert((uint32_t)regions.back()->getOriginalRegionOffset() <=
           maxFrameSize);

    return RandomizedFunction::finalizeAnalysis();
  }

  virtual ret_t randomize(int seed, size_t maxPadding) override {
    int start;
    size_t nslots;
    ssize_t i, slotIdx;
    ZeroPad zp;

    ret_t code = RandomizedFunction::randomize(seed, maxPadding);
    if(code != ret_t::Success) return code;

    // Due to alignment restrictions, we may have increased the frame size,
    // invalidating previously-calculated SP-based offsets.  Update to account
    // for the new size.
    // TODO this is incorrect for SP-limited offsets
    start = randomizedFrameSize;
    slotIdx = curRand->size();
    for(i = regions.size() - 1; i >= 0; i--) {
      if(REGION_TYPE(regions[i]->getFlags()) != x86Region::R_SPLimited &&
         REGION_TYPE(regions[i]->getFlags()) != x86Region::R_Call) break;

      StackRegionPtr &r = regions[i];
      if(start == r->getRandomizedRegionOffset()) break;
      start -= r->getRandomizedRegionSize();
      r->calculateOffsets<ZeroPad>(0, start, zp);
      nslots = r->getSlots().size();
      slotIdx -= nslots;
      memcpy(&curRand->at(slotIdx),
             &r->getSlots()[0],
             sizeof(SlotMap) * nslots);

      DEBUG_VERBOSE(
        DEBUGMSG_VERBOSE("updated "
                         << x86RegionName[REGION_TYPE(r->getFlags())]
                         << " region slots:" << std::endl);
        for(auto &sm : r->getSlots()) {
          DEBUGMSG_VERBOSE("  " << sm.original << " -> " << sm.randomized
                           << std::endl);
        }
      )
    }

    return ret_t::Success;
  }

  /**
   * For x86-64, the bulk frame update allocates space for all regions below
   * the callee-save region; search for an update within that region.
   */
  virtual bool isBulkFrameUpdate(instr_t *instr, int offset) const override {
    switch(instr_get_opcode(instr)) {
    default: return false;
    case OP_add: case OP_sub:
      // Note: it should be okay to check against the original offset as the
      // callee-save region shouldn't change size
      if(offset > regions[0]->getOriginalRegionOffset()) return true;
      else return false;
    }
  }

  /**
   * For x86-64, the bulk update consists of the FP-limited, movable,
   * SP-limited, call and alignment regions.
   */
  virtual uint32_t getRandomizedBulkFrameUpdate() const override {
    assert(regions.size() > 1 && "No bulk frame update");
    return randomizedFrameSize - (regions[0]->getRandomizedRegionOffset());
  }

  virtual bool shouldTransformSlot(int offset) const override {
    int regionType;
    const StackRegionPtr *region = findRegion(offset);
    if(region) {
      regionType = REGION_TYPE((*region)->getFlags());
      if(regionType == x86Region::R_FPLimited ||
         regionType == x86Region::R_Movable ||
         regionType == x86Region::R_SPLimited) return true;
    }
    return false;
  }

  virtual ret_t transformInstr(uint32_t frameSize,
                               uint32_t randFrameSize,
                               instr_t *instr,
                               bool &changed) const override {
    ret_t code = ret_t::Success;

    // Note: frameSize does *not* include push/pop update
    switch(instr_get_opcode(instr)) {
    case OP_push:
      code = swapCalleeSaveReg<instr_get_src, instr_set_src>
                              (frameSize, instr, -8, changed);
      break;
    case OP_pop:
      code = swapCalleeSaveReg<instr_get_dst, instr_set_dst>
                              (frameSize, instr, 0, changed);
      break;
    default: break;
    }

    return code;
  }

private:
  uint32_t alignment;

  /**
   * Rewrite prologue/epilogue push/pop sequences according to the randomized
   * callee-save register area.
   *
   * @template GetOp function to get an operand
   * @template SetOp function to set an operand
   * @param frameSize currently calculated original frame size
   * @param instr an instruction
   * @param offset a canonicalized stack slot offset
   * @param changed output argument set to true if instruction was changed
   */
  template<opnd_t (*GetOp)(instr_t *, unsigned),
           void (*SetOp)(instr_t *, unsigned, opnd_t)>
  ret_t swapCalleeSaveReg(uint32_t frameSize,
                          instr_t *instr,
                          int offset,
                          bool &changed) const {
    const StackRegionPtr *region;
    const x86CalleeSaveRegion *cs;
    reg_id_t randReg;
    opnd_t op;

    offset =
      CodeTransformer::canonicalizeSlotOffset(frameSize,
                                              arch::RegType::StackPointer,
                                              offset);
    region = findRegion(offset);
    if(region && REGION_TYPE((*region)->getFlags()) == x86Region::R_CalleeSave) {
      assert(opnd_is_reg(GetOp(instr, 0)) && "Invalid push or pop");
      cs = static_cast<const x86CalleeSaveRegion *>((*region).get());
      randReg = cs->getRandomizedCalleeSaveReg(offset);
      if(randReg == DR_REG_NULL) return ret_t::BadTransformMetadata;
      else if(randReg != DR_REG_XBP) {
        op = opnd_create_reg(randReg);
        SetOp(instr, 0, op);
        changed = true;
      }
    }

    return ret_t::Success;
  }
};

RandomizedFunctionPtr
arch::getRandomizedFunction(const Binary &binary,
                            const function_record *func)
{ return RandomizedFunctionPtr(new x86RandomizedFunction(binary, func)); }

ret_t arch::transformStack(CodeTransformer *CT,
                           get_rand_info callback,
                           st_handle meta,
                           bool isReturn,
                           uintptr_t childSrcBase,
                           uintptr_t bufSrcBase,
                           uintptr_t childDstBase,
                           uintptr_t bufDstBase,
                           uintptr_t &sp) {
  struct user_regs_struct src;
  struct regset_x86_64 srcST, dstST;
  Process &proc = CT->getProcess();

  // Note: don't mess with FP registers - they don't contain transformable
  // content (e.g., pointers that must be fixed up) and their locations are not
  // being randomized.

  if(!proc.traceable()) return ret_t::InvalidState;
  if(proc.readRegs(src) != ret_t::Success) return ret_t::PtraceFailed;

  srcST.rip = (void *)src.rip;
  srcST.rax = src.rax;
  srcST.rdx = src.rdx;
  srcST.rcx = src.rcx;
  srcST.rbx = src.rbx;
  srcST.rsi = src.rsi;
  srcST.rdi = src.rdi;
  srcST.rbp = src.rbp;
  srcST.rsp = src.rsp;
  srcST.r8 = src.r8;
  srcST.r9 = src.r9;
  srcST.r10 = src.r10;
  srcST.r11 = src.r11;
  srcST.r12 = src.r12;
  srcST.r13 = src.r13;
  srcST.r14 = src.r14;
  srcST.r15 = src.r15;

  // Call stack transform API
  if(st_rewrite_randomized(CT, callback, meta, isReturn,
                           &srcST, (void *)childSrcBase, (void *)bufSrcBase,
                           &dstST, (void *)childDstBase, (void *)bufDstBase))
    return ret_t::TransformFailed;

  src.rip = (uintptr_t)dstST.rip;
  src.rax = dstST.rax;
  src.rdx = dstST.rdx;
  src.rcx = dstST.rcx;
  src.rbx = dstST.rbx;
  src.rsi = dstST.rsi;
  src.rdi = dstST.rdi;
  src.rbp = dstST.rbp;
  src.rsp = dstST.rsp;
  src.r8 = dstST.r8;
  src.r9 = dstST.r9;
  src.r10 = dstST.r10;
  src.r11 = dstST.r11;
  src.r12 = dstST.r12;
  src.r13 = dstST.r13;
  src.r14 = dstST.r14;
  src.r15 = dstST.r15;

  if(proc.writeRegs(src) != ret_t::Success) return ret_t::PtraceFailed;

  sp = src.rsp;
  return ret_t::Success;
}

///////////////////////////////////////////////////////////////////////////////
// DynamoRIO interface
///////////////////////////////////////////////////////////////////////////////

ret_t arch::initDisassembler() {
  bool ret = dr_set_isa_mode(GLOBAL_DCONTEXT, DR_ISA_AMD64, nullptr);
  if(!ret) return ret_t::DisasmSetupFailed;
  else return ret_t::Success;
}

enum arch::RegType arch::getRegTypeDR(reg_id_t reg) {
  switch(reg) {
  case DR_REG_XBP: return RegType::FramePointer;
  case DR_REG_XSP: return RegType::StackPointer;
  default: return RegType::None;
  }
}

reg_id_t arch::getDRRegType(enum RegType reg) {
  switch(reg) {
  case RegType::FramePointer: return DR_REG_XBP;
  case RegType::StackPointer: return DR_REG_XSP;
  default: return DR_REG_NULL;
  }
}

/**
 * Return the immediate value used with the stack pointer in a math operation.
 * @param instr the instruction
 * @return the immediate value added to the stack pointer, or 0 if it's not a
 *         immediate used with the stack pointer
 */
static int32_t stackPointerMathImm(instr_t *instr) {
  bool valid = true;
  int32_t update = 0;
  opnd_t op;

  for(int i = 0; i < instr_num_srcs(instr); i++) {
    op = instr_get_src(instr, i);
    if(opnd_is_immed_int(op)) update = opnd_get_immed_int(op);
    else if(opnd_is_reg(op)) {
      // Ensure the register operand is the stack pointer
      if(opnd_get_reg(op) != DR_REG_XSP) {
        valid = false;
        break;
      }
    }
    else {
      // Unknown operand type
      valid = false;
      break;
    }
  }
  if(!valid) update = 0;
  return update;
}

int32_t arch::getFrameUpdateSize(instr_t *instr) {
  switch(instr_get_opcode(instr)) {
  // Updating stack pointer by an immediate
  case OP_sub: return stackPointerMathImm(instr);
  case OP_add: return -stackPointerMathImm(instr);

  // Pushing/popping values from the stack
  case OP_push:
    return CodeTransformer::getOperandSize(instr_get_src(instr, 0));
  case OP_pushf: return 8;
  case OP_pop:
    return -CodeTransformer::getOperandSize(instr_get_dst(instr, 0));
  case OP_popf: return -8;
  case OP_ret:  case OP_ret_far: return -8;

  // Instructions that modify the stack pointer in a way we don't care about
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
    return 0;

  default:
    DEBUG(WARN("Unhandled update to stack pointer" << std::endl)); return 0;
  }
}

bool
arch::getRestriction(instr_t *instr, const opnd_t &op, RandRestriction &res) {
  bool restricted = false;
  int disp;
  arch::RegType base;

  switch(instr_get_opcode(instr)) {
  // Push/pop instructions look like restricted frame references, but they're
  // also frame updates; handle separately in getStackUpdateRestriction()
  case OP_push: case OP_pushf: case OP_pop: case OP_popf: return false;

  // Similarly, ret & call instructions modify the stack pointer in a way we
  // don't care about
  case OP_ret: case OP_ret_far:
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
    return false;

  default: break;
  }

  assert(opnd_is_base_disp(op) && "Invalid operand - expected base + disp");

  // TODO if moving YMM/ZMM registers to/from the stack, do we need to increase
  // alignment to 32 or 64 bytes, respectively?

  // Because x86-64 is so darn flexible, the compiler can encode
  // displacements with varying sizes depending on the range
  disp = opnd_get_disp(op);
  base = arch::getRegTypeDR(opnd_get_base(op));
  switch(base) {
  case RegType::FramePointer:
    if(INT8_MIN <= disp && disp <= INT8_MAX &&
       !opnd_is_disp_force_full(op)) {
      res.flags = x86Restriction::F_RangeLimited;
      res.size = res.alignment = 0; // Determine when randomizing
      res.base = base;
      res.range.first = res.range.second = INT8_MIN;
      restricted = true;
    }
    break;
  case RegType::StackPointer:
    if(INT8_MIN <= disp && disp <= INT8_MAX &&
       !opnd_is_disp_force_full(op)) {
      res.flags = x86Restriction::F_RangeLimited;
      res.size = res.alignment = 0;
      res.base = base;
      res.range.first = res.range.second = INT8_MIN;
    }
    // Need to check if its a call-area slot in addRestriction()
    else res.flags = x86Restriction::F_CheckCallSlot;
    restricted = true;
    break;
  default:
    assert(false && "Invalid base register for stack slot");
    break;
  }

  return restricted;
}

bool arch::getStackUpdateRestriction(instr_t *instr,
                                     int32_t update,
                                     RandRestriction &res) {
  assert(instr_writes_to_reg(instr, getDRRegType(RegType::StackPointer),
                             DR_QUERY_DEFAULT) &&
         "Invalid stack update instruction");

  switch(instr_get_opcode(instr)) {
  case OP_push: case OP_pushf: case OP_pop: case OP_popf:
    res.flags = x86Restriction::F_Immovable;
    return true;
  case OP_sub: case OP_add:
    // Although the frame size may be larger than a byte's range, if the update
    // to the stack pointer itself is within the byte range then we must limit
    // the randomized frame size
    if((INT8_MIN + 1) <= update && update <= INT8_MAX) {
      res.flags = x86Restriction::F_FrameSizeLimited;
      return true;
    }
    /* fall through */
  default: return false;
  }
}

/**
 * Rewrite a stack pointer + immediate math instruction with a new immediate.
 * @param instr the instruction
 * @param newImm the new immediate
 * @return true if successfully rewritten or false otherwise
 */
static bool rewriteStackPointerMathImm(instr_t *instr, int32_t newImm) {
  bool valid = true;
  opnd_t op;

  for(int i = 0; i < instr_num_srcs(instr); i++) {
    op = instr_get_src(instr, i);
    if(opnd_is_immed_int(op)) {
      op = opnd_create_immed_int(newImm, opnd_get_size(op));
      instr_set_src(instr, i, op);
    }
    else if(opnd_is_reg(op)) {
      // Ensure the register operand is the stack pointer
      if(opnd_get_reg(op) != DR_REG_XSP) {
        valid = false;
        break;
      }
    }
    else {
      // Unknown operand type
      valid = false;
      break;
    }
  }

  return valid;
}

ret_t
arch::rewriteFrameUpdate(instr_t *instr, int32_t newSize, bool &changed) {
  changed = false;
  switch(instr_get_opcode(instr)) {
  case OP_sub:
    if(!rewriteStackPointerMathImm(instr, newSize))
      return ret_t::RandomizeFailed;
    changed = true;
    break;
  case OP_add:
    if(!rewriteStackPointerMathImm(instr, -newSize))
      return ret_t::RandomizeFailed;
    changed = true;
    break;
  default: break;
  }
  return ret_t::Success;
}

#else
# error "Unsupported architecture!"
#endif

