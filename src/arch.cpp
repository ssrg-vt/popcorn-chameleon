#include "arch.h"
#include "log.h"
#include "transform.h"
#include "types.h"
#include "utils.h"

#include "regs.h"

using namespace chameleon;

#if defined __x86_64__

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

void arch::marshalSyscall(struct user_regs_struct &regs, long syscall,
                          long a1, long a2, long a3,
                          long a4, long a5, long a6) {
  regs.rax = syscall;
  regs.rdi = a1;
  regs.rsi = a2;
  regs.rdx = a3;
  regs.r10 = a4;
  regs.r8 = a5;
  regs.r9 = a6;
}

int arch::syscallRetval(struct user_regs_struct &regs) {
  return regs.rax;
}

#define DUMP_REG( regset, name ) \
  #name": " << std::dec << regset.name << " / 0x" << std::hex << regset.name

void arch::dumpRegs(struct user_regs_struct &regs) {
  INFO(DUMP_REG(regs, rax) << std::endl);
  INFO(DUMP_REG(regs, rbx) << std::endl);
  INFO(DUMP_REG(regs, rcx) << std::endl);
  INFO(DUMP_REG(regs, rdx) << std::endl);
  INFO(DUMP_REG(regs, rsi) << std::endl);
  INFO(DUMP_REG(regs, rdi) << std::endl);
  INFO(DUMP_REG(regs, rbp) << std::endl);
  INFO(DUMP_REG(regs, rsp) << std::endl);
  INFO(DUMP_REG(regs, r8) << std::endl);
  INFO(DUMP_REG(regs, r9) << std::endl);
  INFO(DUMP_REG(regs, r10) << std::endl);
  INFO(DUMP_REG(regs, r11) << std::endl);
  INFO(DUMP_REG(regs, r12) << std::endl);
  INFO(DUMP_REG(regs, r13) << std::endl);
  INFO(DUMP_REG(regs, r14) << std::endl);
  INFO(DUMP_REG(regs, r15) << std::endl);
  INFO(DUMP_REG(regs, rip) << std::endl);
  INFO(DUMP_REG(regs, cs) << std::endl);
  INFO(DUMP_REG(regs, ds) << std::endl);
  INFO(DUMP_REG(regs, es) << std::endl);
  INFO(DUMP_REG(regs, fs) << std::endl);
  INFO(DUMP_REG(regs, fs_base) << std::endl);
  INFO(DUMP_REG(regs, gs) << std::endl);
  INFO(DUMP_REG(regs, gs_base) << std::endl);
  INFO(DUMP_REG(regs, ss) << std::endl);
}

///////////////////////////////////////////////////////////////////////////////
// Stack frame information & handling
///////////////////////////////////////////////////////////////////////////////

uint32_t arch::initialFrameSize() { return 8; }

uint32_t arch::alignFrameSize(uint32_t size) { return ROUND_UP(size, 16); }

int32_t arch::framePointerOffset() { return -16; }

///////////////////////////////////////////////////////////////////////////////
// Instruction information
///////////////////////////////////////////////////////////////////////////////

uint64_t arch::syscall(size_t &size) {
  size = 2;
  return 0x050f;
}

///////////////////////////////////////////////////////////////////////////////
// Randomization implementation
///////////////////////////////////////////////////////////////////////////////

/* Restriction flags used to indicate the type of restriction */
enum x86Restriction {
  F_None = 0x0,
  F_Immovable = 0x1,
  F_RangeLimited = 0x2
};

/*
 * x86 region indexes.  Only usable *before* randomization as empty regions may
 * be pruned.  Ordered by lowest stack address.
 */
enum x86Region {
  R_Call = 0,
  R_SPLimited,
  R_Movable,
  R_FPLimited,
  R_Immovable,
  R_CalleeSave,
};

/* x86 region names (corresponds to indexs above) */
const char *x86RegionName[] {
  "call",
  "SP-limited",
  "movable",
  "FP-limited",
  "immovable",
  "callee-save",
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
    size_t i;
    ZeroPad pad;

    // We can't randomize the return address or saved RBP location; move them
    // to the front and randomize the remaining locations.
    sortSlotsReverse();
    std::shuffle(slots.begin() + 2, slots.end(), ru.gen);
    randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
    randomizedSize = origSize;
    sortSlots();
    sortRegisterSaveLocs();

    DEBUG_VERBOSE(
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
 * |    Immovable area     | | Immutable
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |     Movable area      | | Randomizable
 * |     (stack slots)     | | (see below)
 * |                       | v
 * |-----------------------|
 * |                       | ^
 * |       Call area       | | Immutable
 * | (arguments, red zone) | |
 * |                       | v
 * |-----------------------|
 *
 * Within the movable area there are restrictions depending on the original
 * placement of stack slots.  x86-64 allows 1-byte displacements for base +
 * displacement memory references; the displacement for these objects cannot
 * fall outside -128 <-> 127, meaning the randomizer is limited in what it can
 * do with these slots.  Thus
 *
 * Note 1: we don't move stack objects between their original regions as it may
 * create incorrect behavior.  For example, moving a stack slot from the
 * completely randomizable area into a restricted randomizable area may violate
 * the restrictions on those objects.
 *
 * Note 2: we assume all immovable objects are in a contiguous region adjacent
 * to the callee-save region
 */
// TODO we don't do any checking regarding if a single stack slot is accessed
// via both frame and stack pointer or crosses regions and thus could
// potentially fall into one or more regions
class x86RandomizedFunction : public RandomizedFunction {
public:
  x86RandomizedFunction(const Binary &binary, const function_record *func)
    : RandomizedFunction(binary, func), alignment(16) {
    int offset;
    size_t size, regionSize = 0;

    // Add the callee-save slots to the callee-save area
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
    cs->setRegionOffset(-regionSize);
    cs->setRegionSize(regionSize);

    // Add x86-specific regions ordered by lowest stack address first.
    // TODO is it possible to have immovable stack slots interspersed with
    // movable ones?
    regions.emplace_back(new ImmutableRegion(x86Region::R_Call));
    regions.emplace_back(new PermutableRegion(x86Region::R_SPLimited));
    regions.emplace_back(new RandomizableRegion(x86Region::R_Movable));
    regions.emplace_back(new PermutableRegion(x86Region::R_FPLimited));
    regions.emplace_back(new ImmutableRegion(x86Region::R_Immovable));
    regions.push_back(StackRegionPtr(cs));
  }

  virtual uint32_t getFrameAlignment() const override { return alignment; }

  virtual ret_t addRestriction(const RandRestriction &res) override {
    bool foundSlot = false;
    int offset = res.offset;
    uint32_t size = res.size, alignment = res.alignment;
    ret_t code = ret_t::Success;
    std::pair<int, const stack_slot *> slot;

    // Convert offsets to their containing slots, if any
    slot = findSlot(offset);
    if(slot.first != INT32_MAX) {
      offset = slot.first;
      size = slot.second->size;
      alignment = slot.second->alignment;
      foundSlot = true;
    }

    // Avoid adding multiple restrictions for a single slot
    // TODO what if there are multiple types of restrictions for a single stack
    // slot, e.g., one use causes a FP-limited displacement and another causes
    // the slot to be immovable?
    if(seen.count(offset)) return code;
    else seen.insert(offset);

    // Add to the appropriate region depending on the restriction type
    switch(res.flags) {
    case x86Restriction::F_Immovable:
      if(!regions[x86Region::R_CalleeSave]->contains(offset)) {
        // Some functions (e.g., Popcorn's migration library) access offsets
        // beyond the frame size in the metadata; ignore thoses accesses.
        if(abs(offset) <= func->frame_size) {
          regions[x86Region::R_Immovable]->addSlot(offset, size, alignment);
          DEBUGMSG(" -> cannot randomize slot @ " << offset << " (size = "
                   << size << ")" << std::endl);
        }
      }
      else DEBUGMSG(" -> callee-saved register @ " << offset << " (size = "
                    << size << ")" << std::endl);
      break;
    case x86Restriction::F_RangeLimited:
      // Set the size & alignment if we couldn't determine during analysis
      // TODO can we assume 8 byte size/alignment?
      if(!size) size = alignment = 8;

      switch(res.base) {
      case arch::RegType::FramePointer:
        regions[x86Region::R_FPLimited]->addSlot(offset, size, alignment);
        DEBUGMSG(" -> slot @ " << offset
                 << " limited to 1-byte displacements from FP" << std::endl);
        break;
      case arch::RegType::StackPointer:
        // The metadata doesn't contain slot infor for the call area
        if(foundSlot) {
          regions[x86Region::R_SPLimited]->addSlot(offset, size, alignment);
          DEBUGMSG(" -> slot @ " << offset
                   << " limited to 1-byte displacements from SP" << std::endl);
        }
        else {
          regions[x86Region::R_Call]->addSlot(offset, size, alignment);
          DEBUGMSG(" -> call-area slot @ " << offset << std::endl);
        }
        break;
      default: code = ret_t::AnalysisFailed; break;
      }

      break;
    default:
      DEBUGMSG("invalid x86 restriction type: " << res.flags << std::endl);
      code = ret_t::AnalysisFailed;
      break;
    }

    return code;
  }

  /**
   * For x86-64, the bulk frame update allocates space for all regions below
   * the callee-save/immovable region; search for an update within that region.
   */
  virtual bool transformBulkFrameUpdate(int offset) const override {
    int regType;
    size_t i;

    // Note: the immovable region may have been pruned if it was empty
    for(i = 0; i < regions.size(); i++) {
      regType = REGION_TYPE(regions[i]->getFlags());
      if(regType == x86Region::R_Immovable ||
         regType == x86Region::R_CalleeSave) break;
    }

    assert(i < regions.size() && "Invalid x86-64 stack layout");

    if(offset < regions[i]->getOriginalRegionOffset()) return true;
    else return false;
  }

  /**
   * For x86-64, the bulk update consists of the movable & call regions.
   */
  virtual uint32_t getRandomizedBulkFrameUpdate() const override {
    int regType;
    size_t i;

    // Note: the immovable region may have been pruned if it was empty
    for(i = 0; i < regions.size(); i++) {
      regType = REGION_TYPE(regions[i]->getFlags());
      if(regType == x86Region::R_Immovable ||
         regType == x86Region::R_CalleeSave) break;
    }

    // If calling this function, need at least the callee-saved & one of the
    // movable/call regions
    assert(i != 0 && i != regions.size() && "Invalid x86-64 stack layout");

    return randomizedFrameSize + (regions[i]->getRandomizedRegionOffset());
  }

  virtual bool transformOffset(int offset) const override {
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

protected:
  virtual ret_t populateSlots() override {
    int curOffset = 0;
    ssize_t i;
    ret_t code = ret_t::Success;

    // Add stack slots to the movable region.  During analysis we should have
    // added any restricted slots to their appropriate sections; the remaining
    // slots are completely randomizable.
    for(auto &s : slots) {
      if(!seen.count(s.first)) {
        const stack_slot *slot = s.second;
        regions[x86Region::R_Movable]->addSlot(s.first,
                                               slot->size,
                                               slot->alignment);
        DEBUGMSG(" -> randomizable slot @ " << s.first << " (size = "
                 << slot->size << ")" << std::endl);
      }
    }

    // Calculate section offsets & prune empty sections.  Note that regions are
    // in reverse order (lowest stack address first).
    // TODO is it faster to search through unsorted slots in each section to
    // find the bottom offset?
    for(i = regions.size() - 1; i >= 0; i--) {
      if(regions[i]->numSlots() > 0) {
        StackRegionPtr &region = regions[i];
        region->sortSlots();
        const SlotMap &bottom = region->getSlots()[0];
        region->setRegionOffset(bottom.original);
        region->setRegionSize(abs(bottom.original - curOffset));
        curOffset = bottom.original;
      }
      else {
        DEBUGMSG_VERBOSE("removing empty "
                         << x86RegionName[REGION_TYPE(regions[i]->getFlags())]
                         << " region" << std::endl);
        regions.erase(regions.begin() + i);
      }
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
      if(randReg == DR_REG_NULL) return ret_t::BadMetadata;
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

  // Instructions that modify the stack pointer in a way we don't care about
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
  case OP_ret:  case OP_ret_far: return 0;

  default: WARN("Unhandled update to stack pointer" << std::endl); return 0;
  }
}

bool arch::getRestriction(instr_t *instr, opnd_t op, RandRestriction &res) {
  bool restricted = false;
  int disp;
  arch::RegType base;

  switch(instr_get_opcode(instr)) {
  // Push/pop instructions look like restricted frame references, but they're
  // also frame updates; handle separately in other version of getRestriction()
  case OP_push: case OP_pushf: case OP_pop: case OP_popf: return false;

  // Similarly, ret & call instructions modify the stack pointer in a way we
  // don't care about
  case OP_ret: case OP_ret_far:
  case OP_call: case OP_call_ind: case OP_call_far: case OP_call_far_ind:
    return false;

  default: break;
  }

  // TODO if moving YMM/ZMM registers to/from the stack, do we need to increase
  // alignment to 32 or 64 bytes, respectively?

  if(opnd_is_base_disp(op)) {
    // Because x86-64 is so darn flexible, the compiler can encode
    // displacements with varying sizes depending on the range
    disp = opnd_get_disp(op);
    base = arch::getRegTypeDR(opnd_get_base(op));
    switch(base) {
    case RegType::FramePointer: case RegType::StackPointer:
      if(INT8_MIN <= disp && disp <= INT8_MAX &&
         !opnd_is_disp_force_full(op)) {
        res.flags = x86Restriction::F_RangeLimited;
        res.size = res.alignment = 0; // Determine when randomizing
        res.base = base;
        res.range.first = INT8_MIN;
        res.range.second = INT8_MAX;
        restricted = true;
      }
      break;
    default: break;
    }
  }
  return restricted;
}

bool arch::getRestriction(instr_t *instr, RandRestriction &res) {
  switch(instr_get_opcode(instr)) {
  case OP_push: case OP_pushf: case OP_pop: case OP_popf:
    res.flags = x86Restriction::F_Immovable;
    return true;
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

