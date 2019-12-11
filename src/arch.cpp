#include "arch.h"
#include "log.h"
#include "transform.h"
#include "types.h"
#include "utils.h"

#include "regs.h"

#include <array>

using namespace chameleon;

#if defined __x86_64__

namespace {

/* Where to add new instruction */
enum Position { FRONT, BACK };

void debugPrintAddedInstr(instr_t &instr, Position position = BACK) {
  DEBUG_VERBOSE(
    DEBUGMSG_INSTR("  + size = " << instr_length(GLOBAL_DCONTEXT, &instr)
                   << " " << (position == FRONT ? "(prepend) " : ""), &instr);
  )
}

void debugPrintDeletedInstr(instr_t &instr, Position position = BACK) {
  DEBUG_VERBOSE(
    DEBUGMSG_INSTR("  - size = " << instr_length(GLOBAL_DCONTEXT, &instr)
                   << " " << (position == FRONT ? "(prepend) " : ""), &instr);
  )
}

/**
 * Add a new instruction to the back of a list of instructions and set it up
 * for inserting into a function.
 *
 * @param instr A new instruction to be initialized
 * @param opcode The instruction's opcode
 * @param srcs Source operands
 * @param dsts Destination operands
 * @param position Where to insert the new instruction
 * @return a reference to the newly added instruction
 */
template <size_t NSrc, size_t NDst>
instr_t &addInstruction(std::vector<instr_t> &instrs,
                        int opcode,
                        const std::array<opnd_t, NSrc> &srcs,
                        const std::array<opnd_t, NDst> &dsts,
                        Position position = BACK) {
  std::vector<instr_t>::iterator insertPosition;
  switch(position) {
  case FRONT:
    insertPosition = instrs.begin();
    break;
  case BACK:
    insertPosition = instrs.end();
    break;
  default:
    ERROR("Unhandled enum value" << std::endl);
    assert(false && "Unhandled enum value");
  }

  instr_t &instr = *instrs.emplace(insertPosition);
  instr_init(GLOBAL_DCONTEXT, &instr);
  instr_set_opcode(&instr, opcode);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &instr, dsts.size(), srcs.size());
  for(size_t i = 0; i < srcs.size(); i++) {
    instr_set_src(&instr, i, srcs[i]);
  }
  for(size_t i = 0; i < dsts.size(); i++) {
    instr_set_dst(&instr, i, dsts[i]);
  }
  return instr;
}

/**
 * Replace a subset of instructions in a run with new instructions.
 * @param instrs instruction being modified
 * @param start iterator to start of range of instructions being replaced
 * @param end iterator to end of range of instructions being replaced (not
 * inclusive)
 * @param newInstrs new instructions to put in instruction run
 * @bufferStart start of instruction memory buffer to encode new instructions
 */
ret_t replaceInstructionsInRun(InstructionRun &instrs,
                               std::vector<instr_t>::iterator start,
                               std::vector<instr_t>::iterator end,
                               std::vector<instr_t> newInstrs,
                               app_pc bufferStart) {
  std::vector<instr_t> fullRun;
  fullRun.reserve(instrs.instrs.size()); // Probably too big but close enough

  // Copy instructions before the range being replaced into new vector
  auto it = instrs.instrs.begin(), e = instrs.instrs.end();
  while(it != start) {
    DEBUG_VERBOSE(DEBUGMSG_INSTR("  keep   -> ", &*it));

    fullRun.emplace_back(std::move(*it));
    it++;
  }
  assert(it != e && "Invalid replacement range");

  // Copy new instructions into the vector & encode into buffer
  app_pc real = instr_get_app_pc(&*start);
  for(auto &instr : newInstrs) {
    DEBUG_VERBOSE(DEBUGMSG_INSTR("  add    -> ", &instr));

    byte *instrEnd = instr_encode_to_copy(GLOBAL_DCONTEXT, &instr,
                                          bufferStart, real);
    if(!instrEnd) return ret_t::TransformFailed;
    size_t size = instrEnd - bufferStart;
    instr_set_raw_bits(&instr, bufferStart, size);
    bufferStart += size;
    real += size;

    fullRun.emplace_back(std::move(instr));
  }

  // If end is the sentinal end iterator, then it doesn't actually point to an
  // instruction and we need to manually calculate the end address using the
  // last instruction
  app_pc endAddr;
  if(end == e) {
    auto prev = end - 1;
    endAddr = instr_get_app_pc(&*prev) + instr_length(GLOBAL_DCONTEXT, &*prev);
  } else {
    endAddr = instr_get_app_pc(&*end);
  }

  if(real != endAddr) {
    DEBUGMSG("New instructions not the same size, expected " << std::hex
             << (uintptr_t)endAddr << " but got "
             << (uintptr_t)real << std::endl);
    return ret_t::TransformFailed;
  }

  // Clean up range being replaced
  // TODO do before encoding new instructions?
  size_t numNops = 0;
  while(it != end) {
    DEBUG_VERBOSE(
      if(instr_get_opcode(&*it) == OP_nop) numNops++;
      else {
        if(numNops > 0) {
          DEBUGMSG("  remove -> nop x " << numNops << std::endl);
          numNops = 0;
        }
        DEBUGMSG_INSTR("  remove -> ", &*it)
      }
    );

    instr_free(GLOBAL_DCONTEXT, &*it);
    it++;
  }

  // Copy instructions after the range being replaced into new vector
  while(it != e) {
    DEBUG_VERBOSE(DEBUGMSG_INSTR("  keep   -> ", &*it));

    fullRun.emplace_back(std::move(*it));
    it++;
  }

  instrs.instrs = std::move(fullRun);
  return ret_t::Success;
}

}

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

#define DUMP_REG( regset, reg ) \
  #reg": " << std::dec << regset.reg << " / 0x" << std::hex << regset.reg

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
    if(i % 4 == 0) os << std::endl << std::dec << "st" << (i / 4) << ": 0x";
    os << std::hex << std::setfill('0') << std::setw(8) << regs.st_space[i];
  }
  num = sizeof(regs.xmm_space) / sizeof(regs.xmm_space[0]);
  for(size_t i = 0; i < num; i++) {
    if(i % 4 == 0) os << std::endl << std::dec << "xmm" << (i / 4) << ": 0x";
    os << std::hex << std::setfill('0') << std::setw(8) << regs.xmm_space[i];
  }
  os << std::dec << std::setfill(' ') << std::endl;
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
  F_CheckCallSlot,
  F_EnsureCallSlot,
};

#define REGION_TYPE( flags ) (flags & 0x3)

/*
 * x86 regions, ordered by highest stack address.  Can be used as an index into
 * region vector during analysis (empty regions are pruned afterwards), can be
 * used to determine region type using REGION_TYPE macro with region's flags.
 */
enum x86Region {
  R_CalleeSave = 0,
  R_Movable,
  R_Call,
  R_Alignment,
};

/* x86 region names (corresponds to indexs above) */
const char *x86RegionName[] {
  "callee-save",
  "movable",
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
  x86CalleeSaveRegion(const x86CalleeSaveRegion &rhs)
    : StackRegion(rhs), registerLocs(rhs.registerLocs) {}
  StackRegion *copy() const override { return new x86CalleeSaveRegion(*this); }

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
   * Reset the callee-saved registers to their original locations.
   */
  virtual void resetSlots() override {
    StackRegion::resetSlots();
    sortRegisterSaveLocs();
  }

  virtual double entropy(int start, size_t maxPadding) const override {
    size_t size = slots.size();
    double bits;

    // TODO return address & saved FBP are currently not randomizable
    if(size <= 2) return 0.0;
    bits = entropyBits(size - 2);
    DEBUGMSG("bits of entropy (callee-save without SP/FBP): " << bits
             << " for " << size - 2 << " slot(s)" << std::endl);
    return (double)(bits * (size - 2)) / (double)size;
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
 * |     Movable area      | | Randomizable
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
 * - Arguments passed on the stack are placed according to the x86-64 calling
 *   convention and cannot be randomized because the called function expects
 *   the arguments in a certain order.
 *
 * Note: we don't move stack objects between their original regions as it may
 * create incorrect behavior.  For example, moving a stack slot from the
 * completely randomizable area into a permutable area may violate the
 * restrictions on those objects.
 */
class x86RandomizedFunction : public RandomizedFunction {
public:
  x86RandomizedFunction(const Binary &binary,
                        const function_record *func,
                        size_t maxPadding,
                        MemoryWindow &window)
    : RandomizedFunction(binary, func, maxPadding, window), alignment(16) {
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

      DEBUG(
        if(offset < 0)
          WARN("Callee-save location for register " << loc->reg
               << " is outside frame - offset from the stack pointer?"
               << std::endl);
      )
    }
    cs->setOffset(regionSize);
    cs->setSize(regionSize);

    DEBUG(
      Binary::slot_iterator si = binary.getStackSlots(func);
      Binary::unwind_iterator ui = binary.getUnwindLocations(func);
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
        DEBUGMSG("  register " << unwind->reg << " at FBP + " << unwind->offset
                 << std::endl);
      }
      si.reset();
      ui.reset();
    )

    // Add x86-specific regions ordered by highest stack address first.
    regions.push_back(StackRegionPtr(cs));
    // Don't spill into the callee-saved region; due to randomization we may
    // shrink offset encodings to smaller sizes and change the size of code
    regions.emplace_back(
      new RandomizableRegion(x86Region::R_Movable, regionSize));
    regions.emplace_back(new ImmutableRegion(x86Region::R_Call));
    regions.emplace_back(new ImmutableRegion(x86Region::R_Alignment));
  }

  x86RandomizedFunction(const x86RandomizedFunction &rhs,
                        MemoryWindow &mw)
    : RandomizedFunction(rhs, mw), alignment(rhs.alignment) {}

  virtual RandomizedFunction *copy(MemoryWindow &mw) const override
  { return new x86RandomizedFunction(*this, mw); }

  virtual uint32_t getFrameAlignment() const override { return alignment; }

  virtual const char *getRegionName(const StackRegionPtr &r) const override
  { return x86RegionName[REGION_TYPE(r->getFlags())]; }

  virtual ret_t addRestriction(const RandRestriction &res) override {
    bool foundSlot = false;
    int offset = res.offset;
    uint32_t size = res.size, alignment = res.alignment;
    ret_t code = ret_t::Success;
    std::pair<int, const stack_slot *> slot;

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
    case x86Restriction::F_CheckCallSlot:
      // The metadata doesn't contain slot information for the call area
      if(!foundSlot) {
        regions[x86Region::R_Call]->addSlot(offset, 0, 0);
        DEBUGMSG(" -> call-area slot @ " << offset << std::endl);
      }
      break;
    case x86Restriction::F_EnsureCallSlot:
      // Similar to F_CheckCallSlot except the offset *must* correspond to a
      // call slot -- the instruction had an operand that cannot be randomized.
      // This happens when the compiler elides inserting bytes for a zero
      // offset in the base + offset operand.
      if(!foundSlot) {
        regions[x86Region::R_Call]->addSlot(offset, 0, 0);
        DEBUGMSG(" -> call-area slot @ " << offset << std::endl);
      }
      else {
        WARN(" -> slot @ " << offset << " cannot be randomized because "
             << "compiler didn't insert bytes for offset" << std::endl);
        code = ret_t::AnalysisFailed;
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
   * Add stack slots to the movable region.  During analysis we should have
   * added any restricted slots to their appropriate sections; the remaining
   * slots are completely randomizable.
   */
  void populateMovable() {
    StackRegionPtr &r = regions[x86Region::R_Movable];
    for(auto &s : slots) {
      if(!seen.count(s.first)) {
        const stack_slot *slot = s.second;
        r->addSlot(s.first, slot->size, slot->alignment);
        DEBUGMSG(" -> slot @ " << s.first << " (size = " << slot->size
                 << ") is in " << x86RegionName[x86Region::R_Movable]
                 << " region" << std::endl);
      }
    }
  }

  void calculateRegionOffsets(size_t start, bool sort = true) {
    int curOffset, origOffset, newOffset, bubble;
    size_t i;

    assert(start > 0 && "Invalid starting index");

    // Start by pruning empty regions
    for(i = start; i < regions.size(); i++) {
      if(regions[i]->numSlots() == 0) {
        DEBUGMSG_VERBOSE("removing empty "
                         << x86RegionName[REGION_TYPE(regions[i]->getFlags())]
                         << " region" << std::endl);
        regions.erase(regions.begin() + i);
        i--;
      }
    }

    // Next, calculate offsets & sizes
    curOffset = regions[start-1]->getOriginalOffset();
    for(i = start; i < regions.size(); i++) {
      StackRegionPtr &region = regions[i];
      if(sort) region->sortSlots();
      const std::vector<SlotMap> &slots = region->getSlots();
      const SlotMap &top = slots.front(), bottom = slots.back();

      // It's possible due to layout of slots with different sizes that
      // there's a "bubble" of empty space in the frame
      bubble = (int)(top.original - top.size) - curOffset;
      DEBUG(
        // Note: the alignment region is itself a bubble; we'll fix up any
        // overlaps in fixupAlignmentRegion().  The call region's slot sizes
        // aren't determined until fixupCallRegion() so skip here because the
        // assert may detect overlapping slots in some cases (there aren't
        // actually any bubbles because we conservatively assume the call
        // slot extends until the preceding slot).
        if(REGION_TYPE(region->getFlags()) != x86Region::R_Alignment) {
          assert(bubble >= 0 && "Overlapping regions");
          DEBUG(
            if(bubble && REGION_TYPE(region->getFlags()) != x86Region::R_Call)
              DEBUGMSG(" -> bubble: " << curOffset << " - "
                       << top.original - top.size << std::endl);
          );
        }
      )

      // Extend the preceding region to cover the bubble.  Note that it's
      // possible to have a negative bubble with the alignment region (due to
      // overlaps); just ignore for now.
      if(bubble > 0 &&
         REGION_TYPE(regions[i-1]->getFlags()) != x86Region::R_CalleeSave &&
         REGION_TYPE(region->getFlags()) != x86Region::R_Call) {
        StackRegionPtr &prev = regions[i-1];
        origOffset = prev->getOriginalOffset();
        newOffset = std::min(prev->getMaxOffset(), origOffset + bubble);
        prev->setOffset(newOffset);
        prev->setSize(prev->getOriginalSize() + newOffset - origOffset);
        curOffset += bubble;

        DEBUG(
          assert(newOffset >= origOffset && "Invalid offset extension");
          if(newOffset > origOffset)
            DEBUGMSG( "extended " << x86RegionName[prev->getFlags()]
                     << " region to " << prev->getOriginalOffset()
                     << std::endl);
        )
      }

      region->setOffset(bottom.original);
      region->setSize(bottom.original - curOffset);
      curOffset = bottom.original;

      DEBUGMSG_VERBOSE(x86RegionName[region->getFlags()] << " region size: "
                       << region->getOriginalSize() << std::endl);
    }
  }

  /**
   * Fix up cases where the alignment region overlaps slots in another region.
   */
  void fixupAlignmentRegion() {
    bool movedSlot = false;
    int alignStart;
    SlotMap tmp;

    StackRegionPtr &alignRegion = regions.back();
    if(REGION_TYPE(alignRegion->getFlags()) != x86Region::R_Alignment) return;

    assert(regions.size() > 1 && "Invalid stack regions");
    assert(alignRegion->numSlots() == 1 && "Invalid alignment region");

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

    // Sort the alignment region with the new slots and prune the padding slot
    // to not overlap with any other slots
    alignRegion->sortSlots();
    SlotMap &align = alignSlots.back(),
            &moved = alignSlots[alignSlots.size() - 2];
    assert(align.original != moved.original &&
           "Alignment completely overlaps slot");
    if(moved.original > alignStart)
      align.size = align.original - moved.original;

    // Finally, re-calculate offsets of/prune any changed regions
    calculateRegionOffsets(regions.size() - 2, false);
  }

  /**
   * We can't determine the call region's characteristics until we've seen all
   * the other slots in the function.  Fix up call region size/offset and
   * sizes/alignments of individual slots.
   */
  void fixupCallRegion() {
    size_t i, j;
    int curOffset;

    // The region sizes for SP-based offsets may have been artificially
    // inflated due to frame alignment restrictions
    for(i = regions.size() - 1; i > 0; i--) {
      StackRegionPtr &region = regions[i];
      if(REGION_TYPE(region->getFlags()) != x86Region::R_Call) break;

      // We didn't know sizes of call region slots during analysis but now that
      // we've seen all slots, fix those up here
      assert(i > 0 && "Invalid stack frame regions");
      std::vector<SlotMap> &callSlots = region->getSlots();
      curOffset = regions[i - 1]->getOriginalOffset();
      for(j = 0; j < callSlots.size(); j++) {
        callSlots[j].size = callSlots[j].original - curOffset;
        callSlots[j].alignment = std::min<int>(callSlots[j].size, 8);
        curOffset = callSlots[j].original;
      }
      assert(curOffset == region->getOriginalOffset() &&
             "Invalid slot sizes for call region");

      const SlotMap &first = region->getSlots().front();
      region->setSize(region->getOriginalOffset() -
                      (first.original - first.size));

      DEBUGMSG_VERBOSE("updated region size for " <<
                       x86RegionName[REGION_TYPE(region->getFlags())]
                       << " region to " << region->getOriginalSize()
                       << std::endl);
    }
  }

  std::vector<StackRegionPtr>::iterator findRegionByType(x86Region type) {
    std::vector<StackRegionPtr>::iterator it;
    for(it = regions.begin(); it != regions.end(); it++) {
      if(REGION_TYPE((*it)->getFlags()) == type) return it;
    }
    return it;
  }

  void moveCalleeSaveToRandomizable() {
    int offset;
    size_t size;

    auto calleeSaveIt = findRegionByType(x86Region::R_CalleeSave);
    assert(calleeSaveIt!= regions.end() && "No callee-save region");
    auto &calleeSave = *calleeSaveIt;

    // If there's no fully randomizable region, make one
    auto randomizableIt = findRegionByType(x86Region::R_Movable);
    if(randomizableIt == regions.end()) {
      regions.emplace_back(new RandomizableRegion(x86Region::R_Movable));
      randomizableIt = regions.end() - 1;
      (*randomizableIt)->setOffset(calleeSave->getOriginalOffset());
    }
    auto &randomizable = *randomizableIt;

    DEBUGMSG_VERBOSE("moving callee-save slots to fully randomizable region"
                     << std::endl);

    Binary::unwind_iterator ui = binary.getUnwindLocations(func);
    for(; !ui.end(); ++ui) {
      const unwind_loc *loc = *ui;
      size = arch::getCalleeSaveSize(loc->reg);
      offset =
        CodeTransformer::canonicalizeSlotOffset(func->frame_size,
                                                arch::RegType::FramePointer,
                                                loc->offset);
      randomizable->addSlot(offset, size, size);

      DEBUGMSG_VERBOSE("  slot @ " << offset << ", size=" << size
                       << std::endl);
    }

    randomizable->setMinStartingOffset(0);
    randomizable->setMaxOffset(INT32_MAX);
    randomizable->setSize(randomizable->getOriginalOffset());
    randomizable->sortSlots();

    DEBUGMSG("updated fully randomizable region to hold callee-save slots, "
             "new size = " << randomizable->getOriginalOffset() << std::endl);

    regions.erase(calleeSaveIt);
    DEBUGMSG("removed permutable callee-save region" << std::endl);
    // TODO do we need to remove alignment region?
  }

  virtual ret_t rewritePrologueAndEpilogue() override {
    ret_t code;
    bool foundPrologue = false, foundEpilogue = false;
    int calleeSaveOffset;

    for(auto &instrRun : instrs) {
      bool containsPrologue = false, containsEpilogue = false;
      for(auto &instr : instrRun.instrs) {
        if(isCalleeSavePush(instr)) containsPrologue = true;
        if(isCalleeSavePop(instr)) containsEpilogue = true;
      }
      instrRun.containsPrologue = containsPrologue;
      instrRun.containsEpilogue = containsEpilogue;

      foundPrologue |= containsPrologue;
      foundEpilogue |= containsEpilogue;

      if(containsPrologue) {
        DEBUGMSG("prologue at 0x" << std::hex << (uint64_t)instrRun.startAddr
                 << " - 0x" << (uint64_t)instrRun.endAddr << std::endl);
        code = rewritePrologueForRandomization(instrRun, calleeSaveOffset);
        if(code != ret_t::Success) return code;
      }
      if(containsEpilogue) {
        DEBUGMSG("epilogue at 0x" << std::hex << (uint64_t)instrRun.startAddr
                 << " - 0x" << (uint64_t)instrRun.endAddr << std::endl);
        code = rewriteEpilogueForRandomization(instrRun, calleeSaveOffset);
        if(code != ret_t::Success) return code;
      }
    }

    // This is not necessarily an error because a function may not expect to
    // clean up, e.g., __libc_start_main ends by calling exit()
    if(!foundEpilogue) WARN("Could not find epilogue for function @ "
                            << std::hex << func->addr << std::endl);

    if(!foundPrologue) return ret_t::AnalysisFailed;

    moveCalleeSaveToRandomizable();

    return ret_t::Success;
  }

  virtual ret_t
  rewritePrologueForRandomization(InstructionRun &instrs,
                                  int &calleeSaveOffset) override {
    int spUpdate = 0;
    size_t origSize = 0, newSize;
    opnd_t src, src2, dst;
    std::vector<instr_t> newInstrs;

    DEBUGMSG_VERBOSE("rewriting prologue" << std::endl);

    // Move the return address from its original location to the "new" slot
    // (which will eventually be randomized)
    src = opnd_create_base_disp(DR_REG_RSP, DR_REG_NULL, 0, 0, OPSZ_8);
    dst = opnd_create_reg(DR_REG_RAX);
    instr_t &movToReg = addInstruction<1, 1>(newInstrs, OP_movq,
                                             {{src}}, {{dst}});
    newSize = instr_length(GLOBAL_DCONTEXT, &movToReg);

    src = dst;
    dst = opnd_create_base_disp_ex(DR_REG_RSP, DR_REG_NULL, 0, 0, OPSZ_8, true,
                                   true, false);
    instr_t &movToStack = addInstruction<1, 1>(newInstrs, OP_movq,
                                               {{src}}, {{dst}});
    newSize += instr_length(GLOBAL_DCONTEXT, &movToStack);

    for(auto &instr : newInstrs) debugPrintAddedInstr(instr);

    // Walk through the prologue, converting push into movq instructions and
    // updating the frame allocation math to include the callee-save space
    calleeSaveOffset = 0;
    auto it = instrs.instrs.begin();
    for(auto e = instrs.instrs.end(); it != e; it++) {
      auto &instr = *it;
      bool finished = false;

      switch(instr_get_opcode(&instr)) {
      case OP_nop: break;
      case OP_push:
        assert(opnd_is_reg(instr_get_src(&instr, 0)));
        if(!isCalleeSavePush(instr)) {
          assert(opnd_is_reg(instr_get_src(&instr, 0)) &&
                 opnd_get_reg(instr_get_src(&instr, 0)) == DR_REG_RAX &&
                 "Unhandled frame setup instruction");
          assert(spUpdate == 0 && "Multiple SP update instructions?");

          // The compiler inserted a push %rax to align/alllocate stack space
          // for the frame, convert to subtraction instruction
          spUpdate = abs(calleeSaveOffset) + 8;
          src = opnd_create_immed_int(spUpdate, OPSZ_4);
          src2 = opnd_create_reg(DR_REG_RSP);
          dst = opnd_create_reg(DR_REG_RSP);
          addInstruction<2, 1>(newInstrs, OP_sub, {{src, src2}}, {{dst}});
          break;
        }

        calleeSaveOffset -= 8;
        src = opnd_create_reg(opnd_get_reg(instr_get_src(&instr, 0)));
        dst = opnd_create_base_disp_ex(DR_REG_RSP, DR_REG_NULL, 0,
                                       calleeSaveOffset, OPSZ_8, true,
                                       true, false);
        addInstruction<1, 1>(newInstrs, OP_movq, {{src}}, {{dst}});
        break;
      case OP_mov_st:
        src = instr_get_src(&instr, 0);
        dst = instr_get_dst(&instr, 0);
        // If it's not mov %rsp, %rbp then it's not part of the prologue
        if(!opnd_is_reg(src) || opnd_get_reg(src) != DR_REG_RSP ||
           !opnd_is_reg(dst) || opnd_get_reg(dst) != DR_REG_RBP) {
          finished = true;
          break;
        }

        // New rbp points to CFA - 0x10
        src = opnd_create_base_disp_ex(DR_REG_RSP, DR_REG_NULL, 0, -8,
                                       OPSZ_lea, true, true, false);
        dst = opnd_create_reg(DR_REG_RBP);
        addInstruction<1, 1>(newInstrs, OP_lea, {{src}}, {{dst}});
        break;
      case OP_sub:
        assert(opnd_is_immed_int(instr_get_src(&instr, 0)) &&
               opnd_is_reg(instr_get_src(&instr, 1)) &&
               opnd_get_reg(instr_get_src(&instr, 1)) == DR_REG_RSP &&
               opnd_is_reg(instr_get_dst(&instr, 0)) &&
               opnd_get_reg(instr_get_src(&instr, 1)) == DR_REG_RSP);
        assert(spUpdate == 0 && "Multiple SP update instructions?");

        src = instr_get_src(&instr, 0);
        spUpdate = opnd_get_immed_int(src) + abs(calleeSaveOffset);
        src = opnd_create_immed_int(spUpdate, OPSZ_4);
        src2 = opnd_create_reg(DR_REG_RSP);
        dst = opnd_create_reg(DR_REG_RSP);
        addInstruction<2, 1>(newInstrs, OP_sub, {{src, src2}}, {{dst}});
        break;
      default:
        // Any remaining instructions are not part of the prologue
        finished = true;
        break;
      }

      if(finished) break;

      origSize += instr_length(GLOBAL_DCONTEXT, &instr);
      if(instr_get_opcode(&instr) != OP_nop) {
        auto &newInstr = newInstrs.back();
        newSize += instr_length(GLOBAL_DCONTEXT, &newInstr);

        debugPrintDeletedInstr(instr);
        debugPrintAddedInstr(newInstr);
      }
    }

    // Add an instruction to update the SP if the prologue didn't already
    if(spUpdate == 0) {
      src = opnd_create_immed_int(abs(calleeSaveOffset), OPSZ_4);
      src2 = opnd_create_reg(DR_REG_RSP);
      dst = opnd_create_reg(DR_REG_RSP);
      auto &newInstr = addInstruction<2, 1>(newInstrs, OP_sub,
                                            {{src, src2}}, {{dst}});
      newSize += instr_length(GLOBAL_DCONTEXT, &newInstr);
      debugPrintAddedInstr(newInstr);
    }

    DEBUGMSG("size: original = " << origSize << " vs new = " << newSize
             << std::endl);

    if(origSize < newSize) {
      DEBUGMSG("not enough space to rewrite prologue" << std::endl);
      return ret_t::AnalysisFailed;
    }

    // Implant new instructions
    uint64_t offset = (uint64_t)(instrs.startAddr) - func->addr;
    return replaceInstructionsInRun(instrs,
                                    instrs.instrs.begin(),
                                    it,
                                    std::move(newInstrs),
                                    funcData[offset]);
  }

  virtual ret_t
  rewriteEpilogueForRandomization(InstructionRun &instrs,
                                  int calleeSaveOffset) override {
    int spUpdate = 0, calleeSaveSize = abs(calleeSaveOffset);
    size_t origSize = 0, newSize = 0;
    opnd_t src, src2, dst;
    std::vector<instr_t> newInstrs;

    DEBUGMSG_VERBOSE("rewriting epilogue" << std::endl);

    // Walk through the epilogue, converting pop into movq instructions and
    // updating the frame allocation math to include the callee-save space.
    // The epilogue's placement is tricky because there can be instructions in
    // the run before and/or after the epilogue instructions; the latter
    // happens when the epilogue is emitted in the middle of the function.
    auto start = instrs.instrs.end(), end = instrs.instrs.end();
    for(auto it = instrs.instrs.begin(), e = instrs.instrs.end();
        it != e;
        it++) {
      auto &instr = *it;
      bool transformed = false;

      switch(instr_get_opcode(&instr)) {
      case OP_nop:
        transformed = true;
        break;
      case OP_pop:
        assert(opnd_is_reg(instr_get_dst(&instr, 0)) &&
               isCalleeSavePop(instr));
        transformed = true;

        src = opnd_create_base_disp_ex(DR_REG_RSP, DR_REG_NULL, 0,
                                       calleeSaveOffset, OPSZ_8, true,
                                       true, false);
        dst = opnd_create_reg(opnd_get_reg(instr_get_dst(&instr, 0)));
        addInstruction<1, 1>(newInstrs, OP_movq, {{src}}, {{dst}});
        calleeSaveOffset += 8;
        break;
      case OP_add:
        assert(opnd_is_immed_int(instr_get_src(&instr, 0)) &&
               opnd_is_reg(instr_get_src(&instr, 1)) &&
               opnd_is_reg(instr_get_dst(&instr, 0)));
        assert(spUpdate == 0 && "Multiple SP update instructions?");
        transformed = true;

        src = instr_get_src(&instr, 0);
        spUpdate = opnd_get_immed_int(src) + abs(calleeSaveOffset);
        src = opnd_create_immed_int(spUpdate, OPSZ_4);
        src2 = opnd_create_reg(DR_REG_RSP);
        dst = opnd_create_reg(DR_REG_RSP);
        addInstruction<2, 1>(newInstrs, OP_add, {{src, src2}}, {{dst}});
        break;
      // We can't break out of the entire loop like in the prologue because the
      // epilogue can come *after* non-epilogue instructions
      default: break;
      }

      if(transformed) {
        // TODO handle multiple epilogues in a single instruction run
        assert(end == instrs.instrs.end() &&
               "Multiple epilogues in instruction run");

        // Mark the first instruction in the run we want transform
        if(start == instrs.instrs.end()) start = it;

        origSize += instr_length(GLOBAL_DCONTEXT, &instr);
        if(instr_get_opcode(&instr) != OP_nop) {
          auto &newInstr = newInstrs.back();
          newSize += instr_length(GLOBAL_DCONTEXT, &newInstr);

          debugPrintDeletedInstr(instr);
          debugPrintAddedInstr(newInstr);
        }
      }
      // Mark the first instruction after the end of the epilogue
      else if(start != instrs.instrs.end() && end == instrs.instrs.end())
        end = it;
    }

    // Add an instruction to update the SP if the epilogue didn't already
    if(spUpdate == 0) {
      src = opnd_create_immed_int(calleeSaveSize, OPSZ_4);
      src2 = opnd_create_reg(DR_REG_RSP);
      dst = opnd_create_reg(DR_REG_RSP);
      auto &newInstr = addInstruction<2, 1>(newInstrs, OP_add,
                                            {{src, src2}}, {{dst}}, FRONT);
      newSize += instr_length(GLOBAL_DCONTEXT, &newInstr);
      debugPrintAddedInstr(newInstr, FRONT);
    }

    // Move the return address back to its original location for the return
    // instruction.  We can't use rax or rdx as a scratch register during
    // return address restoration as they may contain return values.
    reg_id_t scratchReg = DR_REG_RCX;
    src = opnd_create_base_disp_ex(DR_REG_RSP, DR_REG_NULL, 0, 0, OPSZ_8, true,
                                   true, false);
    dst = opnd_create_reg(scratchReg);
    instr_t &movToReg = addInstruction<1, 1>(newInstrs, OP_movq,
                                             {{src}}, {{dst}});
    newSize += instr_length(GLOBAL_DCONTEXT, &movToReg);

    src = dst;
    dst = opnd_create_base_disp(DR_REG_RSP, DR_REG_NULL, 0, 0, OPSZ_8);
    instr_t &movToStack = addInstruction<1, 1>(newInstrs, OP_movq,
                                               {{src}}, {{dst}});
    newSize += instr_length(GLOBAL_DCONTEXT, &movToStack);

    DEBUG_VERBOSE(
      auto spUpdateInstr = newInstrs.end();
      spUpdateInstr -= 2;
      for(auto e = newInstrs.end(); spUpdateInstr != e; spUpdateInstr++) {
        debugPrintAddedInstr(*spUpdateInstr);
      }
    )

    DEBUGMSG("size: original = " << origSize << " vs new = " << newSize
             << std::endl);

    if(origSize < newSize) {
      DEBUGMSG("not enough space to rewrite epilogue" << std::endl);
      return ret_t::AnalysisFailed;
    }

    uint64_t offset = (uint64_t)(instrs.startAddr) - func->addr;
    return replaceInstructionsInRun(instrs,
                                    start,
                                    end,
                                    std::move(newInstrs),
                                    funcData[offset]);
  }

  virtual ret_t finalizeAnalysis() override {
    uint32_t frameSize;

    // Put the slots for which we did not detect a restriction into sections
    populateMovable();

    // Calculate section offsets & prune empty sections.
    regions[0]->sortSlots();
    calculateRegionOffsets(1);
    fixupAlignmentRegion();
    fixupCallRegion();

    // Leaf functions don't necessarily need to abide by alignment restrictions
    if(!ALIGNED(func->frame_size, 16)) {
      alignment = 1;
      frameSize = func->frame_size;
      while(!(frameSize & 0x1)) {
        alignment <<= 1;
        frameSize >>= 1;
      }
      DEBUGMSG("changed frame alignment to " << alignment << std::endl);
    }

    return RandomizedFunction::finalizeAnalysis();
  }

  virtual ret_t randomize(int seed) override {
    int start;
    size_t nslots;
    ssize_t i, slotIdx;
    ZeroPad zp;

    ret_t code = RandomizedFunction::randomize(seed);
    if(code != ret_t::Success) return code;

    // Due to alignment restrictions, we may have increased the frame size,
    // invalidating previously-calculated SP-based offsets.  Update to account
    // for the new size.
    start = randomizedFrameSize;
    slotIdx = curRand->size();
    for(i = regions.size() - 1; i >= 0; i--) {
      if(REGION_TYPE(regions[i]->getFlags()) != x86Region::R_Call) break;

      StackRegionPtr &r = regions[i];
      if(start == r->getRandomizedOffset()) break;
      start -= r->getRandomizedSize();
      r->calculateOffsets<ZeroPad>(0, start, zp);
      nslots = r->numSlots();
      slotIdx -= nslots;
      memcpy(&curRand->at(slotIdx),
             &r->getSlots()[0],
             sizeof(SlotMap) * nslots);

      DEBUG(
        DEBUGMSG("updated " << x86RegionName[REGION_TYPE(r->getFlags())]
                 << " region slots:" << std::endl);
        for(auto &sm : r->getSlots())
          DEBUGMSG("  " << sm.original << " -> " << sm.randomized
                   << std::endl);
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
      if(offset > regions[0]->getOriginalOffset()) return true;
      else return false;
    }
  }

  /**
   * For x86-64, the bulk update consists of the FP-limited, movable,
   * SP-limited, call and alignment regions.
   */
  virtual uint32_t getRandomizedBulkFrameUpdate() const override {
    assert(regions.size() > 1 && "No bulk frame update");
    return randomizedFrameSize - (regions[0]->getRandomizedOffset());
  }

  virtual bool shouldTransformSlot(int offset) const override {
    int regionType;
    const StackRegionPtr *region = findRegion(offset);
    if(region) {
      regionType = REGION_TYPE((*region)->getFlags());
      if(regionType == x86Region::R_Movable) return true;
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
   * Return whether the instruction is pushing a callee-saved register onto the
   * stack.
   *
   * @param instr instruction to check
   * @return true if the instruction is pushing a callee-saved register onto
   * the stack or false otherwise
   */
  bool isCalleeSavePush(instr_t& instr) {
    switch(instr_get_opcode(&instr)) {
    case OP_push:
      assert(opnd_is_reg(instr_get_src(&instr, 0)));
      switch(opnd_get_reg(instr_get_src(&instr, 0))) {
      case DR_REG_RBX: case DR_REG_RSP: case DR_REG_RBP: case DR_REG_R12:
      case DR_REG_R13: case DR_REG_R14: case DR_REG_R15:
        return true;
      default: return false;
      }
    default: return false;
    }
  }

  /**
   * Return whether the instruction is popping a callee-saved register off of
   * the stack.
   *
   * @param instr instruction to check
   * @return true if the instruction is popping a callee-saved register onto
   * the stack or false otherwise
   */
  bool isCalleeSavePop(instr_t& instr) {
    switch(instr_get_opcode(&instr)) {
    case OP_pop:
      assert(opnd_is_reg(instr_get_dst(&instr, 0)));
      switch(opnd_get_reg(instr_get_dst(&instr, 0))) {
      case DR_REG_RBX: case DR_REG_RSP: case DR_REG_RBP: case DR_REG_R12:
      case DR_REG_R13: case DR_REG_R14: case DR_REG_R15:
        return true;
      default: return false;
      }
    default: return false;
    }
  }

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
                            const function_record *func,
                            size_t maxPadding,
                            MemoryWindow &window) {
  return RandomizedFunctionPtr(
    new x86RandomizedFunction(binary, func, maxPadding, window));
}

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

void arch::dumpBacktrace(CodeTransformer *CT,
                         get_rand_info callback,
                         st_handle meta,
                         uintptr_t childBase,
                         uintptr_t bufBase) {
  struct user_regs_struct src;
  struct regset_x86_64 srcST;
  Process &proc = CT->getProcess();

  if(!proc.traceable() || proc.readRegs(src) != ret_t::Success) return;

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

  st_dump_stack(CT, callback, meta, &srcST,
                (void *)childBase, (void *)bufBase);
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

bool arch::shouldKeepForRandomization(instr_t *instr) {
  switch(instr_get_opcode(instr)) {
  // Keep nops around because Popcorn's compiler may have inserted them for
  // Chameleon to add new instructions
  case OP_nop: return true;

  // Connect the prologue into a single run, which has the following format:
  //   push %rbp
  //   movq %rsp, %rbp
  //   ...push other callee-saved registers...
  case OP_mov_st: {
    opnd_t src = instr_get_src(instr, 0);
    if(!opnd_is_reg(src) || opnd_get_reg(src) != DR_REG_RSP) return false;
    opnd_t dst = instr_get_dst(instr, 0);
    if(!opnd_is_reg(dst) || opnd_get_reg(dst) != DR_REG_RBP) return false;
    return true;
  }
  default: return false;
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
    if(opnd_is_immed_int(op)) {
      assert(CodeTransformer::getOperandSize(op) == 4 &&
             "compiler didn't encode stack pointer math immediate in 4 bytes");
      update = opnd_get_immed_int(op);
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

#define WITHIN_BYTE( val ) (INT8_MIN <= disp && disp <= INT8_MAX)

#if DEBUG_BUILD
/**
 * Double check that the compiler emitted 4-byte displacements for a base+disp
 * operand.
 *
 * @param op An operand to check.
 * @return true if the displacement is encoded in 4 bytes, false otherwise.
 */
static inline bool isDisplacement4Bytes(const opnd_t &op) {
  assert(opnd_is_base_disp(op) && "invalid operand");
  int disp = opnd_get_disp(op);
  if(WITHIN_BYTE(disp)) {
    return opnd_is_disp_force_full(op);
  }
  else return true;
}
#endif

bool arch::getRestriction(instr_t *instr,
                          const opnd_t &op,
                          int offset,
                          RandRestriction &res) {
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

  // Popcorn's compiler forces 4-byte displacements, but SP-offset slots still
  // need to be checked to see if they're argument marshalling for a call (and
  // thus immovable).
  arch::RegType base = arch::getRegTypeDR(opnd_get_base(op));
  switch(base) {
  case RegType::StackPointer:
    res.base = base;
    res.offset = offset;
    if(opnd_get_disp(op) != 0) {
      assert(isDisplacement4Bytes(op) &&
             "compiler didn't encode small displacement with 4 bytes");
      res.flags = x86Restriction::F_CheckCallSlot;
    }
    else res.flags = x86Restriction::F_EnsureCallSlot;
    return true;
    break;
  case RegType::FramePointer:
    assert(isDisplacement4Bytes(op) &&
           "compiler didn't encode small displacement with 4 bytes");
    // fall through
  default: return false;
  }
}

bool arch::getFrameUpdateRestriction(instr_t *instr,
                                     int32_t frameSize,
                                     int32_t update,
                                     RandRestriction &res) {
  int32_t offset;

  assert(instr_writes_to_reg(instr, getDRRegType(RegType::StackPointer),
                             DR_QUERY_DEFAULT) &&
         "Invalid stack update instruction");

  switch(instr_get_opcode(instr)) {
  case OP_push: case OP_pushf: case OP_pop: case OP_popf:
    // If growing the frame, the referenced slot includes the update whereas if
    // we're shrinking the frame it doesn't.
    offset = (update > 0) ? update : 0;
    offset = CodeTransformer::canonicalizeSlotOffset(frameSize + update,
                                                     RegType::StackPointer,
                                                     0);
    res.offset = offset;
    res.alignment = res.size = abs(update);
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

