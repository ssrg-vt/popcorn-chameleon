/**
 * class RandomizedFunction
 *
 * Metadata describing information needed to randomize a function and transform
 * threads executing the functions to adhere to the randomized layout.
 * Includes where function activation information (i.e., on the stack and in
 * registers) is placed in a randomized version of the function and instruction
 * information (e.g., transformation points).
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 11/27/2018
 */

#ifndef _RANDOMIZE_H
#define _RANDOMIZE_H

#include <algorithm>
#include <memory>
#include <random>
#include <unordered_set>
#include <unordered_map>
#include <vector>

#include <cstdint>

#include "binary.h"
#include "memoryview.h"
#include "types.h"
#include "utils.h"

namespace chameleon {

///////////////////////////////////////////////////////////////////////////////
// Slot re-mapping information
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Note: maintain information as POD types because we interface with C and   //
// thus need to pass raw structs.                                            //
///////////////////////////////////////////////////////////////////////////////

/* Slot mapping data structure. */
typedef struct SlotMap {
  int original, randomized;
  uint32_t size, alignment;
} SlotMap;

/**
 * Comparison function for sorting & searching a SlotMap.  Searches based on
 * the original offset.
 *
 * @param first slot mapping
 * @param second slot mapping
 * @return true if a's first element is less than b's first element
 */
bool slotMapCmp(const SlotMap &a, const SlotMap &b);

/**
 * Return whether the SlotMap contains a given offset.  Uses the slot's
 * original offset.
 *
 * @param slot a slot mapping
 * @param offset a canonicalized stack offset
 * @return true if the slot contains the offset or false otherwise
 */
bool slotMapContains(const SlotMap *slot, int offset);

/**
 * Return whether an offset would appear in a SlotMap before the specified
 * SlotMap in a sorted ordering of SlotMaps.  Uses the slot's original offset.
 *
 * @param slot a slot mapping
 * @param offset a canonicalized stack offset
 * @return true if the offset would appear before the slot or false otherwise
 */
bool lessThanSlotMap(const SlotMap *slot, int offset);

///////////////////////////////////////////////////////////////////////////////
// Randomization utilities
///////////////////////////////////////////////////////////////////////////////

/**
 * A bunch of randomization utilities bundled in an object for easy access.
 */
struct RandUtil {
  /*
   * Random number generator.  Because we may generate a large number of
   * random numbers and have limited entropy, use a pseudo-RNG seeded with a
   * true random number passed to the constructor.
   */
  std::default_random_engine gen;

  /* Stack slot padding */
  typedef std::uniform_int_distribution<int>::param_type slotBounds;
  std::uniform_int_distribution<int> slotDist;

  RandUtil() = delete;
  RandUtil(int seed, int maxPadding) {
    gen.seed(seed);
    slotDist.param(slotBounds(0, maxPadding));
  }

  /**
   * Generate a randomized stack slot padding value.
   * @return a random number to be used to pad between stack slots
   */
  int slotPadding() { return slotDist(gen); }
};

///////////////////////////////////////////////////////////////////////////////
// Stack regions
///////////////////////////////////////////////////////////////////////////////

/**
 * A region of the stack which is randomized in different ways depending on the
 * child class implementation.
 */
class StackRegion {
public:
  StackRegion(int32_t flags = 0,
              int32_t minStartOffset = 0,
              int32_t maxOffset = INT32_MAX)
    : flags(flags), minStartOffset(minStartOffset), maxOffset(maxOffset),
      origOffset(INT32_MAX), randomizedOffset(INT32_MAX), origSize(0),
      randomizedSize(0) {}
  StackRegion(const StackRegion &rhs)
    : flags(rhs.flags), minStartOffset(rhs.minStartOffset),
      maxOffset(rhs.maxOffset), origOffset(rhs.origOffset),
      randomizedOffset(rhs.randomizedOffset), origSize(rhs.origSize),
      randomizedSize(rhs.randomizedSize), slots(rhs.slots) {}

  /**
   * Return a copy of the stack region.
   */
  virtual StackRegion *copy() const = 0;

  /**
   * Add a slot to the region.
   * @param offset a canonicalized stack offset representing a slot
   * @param size size of the slot
   * @param alignment alignment of the slot
   */
  void addSlot(int offset, uint32_t size, uint32_t alignment);

  /**
   * Sort the slots so they can be searched.
   */
  void sortSlots() { std::sort(slots.begin(), slots.end(), slotMapCmp); }

  /**
   * Calculate randomized slot offsets and add padding using the templated
   * object.
   *
   * @template Pad an object that implements the slotPadding() function which
   *           returns an integer amount of padding to add between slots
   * @param startIdx the index into the vector at which to start calculating
   * @param startOffset the starting offset
   * @return the randomized offset of the last stack slot
   */
  template<typename Pad>
  int calculateOffsets(size_t startIdx, int startOffset, Pad &pad) {
    for(size_t i = startIdx; i < slots.size(); i++) {
      startOffset = ROUND_UP(startOffset + slots[i].size + pad.slotPadding(),
                             slots[i].alignment);
      slots[i].randomized = startOffset;
    }
    return startOffset;
  }

  /**
   * Randomize the slots in a region.  Calculates the new offset & size.
   *
   * Note: child class implementations *must* sort the slots using sortSlots()
   * after any randomization to make them available for searching!
   *
   * @param start the starting offset of the region
   * @param ru a random number generator
   */
  virtual void randomize(int start, RandUtil &ru) = 0;

  /**
   * Reset slots to their original locations.
   */
  virtual void resetSlots();

  /**
   * Get the average number of bits of entropy, i.e., number of bits required
   * to encode possible locations for slots post-randomization, for slots in
   * the region.
   *
   * @param start the starting offset of the region
   * @param maximum amount of padding that can be added between slots
   * @return the average number of bits of entropy for slots in the region
   */
  virtual double entropy(int start, size_t maxPadding) const = 0;

  /**
   * Return the randomized offset of slot.
   * @param orig the canonicalized original offset
   * @return the canonicalized randomized offset or INT32_MAX if none available
   */
  int getRandomizedOffset(int orig);

  /**
   * Return whether an offset falls within the region's original bounds.  Note
   * that this does *not* necessarily mean there's a slot associated with the
   * offset.
   *
   * @param orig a canonicalized offset
   * @return true if the offset falls within the region, false otherwise
   */
  bool contains(int orig) const
  { return CONTAINS_BELOW(orig, origOffset, origSize); }

  /**
   * Setters & getters - set/get what you ask for.  Setters for offset & size
   * apply to the original version of the frame (randomized offset & size are
   * calculated by randomize()).
   */
  void setFlags(int32_t flags) { this->flags = flags; }
  void addFlags(int32_t flags) { this->flags |= flags; }
  void clearFlags(int32_t flags) { this->flags &= ~flags; }
  int32_t getFlags() const { return flags; }
  void setMinStartingOffset(int32_t offset) { this->minStartOffset = offset; }
  int32_t getMinStartingOffset() const { return minStartOffset; }
  void setMaxOffset(int32_t maxOffset) { this->maxOffset = maxOffset; }
  int32_t getMaxOffset() const { return maxOffset; }
  void setOffset(int32_t offset) { origOffset = offset; }
  void setSize(size_t size) { origSize = size; }
  int32_t getOriginalOffset() const { return origOffset; }
  size_t getOriginalSize() const { return origSize; }
  int32_t getRandomizedOffset() const { return randomizedOffset; }
  size_t getRandomizedSize() const { return randomizedSize; }
  size_t numSlots() const { return slots.size(); }
  std::vector<SlotMap> &getSlots() { return slots; }
  const std::vector<SlotMap> &getSlots() const { return slots; }

protected:
  /* Flags that targets can use to add information about the section */
  int32_t flags;

  /* Region restrictions */
  int32_t minStartOffset; /* Minimum starting offset of region */
  int32_t maxOffset; /* Maximum offset of region */

  /*
   * Region information.  The region's offset is the furthest address away from
   * the canonical frame address, i.e., the lowest address contained in the
   * region for stacks that grow down or the highest address contained in the
   * region for stacks that grow up.  Note that offsets are maintained as
   * positive offsets from the stack frame's canonical frame address.
   */
  int32_t origOffset, randomizedOffset;
  uint32_t origSize, randomizedSize;

  ///////////////////////////////////////////////////////////////////////////
  // Note: maintain information as vectors because we interface with C and //
  // thus need to pass raw arrays.                                         //
  ///////////////////////////////////////////////////////////////////////////

  /* Stack slots in the region.  Stack slot offsets are canonicalized. */
  std::vector<SlotMap> slots;

  /**
   * Convert the number of possible locations into the number of bits of
   * entropy.
   *
   * @param nlocs number of possible locations
   * @return number of bits of entropy
   */
  static double entropyBits(size_t nlocs) { return log2((double)nlocs); }
};

typedef std::unique_ptr<StackRegion> StackRegionPtr;

/**
 * Class which returns a zero for slot padding.
 */
struct ZeroPad { int slotPadding() { return 0; } };

/**
 * Stack region comparison function for sorting.  Sort by original offset.
 * @param a first stack region
 * @param b second stack region
 * @return true if a comes before b in a sorted ordering of stack regions
 */
bool regionCompare(const StackRegionPtr &a, const StackRegionPtr &b);

/**
 * A region of the stack which cannot be randomized - slots maintain the same
 * intra-region location.
 *
 * Note: randomized offsets may *not* be identical to original offsets due to
 * this region's placement around other randomizable regions.  The ordering and
 * relative offsets of slots within the region are preserved.
 */
class ImmutableRegion : public StackRegion {
public:
  ImmutableRegion(int32_t flags = 0) : StackRegion(flags) {}
  ImmutableRegion(const ImmutableRegion &rhs) : StackRegion(rhs) {}
  StackRegion *copy() const override { return new ImmutableRegion(*this); }

  /**
   * Update the "randomized" offsets of slots in consideration of the starting
   * offset.  Does not randomize ordering or intra-region locations of slots.
   *
   * @param start the starting offset of the region
   * @param ru a random number generator
   */
  virtual void randomize(int start, RandUtil &ru) override;

  /**
   * Get the average number of bits of entropy, i.e., number of bits required
   * to encode possible locations for slots post-randomization, for slots in
   * the region.
   *
   * @param start the starting offset of the region
   * @param maximum amount of padding that can be added between slots
   * @return the average number of bits of entropy for slots in the region
   */
  virtual double entropy(int start, size_t maxPadding) const;
};

/**
 * A region of the stack which can be permuted (i.e., the ordering of slots is
 * randomizable) but no padding can be added between slots.  This means that
 * the randomized version of the section has the same (or less) size as the
 * original region.
 *
 * Note: the current implementation assumes power-of-2 alignments!
 */
class PermutableRegion : public StackRegion {
public:
  PermutableRegion(int32_t flags = 0,
                   int32_t minStartOffset = 0,
                   int32_t maxOffset = INT32_MAX)
    : StackRegion(flags, minStartOffset, maxOffset) {}
  PermutableRegion(const PermutableRegion &rhs) : StackRegion(rhs) {}
  StackRegion *copy() const override { return new PermutableRegion(*this); }

  /**
   * Randomize stack slot locations by permuting the ordering of stack slots.
   * Because the slots are only permuted, the randomized offset & size are
   * equivalent to the original offset and size.  If the permutation's offset
   * exceeds the original offset or the permutation's size exceeds any
   * specified maximum size, the region is restored to its original layout.
   *
   * @param start the starting offset of the region
   * @param ru a random number generator
   */
  virtual void randomize(int start, RandUtil &ru) override;

  /**
   * Get the average number of bits of entropy, i.e., number of bits required
   * to encode possible locations for slots post-randomization, for slots in
   * the region.
   *
   * @param start the starting offset of the region
   * @param maximum amount of padding that can be added between slots
   * @return the average number of bits of entropy for slots in the region
   */
  virtual double entropy(int start, size_t maxPadding) const;
};

/**
 * A region of the stack which is fully randomizable, i.e., slots orderings can
 * be randomized and padding can be added between slots.
 */
class RandomizableRegion : public StackRegion {
public:
  RandomizableRegion(int32_t flags = 0,
                     int32_t minStartOffset = 0,
                     int32_t maxOffset = INT32_MAX)
    : StackRegion(flags, minStartOffset, maxOffset) {}
  RandomizableRegion(const RandomizableRegion &rhs) : StackRegion(rhs) {}
  StackRegion *copy() const override { return new RandomizableRegion(*this); }

  /**
   * Randomize stack slot locations by both permuting the ordering of stack
   * slots and by adding padding.  Calculates the new offset and size.
   *
   * @param start the starting offset of the region
   * @param ru a random number generator
   */
  virtual void randomize(int start, RandUtil &ru) override;

  /**
   * Get the average number of bits of entropy, i.e., number of bits required
   * to encode possible locations for slots post-randomization, for slots in
   * the region.
   *
   * @param start the starting offset of the region
   * @param maximum amount of padding that can be added between slots
   * @return the average number of bits of entropy for slots in the region
   */
  virtual double entropy(int start, size_t maxPadding) const;
};

///////////////////////////////////////////////////////////////////////////////
// Randomized function
///////////////////////////////////////////////////////////////////////////////

/**
 * Struct containing information about randomization restrictions for a slot.
 */
struct RandRestriction {
  int offset; /* canonicalized stack offset identifying the slot */
  int32_t flags; /* ISA-specific flags - see details in arch.cpp */
  uint32_t size, alignment; /* size & alignment of slot */
  uint16_t base; /* base register or UINT16_MAX if no restriction */
  range_t range; /* offset restriction */
};

/*
 * This class is virtual and must be inherited by an ISA-specific child class
 * that implements the machinery necessary for laying out the stack.  The child
 * class should populated the regions vector with appropriate stack regions in
 * the constructor, ordered by smallest region offset first.
 */
class RandomizedFunction {
public:
  /* Type of transformation point */
  enum TransformType {
    None,
    CallSite,
    Return
  };

  RandomizedFunction() = delete;
  RandomizedFunction(const Binary &binary,
                     const function_record *func,
                     size_t maxPadding);
  RandomizedFunction(const RandomizedFunction &rhs, MemoryWindow &mw);
  ~RandomizedFunction()
  { if(instrs) instrlist_clear_and_destroy(GLOBAL_DCONTEXT, instrs); }

  /**
   * Deep copy the randomized function.
   * @param mw a memory window used to set the copied instruction's raw bits
   */
  virtual RandomizedFunction *copy(MemoryWindow &mw) const = 0;

  /**
   * Get alignment requirements for the function's stack frame.
   * @return frame alignment requirements
   */
  virtual uint32_t getFrameAlignment() const = 0;

  /**
   * Get the function's metadata record.
   * @return the function record
   */
  const function_record *getFunctionRecord() const { return func; }

  /**
   * Get & set the function's instructions.  After setting the instruction
   * list, the RandomizedFunction takes ownership of the list & contained
   * instructions.  Users can modify the instructions (including
   * adding/removing instructions) but *must not* delete the list itself.
   */
  const instrlist_t *getInstructions() const { return instrs; }
  instrlist_t *getInstructions() { return instrs; }
  void setInstructions(instrlist_t *instrs) { this->instrs = instrs; }

  /**
   * Add a randomization restriction for a slot.
   * @param res slot and restriction information
   * @return a return code describing the outcome
   */
  virtual ret_t addRestriction(const RandRestriction &res) = 0;

  /**
   * Finalize all analysis, including generating any extra information required
   * for randomization and populating stack regions with stack slots from
   * metadata after analyzing restrictions.  Just to emphasize, this must be
   * called *after* analysis.
   *
   * @return a return code describing the outcome
   */
  virtual ret_t finalizeAnalysis();

  /**
   * Randomize a function.
   *
   * Note: metadata from the previous randomization is kept in order to
   * translate from previous randomizations to the current randomization.
   *
   * @param seed random number generator seed
   * @return a return code describing the outcome
   */
  virtual ret_t randomize(int seed);

  /**
   * Set all stack elements to their original locations.
   * @return a return code describing the outcome
   */
  virtual ret_t resetSlots();

  /**
   * Return the previously-randomized frame size.
   * @return the previously-randomized frame size
   */
  uint32_t getPrevRandFrameSize() const { return prevRandFrameSize; }

  /**
   * Return the randomized frame size.
   * @return the randomized frame size
   */
  uint32_t getRandomizedFrameSize() const { return randomizedFrameSize; }

  /**
   * Get the the slot remapping information from the previous randomization.
   * @return slot remapping information for previous randomization
   */
  const std::vector<SlotMap> &getPrevRandSlots() const { return *prevRand; }

  /**
   * Get the the slot remapping information for the current randomization.
   * @return slot remapping information for currentrandomization
   */
  const std::vector<SlotMap> &getRandomizedSlots() const { return *curRand; }

  /**
   * Add a program transformation point for the function.
   * @param addr a program transformation point
   */
  void addTransformAddr(uintptr_t addr, TransformType type) {
    assert(funcContains(func, addr) && "Transformation point not in function");
    transformAddrs[addr] = type;;
  }

  /**
   * Return whether a program address is a transformation point.  If not,
   * return a None type; else return the type of the transformation point.
   * @param addr a program counter value
   * @return the type of transformation point or None if it's not a
   *         transformation point
   */
  TransformType getTransformationType(uintptr_t addr) const {
    auto it = transformAddrs.find(addr);
    if(it == transformAddrs.end()) return TransformType::None;
    else return it->second;
  }

  /**
   * Get addresses of valid program transformation points for the function.
   * @return vector of program transformation points
   */
  const std::unordered_map<uintptr_t, TransformType> &getTransformAddrs() const
  { return transformAddrs; }

  /**
   * Typically compilers allocate space for callee-saved registers/immovable
   * slots by storing registers onto the stack and then bulk-allocating the
   * remaining frame space with a single math operation.  Return whether a
   * frame size update (denoted by an offset) is the bulk-update and needs to
   * be transformed.
   *
   * @param instr an instruction
   * @param offset a canonicalized offset
   * @return true if it needs to be transformed, false otherwise
   */
  virtual bool isBulkFrameUpdate(instr_t *instr, int offset) const = 0;

  /**
   * Return the bulk frame update size for the randomized frame.
   * @return bulk frame update size for randomized frame
   */
  virtual uint32_t getRandomizedBulkFrameUpdate() const = 0;

  /**
   * Convert a previously-randomized offset to the original offset.
   * @param prev the canonicalized stack slot offset from a previous
   *             randomization
   * @return the canonicalized original offset, or INT32_MAX if prevRand
   *         doesn't correspond to any stack slot
   */
  int getOriginalOffset(int prev) const;

  /**
   * Get the randomized offset for a stack slot.  Note that based on
   * restrictions or entropy, the randomized offset may not actually be
   * different than the original offset.
   *
   * @param orig the canonicalized original stack slot offset
   * @return the canonicalized randomized offset, or INT32_MAX if orig
   *         doesn't correspond to any stack slot
   */
  int getRandomizedOffset(int orig) const;

  /**
   * Return whether a given offset should be transformed.
   * @param offset a canonicalized stack offset from the previous randomization
   * @return true if the offset should be randomized or false otherwise
   */
  virtual bool shouldTransformSlot(int offset) const = 0;

  /**
   * Hook to allow ISA-specific implementations to do any other transformations
   * not captured by finding & replacing memory reference operands.
   *
   * @param frameSize current frame size
   * @param randFrameSize current randomized frame size
   * @param instr an instruction
   * @param changed output argument set to true if the instruction was changed
   * @return a return code describing the outcome
   */
  virtual ret_t transformInstr(uint32_t frameSize,
                               uint32_t randFrameSize,
                               instr_t *instr,
                               bool &changed) const = 0;

protected:
  /* Binary & function metadata */
  const Binary &binary;
  const function_record *func;

  /* Disassembled instructions */
  instrlist_t *instrs;

  /* Maximum size of frame */
  uint32_t maxFrameSize;

  /*
   * Map of program counter addresses where we can do a transformation and the
   * type of transformation point.
   */
  std::unordered_map<uintptr_t, TransformType> transformAddrs;

  /*
   * Canonicalized slots from metadata for searching.  Randomized versions of
   * slots are contained in the region objects.
   */
  std::vector<std::pair<int, const stack_slot *>> slots;

  /*
   * Maintain lists of slot remappings from one previous and current
   * randomization in order to transform thread stacks.
   *
   * Note: in general, slot remapping accesses should happen through prevRand,
   * curRand, and prevSortedByRand, *not* _a and _b
   */
  std::vector<SlotMap> _a, _b, prevSortedByRand;
  std::vector<SlotMap> *prevRand, *curRand;

  /* Set of previously-seen offsets during analysis */
  std::unordered_set<int> seen;

  /* Stack regions.  Laid out by target-specific implementation. */
  std::vector<StackRegionPtr> regions;

  /* Frame size from previous and current randomization */
  uint32_t prevRandFrameSize, randomizedFrameSize;

  /* Maximum padding that can be added between fully-randomizable slots */
  size_t maxPadding;

  /**
   * Find the stack slot corresponding to a given offset.
   * @param a canonicalized offset
   * @return a canonicalized offset/stack slot record pair corresponding to the
   *         containing stack slot, or a <INT32_MAX, nullptr> pair if no slot
   *         contains the offset
   */
  std::pair<int, const stack_slot *> findSlot(int offset);

  /**
   * Same as findSlot() but include the end of the slot in checking.  Should
   * *only* be called after findSlot() could not find a corresponding slot.
   *
   * @param a canonicalized offset
   * @return a canonicalized offset/stack slot record pair corresponding to the
   *         containing stack slot, or a <INT32_MAX, nullptr> pair if no slot
   *         contains the offset
   */
  std::pair<int, const stack_slot *> findSlotEndInclusive(int offset);

  /**
   * Find the region containing an offset or nullptr if none do.
   * @param offset a canonicalized offset
   * @return a pointer to the containing StackRegion object or nullptr if none
   *         contain the offset
   */
  StackRegionPtr *findRegion(int offset);
  const StackRegionPtr *findRegion(int offset) const;
};

typedef std::unique_ptr<RandomizedFunction> RandomizedFunctionPtr;

}

#endif /* _RANDOMIZE_H */

