#include <algorithm>
#include <map>
#include <cmath>
#include <cstdlib>

#include "arch.h"
#include "log.h"
#include "randomize.h"
#include "transform.h"
#include "utils.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// StackRegion implementation
///////////////////////////////////////////////////////////////////////////////

// TODO this could be improved - keep slots in sorted ordering as we add them
// for quicker existence checking.  We're currently assuming there's a small
// number of slots per region and thus it's not worth keeping the slots sorted.
void StackRegion::addSlot(int offset, uint32_t size, uint32_t alignment) {
  SlotMap newSlot = { offset, INT32_MAX, size, alignment };

  // Do existence checking so we don't have redundant slots
  for(auto &sm : slots) {
    if(CONTAINS(offset, sm.original, sm.size)) {
      if(!CONTAINS(offset + size, sm.original, sm.size))
        WARN("Overlapping slots? "
             << sm.original << " -> " << sm.original + sm.size << ", "
             << offset << " -> " << offset + size << std::endl);
      return;
    }
  }

  slots.emplace_back(std::move(newSlot));
}

template<typename Pad>
int StackRegion::calculateOffsets(size_t startIdx, int startOffset, Pad &pad) {
  startOffset = abs(startOffset);
  for(size_t i = startIdx; i < slots.size(); i++) {
    startOffset = ROUND_UP(startOffset + slots[i].size + pad.slotPadding(),
                           slots[i].alignment);
    slots[i].randomized = -startOffset;
  }
  return -startOffset;
}

int StackRegion::getRandomizedOffset(int orig) {
  int offset = INT32_MAX;
  ssize_t idx = findRight<SlotMap, int, slotMapContains, lessThanSlotMap>
                         (&slots[0], slots.size(), orig);
  if(idx >= 0 && slotMapContains(&slots[idx], orig))
    offset = orig - slots[idx].original + slots[idx].randomized;
  return offset;
}

void ImmutableRegion::randomize(int start, RandUtil &ru) {
  ZeroPad pad;

  sortSlotsReverse();
  randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
  randomizedSize = origSize;

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("immutable slots:" << std::endl);
    for(auto &sm : slots) {
      DEBUGMSG_VERBOSE("  " << sm.original << " -> " << sm.randomized
                       << std::endl);
    }
  )

  sortSlots();
}

/**
 * Permutable regions need to be able to randomize slot ordering without
 * increasing the region's size (there may be ISA-specific size restrictions).
 * Bucket objects are the unit that must be filled with slots to optimally
 * satisfy alignment requirements and not insert extra padding.  Buckets
 * consist of actual slots and empty "holes" (denoted as SlotMaps with
 * originalOffset = 0).  Holes can be filled in with actual slots.
 */
struct Bucket {
  std::vector<SlotMap> slots; /* Slots & holdes in the bucket */

  /**
   * Create a hole of a given size.
   * @param size size of the hole
   * @return a hole
   */
  static SlotMap getHole(uint32_t size) {
    SlotMap tmp = { 0, 0, size, 1 };
    return tmp;
  }

  /**
   * Return whether a hole can hold a slot.
   * @param curOffset current offset in bucket
   * @param hole a hole
   * @param s a SlotMap
   * @return true if the hole can hold the slot or false otherwise
   */
  static bool canHoldSlot(uint32_t curOffset,
                          const SlotMap &hole,
                          const SlotMap &s,
                          uint32_t &beforePad,
                          uint32_t &afterPad) {
    uint32_t alignUp;

    assert(hole.original == 0 && "Not a hole");

    alignUp = ROUND_UP(curOffset, s.alignment);
    if(CONTAINS(alignUp, curOffset, hole.size + 1) &&
       CONTAINS(alignUp + s.size, curOffset, hole.size + 1)) {
      beforePad = alignUp - curOffset;
      afterPad = hole.size - s.size - beforePad;
      return true;
    }
    else return false;
  }

  Bucket() = delete;
  Bucket(uint32_t size) { slots.emplace_back(getHole(size)); }

  /**
   * Attempt to add a slot to the bucket by searching for big enough holes.
   * @param s SlotMap object
   * @return true if the slot was successfully added or false otherwise
   */
  bool addSlotMap(const SlotMap &s) {
    uint32_t curOffset = 0, beforePad = 0, afterPad = 0;
    size_t i;
    std::vector<SlotMap>::iterator it;

    assert(s.original != 0 && "Invalid sentinal offset");

    for(i = 0; i < slots.size(); i++) {
      if(slots[i].original == 0 &&
         canHoldSlot(curOffset, slots[i], s, beforePad, afterPad)) {
        it = slots.begin() + i;
        it = slots.erase(it);
        if(beforePad) {
          it = slots.insert(it, getHole(beforePad));
          it++;
        }
        it = slots.insert(it, s);
        if(afterPad) {
          it++;
          it = slots.insert(it, getHole(afterPad));
        }
        return true;
      }
      else curOffset += slots[i].size;
    }
    return false;
  }

  /**
   * Return whether the bucket is filled, i.e., it doesn't have holes at the
   * end of all slots.  Note that the bucket may still have internal
   * fragmentation due to alignment restrictions.
   *
   * @return true if the bucket is filled, false otherwise
   */
  bool filled() const { return slots.back().original != 0; }
};

/**
 * Return whether slot a's size/alignment requirements are less than slot b's.
 * @param a first SlotMap
 * @param b second SlotMap
 * @return true if a comes before b in a sorted ordering
 */
static bool slotSizeAlignCmp(const SlotMap &a, const SlotMap &b)
{ return ROUND_UP(a.size, a.alignment) < ROUND_UP(b.size, b.alignment); }

void PermutableRegion::randomize(int start, RandUtil &ru) {
  bool added, fillerBucket = false;
  uint32_t bucketSize = 0, curSize;
  size_t i, j;
  std::vector<Bucket> buckets;
  SlotMap toPlace;
  ZeroPad pad;

  // Sort buckets by increasing size/alignment requirements & determine the
  // bucket size based on slot sizes & alignments.  For example, a stack slot
  // of size 24 with 16-byte alignment requires a 32-byte bucket.
  std::sort(slots.begin(), slots.end(), slotSizeAlignCmp);
  bucketSize = ROUND_UP(slots.back().size, slots.back().alignment);

  // Due to starting offset, the first bucket may actually be smaller to round
  // the frame up to the nearest bucket size
  curSize = ROUND_UP(abs(start), bucketSize) - abs(start);
  if(curSize < bucketSize) {
    buckets.emplace_back(Bucket(curSize));
    fillerBucket = true;
  }

  // To avoid deterministically placing equal sized slots into the same buckets
  // for every permutation, e.g., a frame with multiple 8-byte slots being
  // placed into the same buckets due to their ordering from sorting, randomize
  // slots which are in equivalent classes (defined by size & alignment).
  for(i = 0; i < slots.size(); i++) {
    curSize = ROUND_UP(slots[i].size, slots[i].alignment);
    j = i;
    while(j < slots.size() &&
          ROUND_UP(slots[j].size, slots[j].alignment) == curSize) j++;
    std::shuffle(slots.begin() + i, slots.begin() + j, ru.gen);
    i = j - 1;
  }

  // Fill buckets starting with largest slots first.
  while(slots.size()) {
    toPlace = slots.back();
    slots.pop_back();

    // Search for an existing bucket that can accomodate the slot
    added = false;
    for(auto &bucket : buckets) {
      if(bucket.addSlotMap(toPlace)) {
        added = true;
        break;
      }
    }

    // Add a new bucket if no existing buckets can contain the slot
    if(!added) {
      buckets.emplace_back(Bucket(bucketSize));
      added = buckets.back().addSlotMap(toPlace);
      assert(added && "Couldn't add slot to empty bucket");
    }
  }

  // Move all filled/non-filled buckets to be contiguous; j points to the split
  for(j = i = (int)fillerBucket; i < buckets.size(); i++) {
    if(buckets[i].filled()) {
      std::swap(buckets[i], buckets[j]);
      j++;
    }
  }

  // Randomize buckets, serialize back into slots vector & calculate offsets
  // TODO do we need special handling for unfilled buckets?
  std::shuffle(buckets.begin() + (int)fillerBucket,
               buckets.begin() + j,
               ru.gen);
  std::shuffle(buckets.begin() + j, buckets.end(), ru.gen);
  for(auto &bucket : buckets)
    for(auto slot = bucket.slots.rbegin(); slot != bucket.slots.rend(); slot++)
      if(slot->original != 0) slots.emplace_back(*slot);
  randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);

  // If permutation failed, resort to original ordering
  if(randomizedOffset < origOffset) {
    WARN("Could not permute slots in " << origOffset << " -> "
         << origOffset + (int)origSize << " region" << std::endl);
    for(auto &sm : slots) sm.randomized = sm.original;
  }
  else if(randomizedOffset > origOffset) {
    // TODO extra space, disperse between slots
  }

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("permuted slots:" << std::endl);
    for(i = 0; i < slots.size(); i++) {
      DEBUGMSG_VERBOSE("  " << slots[i].original << " -> "
                       << slots[i].randomized << std::endl);
    }
  )

  // Sometimes we actually manage to create smaller regions than those laid out
  // by the compiler.  Logically pad to fill the region.
  randomizedOffset = start - origSize;
  randomizedSize = origSize;

  // Sort by original offset for searching
  sortSlots();
}

void RandomizableRegion::randomize(int start, RandUtil &ru) {
  int curOffset;

  // Randomize slots with padding
  std::shuffle(slots.begin(), slots.end(), ru.gen);
  curOffset = calculateOffsets<RandUtil>(0, start, ru);

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("randomized slots:" << std::endl);
    for(size_t i = 0; i < slots.size(); i++)
      DEBUGMSG_VERBOSE("  " << slots[i].original << " -> "
                       << slots[i].randomized << std::endl);
  )

  // Sort by original offset for searching & update frame sizes
  sortSlots();
  randomizedSize = abs(curOffset - start);
  randomizedOffset = curOffset;
}

///////////////////////////////////////////////////////////////////////////////
// RandomizedFunction implementation
///////////////////////////////////////////////////////////////////////////////

/**
 * Comparison function for sorting & searching a slot.
 * @param a first offset/stack slot record pair
 * @param b second offset/stack slot record pair
 * @return true if a's offset is less than b's offset
 */
static bool slotCmp(const std::pair<int, const stack_slot *> &a,
                    const std::pair<int, const stack_slot *> &b)
{ return a.first < b.first; }

RandomizedFunction::RandomizedFunction(const Binary &binary,
                                       const function_record *func)
  : binary(binary), func(func) {
  int offset;
  arch::RegType type;
  Binary::slot_iterator si = binary.getStackSlots(func);

  slots.reserve(si.getLength());
  for(; !si.end(); ++si) {
    const stack_slot *slot = *si;
    type = arch::getRegType(slot->base_reg);
    offset = CodeTransformer::canonicalizeSlotOffset(func->frame_size,
                                                     type,
                                                     slot->offset);
    slots.emplace_back(offset, slot);
  }
  std::sort(slots.begin(), slots.end(), slotCmp);
}

ret_t RandomizedFunction::randomize(int seed, size_t maxPadding) {
  int offset = 0;
  ret_t retcode;
  RandUtil ru(seed, maxPadding);
  randomizedFrameSize = UINT32_MAX;

  if((retcode = populateSlots()) != ret_t::Success) return retcode;

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

  // Note: regions are ordered from lowest region first; walk the vector in
  // reverse order to calculate CFA offsets
  for(auto r = regions.rbegin(); r != regions.rend(); r++) {
    (*r)->randomize(offset, ru);
    offset = (*r)->getRandomizedRegionOffset();
  }
  randomizedFrameSize = abs(regions[0]->getRandomizedRegionOffset());
  randomizedFrameSize = ROUND_UP(randomizedFrameSize, getFrameAlignment());

  DEBUGMSG("randomized frame size: " << randomizedFrameSize << std::endl);

  return ret_t::Success;
}

int RandomizedFunction::getRandomizedOffset(int orig) const {
  const StackRegionPtr *region = findRegion(orig);
  if(region) return (*region)->getRandomizedOffset(orig);
  else return 0;
}

/**
 * Return whether the slot contains a given offset.
 * @param slot offset/stack slot record pair
 * @param offset a canonicalized offset
 * @return true if the slot contains the offset, false otherwise
 */
static bool
slotContains(const std::pair<int, const stack_slot *> *slot, int offset)
{ return CONTAINS(offset, slot->first, slot->second->size); }

/**
 * Return whether an offset would appear in a slot before the specified pair
 * in a sorted ordering of offset/stack slot record pairs.
 *
 * @param slot slot offset/stack slot record pair
 * @param offset a canonicalized offset
 * @return true if the offset would appear before the slot or false otherwise
 */
static bool
lessThanSlot(const std::pair<int, const stack_slot *> *slot, int offset)
{ return offset < slot->first; }

std::pair<int, const stack_slot *> RandomizedFunction::findSlot(int offset) {
  ssize_t idx = findRight<std::pair<int, const stack_slot *>, int,
                          slotContains, lessThanSlot>
                         (&slots[0], slots.size(), offset);
  if(idx >= 0 && slotContains(&slots[idx], offset)) return slots[idx];
  else return std::pair<int, const stack_slot *>(INT32_MAX, nullptr);
}

/**
 * Return whether the region contains a given offset.
 * @param region a StackRegion object
 * @param offset a canonicalized offset
 * @return true if the region contains the offset, false otherwise
 */
static bool regionContains(const StackRegionPtr *region, int offset)
{ return (*region)->contains(offset); }

/**
 * Return whether an offset would appear in a region before the specified
 * region in a sorted ordering of regions.
 *
 * @param region a StackRegion object
 * @param offset a canonicalized offset
 * @return true if the offset would appear before the region or false otherwise
 */
static bool lessThanRegion(const StackRegionPtr *region, int offset)
{ return offset < (*region)->getOriginalRegionOffset(); }

StackRegionPtr *RandomizedFunction::findRegion(int offset) {
  ssize_t idx = findRight<StackRegionPtr, int, regionContains, lessThanRegion>
                         (&regions[0], regions.size(), offset);
  if(idx >= 0 && regionContains(&regions[idx], offset)) return &regions[idx];
  else return nullptr;
}

const StackRegionPtr *RandomizedFunction::findRegion(int offset) const {
  ssize_t idx = findRight<StackRegionPtr, int, regionContains, lessThanRegion>
                         (&regions[0], regions.size(), offset);
  if(idx >= 0 && regionContains(&regions[idx], offset)) return &regions[idx];
  else return nullptr;
}

