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
// Slot re-mapping information
///////////////////////////////////////////////////////////////////////////////

bool chameleon::slotMapCmp(const SlotMap &a, const SlotMap &b)
{ return a.original < b.original; }

bool chameleon::slotMapContains(const SlotMap *slot, int offset)
{ return CONTAINS_BELOW(offset, slot->original, slot->size); }

bool chameleon::lessThanSlotMap(const SlotMap *slot, int offset)
{ return offset < slot->original; }

///////////////////////////////////////////////////////////////////////////////
// StackRegion implementation
///////////////////////////////////////////////////////////////////////////////

void StackRegion::addSlot(int offset, uint32_t size, uint32_t alignment) {
  SlotMap newSlot = { offset, INT32_MAX, size, alignment };

  // Do existence checking so we don't have redundant slots
  for(auto &sm : slots) {
    if(CONTAINS_BELOW(offset, sm.original, sm.size)) {
      if(!CONTAINS_BELOW(offset - size + 1, sm.original, sm.size))
        WARN("Overlapping slots? "
             << sm.original - sm.size << " -> " << sm.original << ", "
             << offset - size << " -> " << offset << std::endl);
      return;
    }
  }

  slots.emplace_back(std::move(newSlot));
}

int StackRegion::getRandomizedOffset(int orig) {
  int offset = INT32_MAX;
  ssize_t idx = findRight<SlotMap, int, slotMapContains, lessThanSlotMap>
                         (&slots[0], slots.size(), orig);
  if(idx >= 0 && slotMapContains(&slots[idx], orig))
    offset = orig - slots[idx].original + slots[idx].randomized;
  return offset;
}

bool chameleon::regionCompare(const StackRegionPtr &a, const StackRegionPtr &b)
{ return a->getOriginalOffset() < b->getOriginalOffset(); }

void ImmutableRegion::randomize(int start, RandUtil &ru) {
  ZeroPad pad;
  randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
  randomizedSize = origSize;

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("immutable slots:" << std::endl);
    for(auto &sm : slots) {
      DEBUGMSG_VERBOSE("  " << sm.original << " -> " << sm.randomized
                       << std::endl);
    }
  )
}

double
ImmutableRegion::entropy(int start, size_t maxPadding) const { return 0.0; }

/**
 * Permutable regions need to be able to randomize slot ordering without
 * increasing the region's size (there may be ISA-specific size restrictions).
 * Bucket objects are the unit that must be filled with slots to optimally
 * satisfy alignment requirements and not insert extra padding.  Buckets
 * consist of actual slots and empty "holes" (denoted as SlotMaps with
 * originalOffset = 0).  Holes can be filled in with actual slots.
 */
struct Bucket {
  std::vector<SlotMap> slots; /* Slots & holes in the bucket */

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
   * @param beforePad output argument set to remaining padding before the slot
   *                  if the hole can hold the slot
   * @param afterPad output argument set to remaining padding after the slot if
   *                 the hole can hold the slot
   * @return true if the hole can hold the slot or false otherwise
   */
  static bool canHoldSlot(uint32_t curOffset,
                          const SlotMap &hole,
                          const SlotMap &s,
                          uint32_t &beforePad,
                          uint32_t &afterPad) {
    uint32_t alignDown;

    assert(hole.original == 0 && "Not a hole");

    alignDown = ROUND_DOWN(curOffset, s.alignment);
    if(CONTAINS_BELOW(alignDown, curOffset, hole.size) &&
       CONTAINS_BELOW(alignDown - s.size + 1, curOffset, hole.size)) {
      beforePad = curOffset - alignDown;
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
    uint32_t curOffset = 0, beforePad, afterPad;
    size_t i;
    std::vector<SlotMap>::iterator it;

    assert(s.original != 0 && "Adding hole to bucket");

    for(i = 0; i < slots.size(); i++) {
      curOffset += slots[i].size;
      if(slots[i].original == 0 &&
         canHoldSlot(curOffset, slots[i], s, beforePad, afterPad)) {
        it = slots.begin() + i;
        it = slots.erase(it);
        if(afterPad) {
          it = slots.insert(it, getHole(afterPad));
          it++;
        }
        it = slots.insert(it, s);
        if(beforePad) {
          it++;
          it = slots.insert(it, getHole(beforePad));
        }
        return true;
      }
    }
    return false;
  }

  /**
   * Count the number of instances of a given slot size/alignment class in the
   * bucket.
   *
   * @param cls slot size/alignment class
   * @param number of instances of class in the bucket
   */
  size_t classCount(size_t cls) const {
    size_t count = 0;
    for(const auto &s : slots)
      if(ROUND_UP(s.size, s.alignment) == cls) count++;
    return count;
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

  // Sort slots by increasing size/alignment requirements & determine the
  // bucket size based on slot sizes & alignments.  For example, a stack slot
  // of size 24 with 16-byte alignment requires a 32-byte bucket.
  std::sort(slots.begin(), slots.end(), slotSizeAlignCmp);
  bucketSize = ROUND_UP(slots.back().size, slots.back().alignment);

  // Due to starting offset, the first bucket may actually be smaller to round
  // the frame up to the nearest bucket size
  curSize = ROUND_UP(start, bucketSize) - start;
  if(curSize && curSize < bucketSize) {
    buckets.emplace_back(Bucket(curSize));
    fillerBucket = true;
  }

  // To avoid deterministically placing equal sized slots into the same buckets
  // for every permutation, e.g., a frame with multiple 8-byte slots being
  // placed into the same buckets due to their ordering from sorting, randomize
  // slots which are in equivalent size/alignment classes.
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
      added = bucket.addSlotMap(toPlace);
      if(added) break;
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
    for(auto slot = bucket.slots.begin(); slot != bucket.slots.end(); slot++)
      if(slot->original != 0) slots.emplace_back(*slot);
  randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
  const SlotMap &top = slots.front();
  randomizedSize = randomizedOffset - (int)(top.randomized - top.size);

  // Sort by original offset for later searching
  sortSlots();

  // TODO if randomizedOffset < origOffset there's leftover space which we
  // should disperse between the slots

  // If permutation failed, resort to original ordering
  if(randomizedSize > origSize) {
    DEBUG(WARN("Could not permute slots in " << origOffset - origSize << " -> "
               << origOffset << " region" << std::endl));
    randomizedOffset = calculateOffsets<ZeroPad>(0, start, pad);
    randomizedSize = origSize;
  }
  else if(randomizedSize < origSize) {
    // Sometimes we actually manage to create smaller regions than those laid
    // out by the compiler.  Logically pad to fill the region.
    //
    // Note: we *must* calculate the new offset by adding the region's size to
    // the start offset (not just assigning origOffset), as the start offset
    // may be different from the original starting offset due to adjacent
    // randomized regions
    randomizedOffset = start + origSize;
    randomizedSize = origSize;
  }

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("permuted slots:" << std::endl);
    for(i = 0; i < slots.size(); i++) {
      DEBUGMSG_VERBOSE("  " << slots[i].original << " -> "
                       << slots[i].randomized << std::endl);
    }
  )
}

double PermutableRegion::entropy(int start, size_t maxPadding) const {
  bool added, fillerBucket = false;
  uint32_t bucketSize = 0, curSize;
  size_t i, j, locs, bucketLocs, totalLocs = 0;
  int bucketOffset, curOffset, firstSlotStart;
  std::vector<SlotMap> tmpSlots(slots);
  std::vector<Bucket> buckets;
  std::unordered_map<size_t, size_t> sizeClasses;
  SlotMap toPlace;

  // We don't know if we can permute the slots because we may overflow the
  // allowable size.  Run the permutation algorithm to check.

  const SlotMap &tmp = slots.front();
  firstSlotStart = tmp.original - tmp.size;
  std::sort(tmpSlots.begin(), tmpSlots.end(), slotSizeAlignCmp);
  bucketSize = ROUND_UP(tmpSlots.back().size, tmpSlots.back().alignment);
  curSize = ROUND_UP(start, bucketSize) - start;
  if(curSize && curSize < bucketSize) {
    buckets.emplace_back(Bucket(curSize));
    bucketOffset = start + curSize;
    fillerBucket = true;
  }
  else bucketOffset = start;

  // Record all class sizes and the number of slots in each class - if we *can*
  // permute, we'll use this information to calculate entropy.
  for(i = 0; i < tmpSlots.size(); i++) {
    curSize = ROUND_UP(tmpSlots[i].size, tmpSlots[i].alignment);
    j = i;
    while(j < tmpSlots.size() &&
          ROUND_UP(tmpSlots[j].size, tmpSlots[j].alignment) == curSize) j++;
    sizeClasses[curSize] = j - i;
    i = j - 1;
  }

  while(tmpSlots.size()) {
    toPlace = tmpSlots.back();
    tmpSlots.pop_back();
    added = false;
    for(auto &bucket : buckets) {
      added = bucket.addSlotMap(toPlace);
      if(added) break;
    }
    if(!added) {
      buckets.emplace_back(Bucket(bucketSize));
      added = buckets.back().addSlotMap(toPlace);
      assert(added && "Couldn't add slot to empty bucket");
    }
  }

  for(j = i = (int)fillerBucket; i < buckets.size(); i++) {
    if(buckets[i].filled()) {
      std::swap(buckets[i], buckets[j]);
      j++;
    }
  }

  DEBUG(
    if(i != j) WARN("Invalid entropy calculation for permutable region - "
                    "unfilled buckets");
  )

  for(auto &bucket : buckets)
    for(auto slot = bucket.slots.begin(); slot != bucket.slots.end(); slot++)
      if(slot->original != 0) tmpSlots.emplace_back(*slot);
  curOffset = start;
  for(i = 0; i < tmpSlots.size(); i++)
    curOffset = ROUND_UP(curOffset + tmpSlots[i].size, tmpSlots[i].alignment);
  curSize = curOffset - firstSlotStart;

  // We can't randomize the region without going over size limit, no entropy
  if(curSize > origSize) return 0.0;

  // Calculate entropy from the number of possible locations for each size
  // class and the number of slots in each class
  // TODO handle unfilled buckets
  bucketLocs = (curOffset - bucketOffset) / bucketSize;
  for(const auto sizeClass : sizeClasses) {
    if(fillerBucket) {
      for(locs = 0, i = 1; i < j; i++)
        locs = std::max(locs, buckets[i].classCount(sizeClass.first));
      locs *= bucketLocs;
      locs += buckets[0].classCount(sizeClass.first);
    }
    else {
      for(locs = 0, i = 0; i < j; i++)
        locs = std::max(locs, buckets[i].classCount(sizeClass.first));
      locs *= bucketLocs;
    }
    totalLocs += locs * sizeClass.second;
  }
  return entropyBits((double)totalLocs / (double)slots.size());
}

void RandomizableRegion::randomize(int start, RandUtil &ru) {
  int curOffset;

  // Randomize slots with padding
  std::shuffle(slots.begin(), slots.end(), ru.gen);
  curOffset = calculateOffsets<RandUtil>(0, start, ru);

  // Sort by original offset for searching & update frame sizes
  sortSlots();
  randomizedSize = curOffset - start;
  randomizedOffset = curOffset;

  DEBUG_VERBOSE(
    DEBUGMSG_VERBOSE("randomized slots:" << std::endl);
    for(size_t i = 0; i < slots.size(); i++)
      DEBUGMSG_VERBOSE("  " << slots[i].original << " -> "
                       << slots[i].randomized << std::endl);
  )
}

double RandomizableRegion::entropy(int start, size_t maxPadding) const {
  const size_t permuteLocs = slots.size();
  double avg = 0.0;

  for(auto &s : slots)
    avg += entropyBits(permuteLocs +
                       ROUND_UP(maxPadding, s.alignment) / s.alignment);
  return avg / (double)slots.size();
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
                                       const function_record *func,
                                       size_t maxPadding)
  : binary(binary), func(func), instrs(nullptr), maxFrameSize(UINT32_MAX),
    prevRandFrameSize(func->frame_size), randomizedFrameSize(func->frame_size),
    maxPadding(maxPadding) {
  int offset;
  arch::RegType type;
  Binary::slot_iterator si = binary.getStackSlots(func);

  curRand = &_a;
  prevRand = &_b;
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

// Note: we don't really care about previous randomization information as we're
// setting up to immediately kick off another randomization; the current
// randomization information will be set as the previous randomizaiton.
RandomizedFunction::RandomizedFunction(const RandomizedFunction &rhs,
                                       MemoryWindow &mw)
  : binary(rhs.binary), func(rhs.func), maxFrameSize(rhs.maxFrameSize),
    transformAddrs(rhs.transformAddrs), slots(rhs.slots), _a(rhs._a),
    _b(rhs._b), seen(rhs.seen), randomizedFrameSize(rhs.randomizedFrameSize),
    maxPadding(rhs.maxPadding) {
  // Deep copy the instructions and point raw bits to the new code buffer
  size_t instrSize;
  if(rhs.instrs) {
    byte_iterator funcData = mw.getData(func->addr);
    byte *cur = funcData[0], *end = cur + func->code_size;
    instrs = instrlist_clone(GLOBAL_DCONTEXT, rhs.instrs);
    instr_t *instr = instrlist_first(instrs),
            *rhsInstr = instrlist_first(rhs.instrs);

    assert(cur && instr && rhsInstr && "Invalid deep copy of instructions");

    while(cur < end) {
      assert(instr && rhsInstr && "Invalid function copy");
      assert(instr_raw_bits_valid(rhsInstr) && "Bits not set");

      instrSize = instr_length(GLOBAL_DCONTEXT, rhsInstr);
      instr_set_raw_bits(instr, cur, instrSize);
      cur += instrSize;
      instr = instr_get_next(instr);
      rhsInstr = instr_get_next(rhsInstr);
    }
  }
  else instrs = nullptr;

  if(rhs.curRand == &rhs._a) {
    curRand = &_a;
    prevRand = &_b;
  }
  else {
    curRand = &_b;
    prevRand = &_a;
  }
  prevSortedByRand.resize(_a.size());

  // Deep copy the regions
  regions.reserve(rhs.regions.size());
  for(auto &r : rhs.regions) regions.emplace_back(r->copy());
}

/**
 * Copy slot remapping information from a stack region into another vector.
 * @param r a stack region
 * @param slots a vector of slot remapping information
 * @param curIdx current index of slots at which to start copying
 * @return the updated index after copying
 */
static inline size_t serializeSlots(const StackRegionPtr &r,
                                    std::vector<SlotMap> &slots,
                                    size_t curIdx) {
  const std::vector<SlotMap> &curSlots = (*r).getSlots();
  memcpy(&slots[curIdx], &curSlots[0], sizeof(SlotMap) * curSlots.size());
  return curIdx + curSlots.size();
}

/**
 * Comparison function for sorting & searching a SlotMap.  Searches based on
 * the randomized offset.
 *
 * @param first slot mapping
 * @param second slot mapping
 * @return true if a's first element is less than b's first element
 */
static bool slotMapCmpRand(const SlotMap &a, const SlotMap &b)
{ return a.randomized < b.randomized; }

#ifdef DEBUG_BUILD
/**
 * Verify that a randomized produced no overlapping slots.
 * @param slots a vector of slot remappings
 * @return true if the randomization is good or false if we detected
 *         overlapping slots
 */
bool verifySlots(const std::vector<SlotMap> &slots) {
  int curOffset = 0;
  std::vector<SlotMap> copy(slots);

  std::sort(copy.begin(), copy.end(), slotMapCmpRand);
  for(auto &slot : copy) {
    if((int)(slot.randomized - slot.size) < curOffset) {
      DEBUG(WARN("Found unsorted/overlapping slots: slot with range "
                 << (int)(slot.randomized - slot.size) << " -> "
                 << slot.randomized << " overlaps previous slot ending at "
                 << curOffset << std::endl));
      return false;
    }
    else curOffset = slot.randomized;
  }
  return true;
}
#endif

ret_t RandomizedFunction::finalizeAnalysis() {
  // We need to maintain a previous randomization mapping because as we
  // randomize we rewrite the instructions, clobbering the original offsets.
  // Start by sizing the slot remapping arrays.
  size_t count = 0;
  for(auto r = regions.begin(); r != regions.end(); r++)
    count += (*r)->numSlots();
  _a.resize(count);
  _b.resize(count);
  prevSortedByRand.resize(count);

  // Now add the slots to the current array to bootstrap
  count = 0;
  for(auto r = regions.begin(); r != regions.end(); r++)
    count = serializeSlots(*r, *curRand, count);

  // Because the child classes are lazy, set the "randomized" offsets to the
  // original offsets to perform translations for the initial randomization
  for(count = 0; count < curRand->size(); count++) {
    auto &ref = curRand->at(count);
    ref.randomized = ref.original;
  }
  std::sort(curRand->begin(), curRand->end(), slotMapCmp);

  assert((uint32_t)regions.back()->getOriginalOffset() <= maxFrameSize &&
         "Invalid calculated frame size");
  DEBUG(
    if(!verifySlots(*curRand)) return ret_t::AnalysisFailed;

    int offset = 0;
    for(const auto &r : regions) {
      offset = std::max(offset, r->getMinStartingOffset());
      DEBUGMSG("bits of entropy: " << r->entropy(offset, maxPadding)
               << std::endl);
      offset = r->getOriginalOffset();
    }
  )

  return ret_t::Success;
}

ret_t RandomizedFunction::randomize(int seed) {
  size_t i;
  int offset = 0;
  RandUtil ru(seed, maxPadding);

  // Move current mappings to previous so we can serialize the new mappings
  // into the current slot remapping vector.  Create a secondary vector of the
  // previous mapping sorted by the randomized offset (instead of original) so
  // that we can use a binary search in getOriginalMapping().
  std::swap(prevRand, curRand);
  memcpy(&prevSortedByRand[0], &prevRand->at(0),
         sizeof(SlotMap) * prevSortedByRand.size());
  std::sort(prevSortedByRand.begin(), prevSortedByRand.end(), slotMapCmpRand);

  i = 0;
  for(auto r = regions.begin(); r != regions.end(); r++) {
    offset = std::max(offset, (*r)->getMinStartingOffset());
    (*r)->randomize(offset, ru);
    offset = (*r)->getRandomizedOffset();
    assert(offset <= (*r)->getMaxOffset() && "Invalid randomized region");

    // Serialize the region's slots into the global vector to be passed to the
    // state transformation runtime
    i = serializeSlots(*r, *curRand, i);
  }
  prevRandFrameSize = randomizedFrameSize;
  randomizedFrameSize = regions.back()->getRandomizedOffset();
  randomizedFrameSize = ROUND_UP(randomizedFrameSize, getFrameAlignment());

  assert(randomizedFrameSize <= maxFrameSize && "Invalid randomization");
  DEBUG(
    if(!verifySlots(*curRand)) return ret_t::RandomizeFailed;
    for(auto slot : *curRand)
      DEBUGMSG("  slot mapping: " << slot.original << " - " << slot.randomized
               << std::endl);
  )

  DEBUGMSG("randomized frame size: " << randomizedFrameSize << std::endl);

  return ret_t::Success;
}

/**
 * Return whether the SlotMap contains a given offset.  Uses the slot's
 * randomized offset.
 *
 * @param slot a slot mapping
 * @offset a canonicalized stack offset
 * @param true if the slot contains the offset or false otherwise
 */
static bool slotMapContainsRand(const SlotMap *slot, int offset)
{ return CONTAINS_BELOW(offset, slot->randomized, slot->size); }

/**
 * Return whether an offset would appear in a SlotMap before the specified
 * SlotMap in a sorted ordering of SlotMaps.  Uses the slot's randomized
 * offset.
 *
 * @param slot a slot mapping
 * @param offset a canonicalized stack offseta
 * @return true if the offset would appear before the slot or false otherwise
 */
static bool lessThanSlotMapRand(const SlotMap *slot, int offset)
{ return offset < slot->randomized; }

int RandomizedFunction::getOriginalOffset(int prev) const {
  int offset = INT32_MAX;
  ssize_t idx;

  idx = findRight<SlotMap, int, slotMapContainsRand, lessThanSlotMapRand>
                 (&prevSortedByRand[0], prevSortedByRand.size(), prev);
  if(idx >= 0 && slotMapContainsRand(&prevSortedByRand[idx], prev))
    offset = prev - prevSortedByRand[idx].randomized +
                    prevSortedByRand[idx].original;
  return offset;
}

int RandomizedFunction::getRandomizedOffset(int orig) const {
  int offset = INT32_MAX;
  ssize_t idx;

  idx = findRight<SlotMap, int, slotMapContains, lessThanSlotMap>
                 (&curRand->at(0), curRand->size(), orig);
  if(idx >= 0 && slotMapContains(&curRand->at(idx), orig))
    offset = orig - curRand->at(idx).original + curRand->at(idx).randomized;
  return offset;
}

/**
 * Return whether the slot contains a given offset.
 * @param slot offset/stack slot record pair
 * @param offset a canonicalized offset
 * @return true if the slot contains the offset, false otherwise
 */
static bool
slotContains(const std::pair<int, const stack_slot *> *slot, int offset)
{ return CONTAINS_BELOW(offset, slot->first, slot->second->size); }

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
 * Return whether the slot contains a given offset inclusive of the slot's
 * ending offset.
 *
 * @param slot offset/stack slot record pair
 * @param offset a canonicalized offset
 * @return true if the slot contains the offset, false otherwise
 */
static bool
slotContainsInclusive(const std::pair<int, const stack_slot *> *slot,
                       int offset)
{ return CONTAINS_BELOW_INCLUSIVE(offset, slot->first, slot->second->size); }

std::pair<int, const stack_slot *>
RandomizedFunction::findSlotEndInclusive(int offset) {
  ssize_t idx = findRight<std::pair<int, const stack_slot *>, int,
                          slotContainsInclusive, lessThanSlot>
                         (&slots[0], slots.size(), offset);
  if(idx >= 0 && slotContainsInclusive(&slots[idx], offset)) return slots[idx];
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
{ return offset < (*region)->getOriginalOffset(); }

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

