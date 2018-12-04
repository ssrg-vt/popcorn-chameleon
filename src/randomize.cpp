#include <algorithm>
#include <map>
#include <cmath>
#include <cstdlib>

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
        WARN("overlapping slots? "
             << sm.original << " -> " << sm.original + sm.size << ", "
             << offset << " -> " << offset + size << std::endl);
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

void ImmutableRegion::randomize(int start, RandUtil &ru) {
  sortSlots();
  for(auto &sm : slots) sm.randomized = sm.original;
  randomizedOffset = start - origSize;
  randomizedSize = origSize;
}

/**
 * Move a slot (toMove) to be placed before another slot (pos).
 * @param slots vector of slots
 * @param pos the position to place the moved slot
 * @param toMove the slot to be moved
 */
static void
moveBefore(std::vector<SlotMap> &slots, size_t pos, size_t toMove) {
  assert(pos < slots.size() && toMove < slots.size() && pos < toMove);
  SlotMap newSM(slots[toMove]);
  slots.insert(slots.begin() + pos, newSM);
  slots.erase(slots.begin() + toMove + 1);
}

void PermutableRegion::randomize(int start, RandUtil &ru) {
  bool filled;
  int curOffset = abs(start), prevOffset;
  unsigned bubble;
  size_t i, j, prevBubbleIdx;

  // Shuffle the slots & set randomized offsets
  std::shuffle(slots.begin(), slots.end(), ru.gen);
  for(i = 0; i < slots.size(); i++) {
    curOffset = ROUND_UP(curOffset + slots[i].size, slots[i].alignment);
    slots[i].randomized = -curOffset;
  }

  // Randomization may have created "bubbles" for stack slots with different
  // sizes & alignments.  Try to resolve bubbles by rearranging slots through
  // a single pass from those closest to the CFA to those furthest away.
  prevOffset = start;
  for(i = 0; i < slots.size(); i++) {
    bubble = abs(slots[i].randomized - prevOffset) - slots[i].size;
    if(bubble) {
      filled = false;

      // TODO make iterative so we can use multiple other slots to fill bubbles

      // First attempt: search slots *after* (i.e., further away from CFA) the
      // current slot to put in front of this slot as it won't perturb previous
      // bubble fillings
      for(j = i + 1; j < slots.size(); j++) {
        if(slots[j].size == bubble && slots[j].alignment == bubble) {
          // Found an eligible slot, swap in front of the bubble-inducing slot
          moveBefore(slots, i, j);
          filled = true;
          break;
        }
      }

      if(filled) {
        // Re-calculate offsets & update index to account for moved slot
        curOffset = abs(prevOffset);
        for(j = i; j < slots.size(); j++) {
          curOffset = ROUND_UP(curOffset + slots[j].size, slots[j].alignment);
          slots[j].randomized = -curOffset;
        }
        i++;
      }
      // TODO ROB if not resolved, search before for slots to move after
      else break;
    }
    prevOffset = slots[i].randomized;
  }

  // Sometimes we actually manage to create smaller regions than those laid out
  // by the compiler.  Logically pad to fill the region.
  assert(slots[slots.size()-1].randomized >= origOffset);
  randomizedOffset = origOffset;
  randomizedSize = origSize;

  // Sort by original offset for searching
  sortSlots();
}

void RandomizableRegion::randomize(int start, RandUtil &ru) {
  int curOffset = abs(start);

  // Shuffle the slots & set their randomized offset (including padding)
  std::shuffle(slots.begin(), slots.end(), ru.gen);
  for(size_t i = 0; i < slots.size(); i++) {
    curOffset = ROUND_UP(slots[i].size + ru.slotPadding() + curOffset,
                         slots[i].alignment);
    slots[i].randomized = -curOffset;
  }

  // Sort by original offset for searching & update frame sizes
  sortSlots();
  randomizedSize = curOffset - abs(start);
  randomizedOffset = -curOffset;
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
      DEBUGMSG("  Register " << unwind->reg << " at FBP + " << unwind->offset
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

  DEBUGMSG("Randomized frame size: " << randomizedFrameSize << std::endl);

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

