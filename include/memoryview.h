/**
 * Classes for building and composing views into memory regions.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/23/2018
 */

#ifndef _MEMORYVIEW_H
#define _MEMORYVIEW_H

#include <algorithm>
#include <memory>
#include <vector>
#include <cstdint>

#include "types.h"
#include "utils.h"

namespace chameleon {

/**
 * class MemoryRegion
 *
 * A contiguous region of memory which can be composed together with other
 * MemoryRegions.  MemoryRegions represent contiguous chunks of memory, i.e.,
 * no holes between start and end of region.  Child classes implement versions
 * with different types of backing stores.
 */
class MemoryRegion {
public:
  /**
   * Instantiate a new memory region.
   * @param start starting address of region
   * @param len length of region in bytes
   */
  MemoryRegion(uintptr_t start, size_t len)
    : start(start), end(start + len), len(len) {}
  MemoryRegion() : start(UINT64_MAX), end(UINT64_MAX), len(UINT64_MAX) {}

  /**
   * Populate the buffer with the region's memory.
   * @param address the starting address to copy into the buffer
   * @param buffer buffer to populate with region's memory
   * @param offset starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(uintptr_t address,
                          std::vector<char> &buffer,
                          size_t offset) const = 0;

  /**
   * Get an iterator to the underlying data store at a given address.
   * @param addr a program virtual address
   * @return an iterator for accessing the underlying data
   */
  virtual byte_iterator getData(uintptr_t address)
  { return byte_iterator::empty(); }

  /* Comparison types & functions for sorting */
  static bool compare(const std::unique_ptr<MemoryRegion> &lhs,
                      const std::unique_ptr<MemoryRegion> &rhs)
  { return lhs->start < rhs->start; }

  /**
   * Field getters - return what you ask for.
   */
  uintptr_t getStart() const { return start; }
  uintptr_t getEnd() const { return end; }
  size_t getLength() const { return len; }

  /**
   * Return whether the region contains a virtual memory address.
   * @param addr a virtual memory address
   * @return true if it contains the address, false otherwise
   */
  bool contains(uintptr_t addr) const
  { return CONTAINS_ABOVE(addr, start, len); }

protected:
  uintptr_t start, end;
  size_t len;
};

typedef std::unique_ptr<MemoryRegion> MemoryRegionPtr;

/**
 * class FileRegion
 *
 * Provides a view of memory backed by file.  Maintain a file size separate
 * from region size because ELF executables can represent a subset of a
 * region's memory on disk; the rest of the region is zero-filled at load time.
 * Note that nothing is allocated as all on-disk data is already mapped into
 * memory and the remaining will be zero-initialized.  More efficient than
 * BufferedRegion, but provides a read-only view of the region; use
 * BufferedRegions for regions that need to be manipulated.
 */
class FileRegion : public MemoryRegion {
public:
  /**
   * Instantiate a file-backed MemoryRegion.
   * @param start starting address of region
   * @param len length of region in bytes
   * @param fileLen length of on-disk portion of memory region; truncated to
   *                match len if larger
   * @param data byte iterator to on-disk data previously mapped into memory
   */
  FileRegion(uintptr_t start, size_t len, size_t fileLen, byte_iterator data)
    : MemoryRegion(start, len), fileLen(std::min<size_t>(len, fileLen)),
      data(data)
  { assert(data.getLength() >= fileLen && "Invalid FileRegion"); }

  /**
   * Populate the buffer with the region's memory.
   * @param address the starting address to copy into the buffer
   * @param buffer buffer to populate with region's memory
   * @param offset starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(uintptr_t address,
                          std::vector<char> &buffer,
                          size_t offset) const override;

  /**
   * Get an iterator to the underlying data store at a given address.
   * @param addr a program virtual address
   * @return an iterator for accessing the underlying data
   */
  virtual byte_iterator getData(uintptr_t address) override;
private:
  size_t fileLen;
  byte_iterator data;
};

/**
 * class BufferedRegion
 *
 * Holds the data representing the memory region in a writable memory buffer.
 * The buffer is instantiated using the on-disk file; any remaining in-memory
 * representation is zero-filled.  Use for regions that need to be manipulated.
 */
class BufferedRegion : public MemoryRegion {
public:
  /**
   * Instantiate a memory-backed MemoryRegion.  A memory buffer is allocated,
   * the on-disk data is copied into the buffer and the rest is
   * zero-initialized.
   *
   * @param start starting address of region
   * @param len length of region in bytes
   * @param fileLen length of on-disk portion of memory region; truncated to
   *                match len if larger
   * @param data byte iterator to on-disk data previously mapped into memory
   */
  BufferedRegion(uintptr_t start,
                 size_t len,
                 size_t fileLen,
                 byte_iterator data);

  /**
   * Populate the buffer with the region's memory.
   * @param address the starting address to copy into the buffer
   * @param buffer buffer to populate with region's memory
   * @param offset starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(uintptr_t address,
                          std::vector<char> &buffer,
                          size_t offset) const override;

  /**
   * Get an iterator to the underlying data store at a given address.
   * @param addr a program virtual address
   * @return an iterator for accessing the underlying data
   */
  virtual byte_iterator getData(uintptr_t address) override;
private:
  std::unique_ptr<unsigned char[]> data;
};

/**
 * class MemoryWindow
 *
 * Provides an abstract view of memory, composed of MemoryRegions.
 * MemoryWindows contain one or more potentially non-contiguous MemoryRegions
 * describing the contents of the memory.  While the regions may either "touch"
 * or be non-contiguous, they are *not* overlapping.
 */
class MemoryWindow {
public:
  MemoryWindow() { regions.reserve(8); }

  /**
   * Remove all regions from the window.
   */
  void clear() { regions.clear(); }

  /**
   * Insert a MemoryRegion into the window.  Note that this assumes ownership
   * of the MemoryRegion contained in the unique pointer; the MemoryRegion is
   * no longer valid for the caller.
   *
   * @param region a unique_ptr to a MemoryRegion
   */
  void insert(MemoryRegionPtr &reg) { regions.push_back(std::move(reg)); }

  /**
   * Sort regions in the window by starting address.
   */
  void sort()
  { std::sort(regions.begin(), regions.end(), MemoryRegion::compare); }

  /**
   * Return an address of a buffer that can be directly passed to the kernel to
   * handle a pagefault if possible, or 0 otherwise.  Pages that can be handled
   * as zero-copy do not cross regions and have all their data in memory, e.g.,
   * BufferedRegions or FileRegions where the entire page is inside the region's
   * on-disk data (not past end-of-region or in implicitly-specified zeros).
   *
   * @param address faulting page address
   * @return address of page buffer used to handle fault or 0 if zero-copy is
   *         not possible
   */
  uintptr_t zeroCopy(uintptr_t address) const;

  /**
   * Project the MemoryRegions in the window into the buffer, zero-filling any
   * holes (i.e., not covered by a MemoryRegion) in the window.  Fills the page
   * starting at address with the window's data.
   *
   * Note: it's up to the caller to ensure that the regions are in sorted order
   * before calling project().  Users can do this by calling sort().
   *
   * @param address page address at which to fill
   * @param buffer a buffer into which the MemoryRegion's contents are copied
   * @return a return code describing the outcome
   */
  ret_t project(uintptr_t address, std::vector<char> &buffer) const;

  /**
   * Get an iterator pointing to the data stored at a given address.  Used to
   * read and modify the virtual address space.  Note that non-trivial
   * iterators are only returned if the underlying data store is modifiable,
   * e.g., a BufferedRegion.
   *
   * @param address a program virtual address
   * @return an iterator for accessing the underlying data
   */
  byte_iterator getData(uintptr_t address);

  /**
   * Return the number of regions in the window.
   * @return the number of regions in the window
   */
  size_t numRegions() const { return regions.size(); }
private:
  std::vector<MemoryRegionPtr> regions;
};

}

#endif /* _MEMORYVIEW_H */

