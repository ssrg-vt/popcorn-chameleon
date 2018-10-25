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
#include <set>
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
    : start(start), end(start + len), len(len)
  { assert(len <= PAGESZ && "Invalid region size"); }
  MemoryRegion() : start(UINT64_MAX), end(UINT64_MAX), len(UINT64_MAX) {}

  /**
   * Populate the buffer with the region's memory.
   * @param buffer buffer to populate with region's memory
   * @param start starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(std::vector<char> &buffer, size_t start) = 0;

  /* Comparison types & operations for sorting */
  typedef bool (*comparator)(const std::unique_ptr<MemoryRegion> &lhs,
                             const std::unique_ptr<MemoryRegion> &rhs);
  static bool compare(const std::unique_ptr<MemoryRegion> &lhs,
                      const std::unique_ptr<MemoryRegion> &rhs)
  { return lhs->start < rhs->start; }

  /**
   * Field getters - return what you ask for.
   */
  uintptr_t getStart() const { return start; }
  uintptr_t getEnd() const { return end; }
  size_t getLength() const { return len; }
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
 */
class FileRegion : public MemoryRegion {
public:
  /**
   * Instantiate a file-backed MemoryRegion.  Nothing is allocated as
   * everything is already mapped into memory (on-disk) or will be
   * zero-initialized.
   *
   * @param start starting address of region
   * @param len length of region in bytes
   * @param fileLen length of on-disk portion of memory region; truncated to
   *                match len if larger
   * @param data pointer to on-disk data previously mapped into memory
   */
  FileRegion(uintptr_t start, size_t len, size_t fileLen, const void *data)
    : MemoryRegion(start, len), fileLen(std::min<size_t>(len, fileLen)),
      data(data) {}

  /**
   * Populate the buffer with the region's memory.
   * @param buffer buffer to populate with region's memory
   * @param start starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(std::vector<char> &buffer, size_t start) override;
private:
  size_t fileLen;
  const void *data;
};

/**
 * class BufferedRegion
 *
 * Holds the data representing the memory region in a writable memory buffer.
 * The buffer is instantiated using the on-disk file; any remaining in-memory
 * representation is zero-filled.
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
   * @param data pointer to on-disk data previously mapped into memory
   */
  BufferedRegion(uintptr_t start,
                 size_t len,
                 size_t fileLen,
                 const void *data);

  /**
   * Populate the buffer with the region's memory.
   * @param buffer buffer to populate with region's memory
   * @param start starting offset within buffer
   * @return number of bytes copied into buffer
   */
  virtual size_t populate(std::vector<char> &buffer, size_t start) override;
private:
  size_t size;
  std::unique_ptr<char[]> data;
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
  MemoryWindow() : regions(MemoryRegion::compare), start(0) {}

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
  void insert(MemoryRegionPtr &region) { regions.insert(std::move(region)); }

  /**
   * Project the MemoryRegions in the window into the buffer.
   * @param buffer a buffer into which the MemoryRegion's contents are copied
   * @return a return code describing the outcome
   */
  ret_t project(std::vector<char> &buffer);

  /**
   * Return the number of regions in the window.
   * @return the number of regions in the window
   */
  size_t size() const { return regions.size(); }

  /**
   * Set the starting address for the window.  Needed because this allows
   * zero-filled regions before the first MemoryRegion's data.
   * @param start the starting address for the window
   */
  void setStart(uintptr_t start) { this->start = start; }
private:
  std::set<MemoryRegionPtr, MemoryRegion::comparator> regions;
  uintptr_t start;
};

}

#endif /* _MEMORYVIEW_H */

