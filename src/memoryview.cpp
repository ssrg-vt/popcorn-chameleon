#include <cstring>

#include "log.h"
#include "memoryview.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// MemoryRegion implementation
///////////////////////////////////////////////////////////////////////////////

MemoryRegion *FileRegion::copy() const
{ return new FileRegion(start, len, fileLen, data); }

size_t FileRegion::populate(uintptr_t address,
                            std::vector<char> &buffer,
                            size_t offset) const {
  ssize_t regOffset = address - start;
  size_t curLen, copyLen = 0;

  // Copy the on-disk data
  curLen = fileLen - regOffset;
  if(curLen > 0) {
    copyLen = std::min<size_t>(buffer.size() - offset, curLen);
    memcpy(&buffer[offset], *data + regOffset, copyLen);
    offset += curLen;
  }

  // Set the remaining region memory to zeros
  curLen = std::min<size_t>(buffer.size() - offset, len - fileLen);
  memset(&buffer[offset], 0, curLen);

  return copyLen + curLen;
}

byte_iterator FileRegion::getData(uintptr_t address) {
  ssize_t regOffset = address - start, remainingLen = fileLen - regOffset;
  if(regOffset >= 0 && remainingLen >= 0)
    return byte_iterator(data[regOffset], remainingLen);
  else return byte_iterator::empty();
}

MemoryRegion *BufferedRegion::copy() const {
  byte_iterator buf(data.get(), len);
  return new BufferedRegion(start, len, len, buf);
}

BufferedRegion::BufferedRegion(uintptr_t start,
                               size_t len,
                               size_t fileLen,
                               byte_iterator data)
    : MemoryRegion(start, len) {
  assert(data.getLength() >= fileLen && "Invalid BufferedRegion");
  fileLen = std::min<size_t>(len, fileLen);
  this->data.reset(new unsigned char[len]);
  memcpy(this->data.get(), *data, fileLen);
  memset(&this->data[fileLen], 0, len - fileLen);
}

size_t BufferedRegion::populate(uintptr_t address,
                                std::vector<char> &buffer,
                                size_t offset) const {
  ssize_t regOffset = address - start;
  ssize_t copyLen = std::min<ssize_t>(buffer.size() - offset, len - regOffset);
  assert(copyLen >= 0 && "Invalid offset or address not contained in region");
  memcpy(&buffer[offset], &(this->data.get()[regOffset]), copyLen);
  return copyLen;
}

byte_iterator BufferedRegion::getData(uintptr_t address) {
  ssize_t regOffset = address - start;
  assert(len - regOffset >= 0 && "Invalid address");
  if(regOffset >= 0) return byte_iterator(&data[regOffset], len - regOffset);
  else return byte_iterator::empty();
}

///////////////////////////////////////////////////////////////////////////////
// MemoryWindow implementation
///////////////////////////////////////////////////////////////////////////////

void MemoryWindow::operator=(MemoryWindow &rhs) {
  regions.clear();
  regions.reserve(rhs.regions.size());
  for(auto &r : rhs.regions) regions.emplace_back(std::move(r));
  rhs.regions.clear();
}

void MemoryWindow::copy(const MemoryWindow &toCopy) {
  regions.clear();
  regions.reserve(toCopy.regions.size());
  for(auto &r : toCopy.regions)
    regions.emplace_back(MemoryRegionPtr(r->copy()));
}

/**
 * Return whether the address is contained within a region.
 * @param region the region object
 * @param addr the virtual address
 * @return true if contained or false otherwise
 */
static bool regionContains(const MemoryRegionPtr *region, uintptr_t addr)
{ return (*region)->contains(addr); }

/**
 * Return whether the address comes before the start of the region in the
 * virtual address space.
 * @param region the region object
 * @param addr the virtual address
 * @return true if addr comes before the region or false otherwise
 */
static bool lessThanRegion(const MemoryRegionPtr *region, uintptr_t addr)
{ return addr < (*region)->getStart(); }

uintptr_t MemoryWindow::zeroCopy(uintptr_t address) const {
  ssize_t regNum;
  byte_iterator data;

  regNum = findRight<MemoryRegionPtr, uintptr_t,
                     regionContains, lessThanRegion>
                    (&regions[0], regions.size(), address);
  if(regNum >= 0 && regions[regNum]->contains(address)) {
    data = regions[regNum]->getData(address);
    if(data.getLength() >= PAGESZ) return (uintptr_t)*data;
  }
  return 0;
}

ret_t
MemoryWindow::project(uintptr_t address, std::vector<char> &buffer) const {
  ssize_t regNum, offset = 0, bufSize = buffer.size(), len;
  std::vector<MemoryRegionPtr>::const_iterator start, r;

  regNum = findRight<MemoryRegionPtr, uintptr_t,
                     regionContains, lessThanRegion>
                    (&regions[0], regions.size(), address);
  if(regNum < 0) {
    memset(&buffer[0], 0, buffer.size());
    return ret_t::Success;
  }

  start = regions.begin() + regNum;
  for(r = start; r != regions.end() && offset < bufSize; r++) {
    // Copy any bytes before the region into the buffer
    len = (*r)->getStart() - address;
    if(len > 0) {
      memset(&buffer[offset], 0, len);
      offset += len;
      address += len;
    }
    else if(len < 0 && r != start) {
      WARN("Overlapping memory regions in window" << std::endl);
      return ret_t::BadMarshal;
    }

    // Copy the region's contents into the buffer
    len = (*r)->populate(address, buffer, offset);
    offset += len;
    address += len;
  }

  // Regions don't fill the buffer, zero-fill remaining space
  if(offset < bufSize) memset(&buffer[offset], 0, offset - bufSize);

  return ret_t::Success;
}

byte_iterator MemoryWindow::getData(uintptr_t address) {
  ssize_t regNum = findRight<MemoryRegionPtr, uintptr_t,
                             regionContains, lessThanRegion>
                            (&regions[0], regions.size(), address);
  if(regNum >= 0 && regions[regNum]->contains(address))
    return regions[regNum]->getData(address);
  else return byte_iterator::empty();
}

