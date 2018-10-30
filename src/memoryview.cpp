#include <cstring>

#include "log.h"
#include "memoryview.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// MemoryRegion implementation
///////////////////////////////////////////////////////////////////////////////

size_t FileRegion::populate(uintptr_t address,
                            std::vector<char> &buffer,
                            size_t offset) const {
  ssize_t regOffset = address - start;
  size_t curLen, copyLen = 0;

  // Copy the on-disk data
  curLen = fileLen - regOffset;
  if(curLen > 0) {
    copyLen = std::min<size_t>(buffer.size() - offset, curLen);
    memcpy(&buffer[offset], (char *)data + regOffset, copyLen);
    offset += curLen;
  }

  // Set the remaining region memory to zeros
  curLen = std::min<size_t>(buffer.size() - offset, len - fileLen);
  memset(&buffer[offset], 0, curLen);

  return copyLen + curLen;
}

BufferedRegion::BufferedRegion(uintptr_t start,
                               size_t len,
                               size_t fileLen,
                               const void *data)
    : MemoryRegion(start, len) {
  fileLen = std::min<size_t>(len, fileLen);
  this->data.reset(new char[len]);
  memcpy(this->data.get(), data, fileLen);
  memset(&this->data[fileLen], 0, len - fileLen);
}

size_t BufferedRegion::populate(uintptr_t address,
                                std::vector<char> &buffer,
                                size_t offset) const {
  ssize_t regOffset = address - start;
  ssize_t copyLen = std::min<ssize_t>(buffer.size() - offset, len - regOffset);
  assert(copyLen >= 0 && "Invalid offset or address not contained in region");
  memcpy(&buffer[offset], this->data.get(), copyLen);
  return copyLen;
}

///////////////////////////////////////////////////////////////////////////////
// MemoryWindow implementation
///////////////////////////////////////////////////////////////////////////////

ret_t
MemoryWindow::project(uintptr_t address, std::vector<char> &buffer) const {
  ssize_t regNum = findRegionRight(address), offset = 0,
          bufSize = buffer.size(), len;
  std::vector<MemoryRegionPtr>::const_iterator r;

  if(regNum < 0) {
    memset(&buffer[0], 0, buffer.size());
    return ret_t::Success;
  }
  r = regions.begin() + regNum;

  for(; r != regions.end() && offset < bufSize; r++) {
    // Copy any bytes before the region into the buffer
    len = (*r)->getStart() - address;
    if(len > 0) {
      memset(&buffer[offset], 0, len);
      offset += len;
      address += len;
    }
    else if(len < 0) {
      WARN("overlapping memory regions in window" << std::endl);
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

ssize_t MemoryWindow::findRegionRight(uintptr_t address) const {
  ssize_t low = 0, high = regions.size() - 1, mid;

  if(high < 0) return -1;
  do {
    mid = (high + low) / 2;
    if(regions[mid]->contains(address)) return mid;
    else if(address < regions[mid]->getStart()) high = mid - 1;
    else low = mid + 1;
  } while(high >= low);

  // Didn't find the record, return the next highest one (if available)
  if(address < regions[mid]->getStart()) return mid;
  else if(mid < regions.size() - 1) return mid + 1;
  else return -1;
}

