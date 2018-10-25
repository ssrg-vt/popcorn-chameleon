#include <cstring>

#include "memoryview.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// MemoryRegion implementation
///////////////////////////////////////////////////////////////////////////////

size_t FileRegion::populate(std::vector<char> &buffer, size_t start) {
  size_t curLen, copyLen;

  // Copy the on-disk data
  copyLen = curLen = std::min<size_t>(buffer.size() - start, fileLen);
  memcpy(&buffer[start], data, curLen);

  // Copy in zeros for remaining memory size
  start += copyLen;
  curLen = std::min<size_t>(buffer.size() - start, len - fileLen);
  memset(&buffer[start], 0, curLen);

  return copyLen + curLen;
}

BufferedRegion::BufferedRegion(uintptr_t start,
                               size_t len,
                               size_t fileLen,
                               const void *data)
    : MemoryRegion(start, len), size(len) {
  fileLen = std::min<size_t>(len, fileLen);
  this->data.reset(new char[len]);
  memcpy(this->data.get(), data, fileLen);
  memset(&this->data[fileLen], 0, len - fileLen);
}

size_t BufferedRegion::populate(std::vector<char> &buffer, size_t start) {
  size_t copyLen = std::min<size_t>(buffer.size() - start, size);
  memcpy(&buffer[start], this->data.get(), copyLen);
  return copyLen;
}

///////////////////////////////////////////////////////////////////////////////
// MemoryWindow implementation
///////////////////////////////////////////////////////////////////////////////

ret_t MemoryWindow::project(std::vector<char> &buffer) {
  std::set<MemoryRegionPtr, MemoryRegion::comparator>::const_iterator r;
  ssize_t byte = 0, offset, copySize, prevEnd = start;

  if(!regions.size()) {
    memset(&buffer[0], 0, buffer.size());
    return ret_t::Success;
  }

  for(r = regions.begin(); r != regions.end() && byte < buffer.size(); r++) {
    offset = (*r)->getStart() - prevEnd;

    // Error check for overlapping regions & fill in holes with zeros
    if(offset < 0) return ret_t::BadMarshal;
    else if(offset > 0) {
      copySize = std::min<size_t>(buffer.size() - byte, offset);
      memset(&buffer[byte], 0, copySize);
      byte += copySize;
    }

    // Copy in the memory region's data
    byte += (*r)->populate(buffer, byte);
    prevEnd = (*r)->getEnd();
  }

  // Fill any remaining space with zeros
  if(byte != buffer.size()) memset(&buffer[byte], 0, buffer.size() - byte);

  return ret_t::Success;
}

