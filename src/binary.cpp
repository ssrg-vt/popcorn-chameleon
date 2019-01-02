#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <het_bin.h>

#include "arch.h"
#include "binary.h"
#include "log.h"

using namespace chameleon;

///////////////////////////////////////////////////////////////////////////////
// Section implementation
///////////////////////////////////////////////////////////////////////////////

ret_t Binary::Section::initialize(Elf *elf,
                                  const char *name,
                                  GElf_Shdr &header,
                                  Elf_Scn *section) {
  this->elf = elf;
  this->name = name;
  this->header = header;
  this->section = section;
  if(header.sh_entsize) {
    entrySize = header.sh_entsize;
    numEntries = header.sh_size / header.sh_entsize;
  }
  else entrySize = numEntries = 0;
  if(!(data = elf_getdata(section, nullptr))) return ret_t::ElfReadError;

  DEBUGMSG_VERBOSE("Section '" << name << "':" << std::endl);
  DEBUGMSG_VERBOSE("  Address: 0x" << std::hex << header.sh_addr << std::endl);
  DEBUGMSG_VERBOSE("  File offset: 0x" << std::hex << header.sh_offset
                   << std::endl);
  DEBUGMSG_VERBOSE("  Size: " << header.sh_size << " bytes" << std::endl);
  DEBUG_VERBOSE(
    if(this->entrySize)
      DEBUGMSG_VERBOSE("  Entries: " << numEntries << " (size = " << entrySize
                       << " bytes)" << std::endl);
  )

  return ret_t::Success;
}

// TODO if we end up doing this more than once we should go ahead and cache the
// entire symbol table in a map (with name as a key) for faster lookups
uintptr_t Binary::SymbolTable::getSymbolAddress(const std::string &sym) const {
  GElf_Sym symEntry;
  for(size_t i = 0; i < numEntries; i++) {
    if(gelf_getsym(data, i, &symEntry) != &symEntry) return 0;
    std::string curSym(elf_strptr(elf, header.sh_link, symEntry.st_name));
    if(sym == curSym) return symEntry.st_value;
  }
  return 0;
}

///////////////////////////////////////////////////////////////////////////////
// Binary implementation
///////////////////////////////////////////////////////////////////////////////

ret_t Binary::initLibELF() {
  if(elf_version(EV_CURRENT) == EV_NONE) return ret_t::ElfFailed;
  else return ret_t::Success;
}

static inline bool checkCompatibility(Elf *e) {
  Elf64_Ehdr *ehdr;

  if(elf_kind(e) != ELF_K_ELF) return false;
  if(gelf_getclass(e) != ELFCLASS64) return false;
  if(!(ehdr = elf64_getehdr(e))) return false;
  if(!arch::supportedArch(ehdr->e_machine)) return false;

  return true;
}

static bool initializeSegments(Elf *e, std::vector<Binary::Segment> &segments) {
  size_t numHeaders;
  GElf_Phdr header;

  if(elf_getphdrnum(e, &numHeaders) != 0) return false;
  segments.reserve(numHeaders);
  for(size_t i = 0; i < numHeaders; i++) {
    if(gelf_getphdr(e, i, &header) != &header) return false;
    segments.emplace_back(header);

    DEBUGMSG_VERBOSE("Segment " << i << ":" << std::endl);
    DEBUGMSG_VERBOSE("  Address: 0x" << std::hex << segments[i].address()
                     << std::endl);
    DEBUGMSG_VERBOSE("  File offset: 0x" << segments[i].fileOffset()
                     << std::endl);
    DEBUGMSG_VERBOSE("  File size: " << std::dec << segments[i].fileSize()
                     << std::endl);
    DEBUGMSG_VERBOSE("  Memory size: " << segments[i].memorySize()
                     << std::endl);
    DEBUGMSG_VERBOSE("  Type: 0x" << std::hex << segments[i].type()
                     << std::endl);
    DEBUGMSG_VERBOSE("  Flags: 0x" << std::hex << segments[i].flags()
                     << std::endl);
  }

  return true;
}

static inline ssize_t fileSize(int fd) {
  struct stat buf;
  assert(fd >= 0 && "Invalid file descriptor");
  if(fstat(fd, &buf) == -1) return -1;
  else return buf.st_size;
}

static inline void buildSectionName(std::string &buf, const char *sec) {
  buf = SECTION_PREFIX;
  buf += ".";
  buf += sec;
}

ret_t Binary::initialize() {
  ret_t retcode = ret_t::Success;
  std::string buf;
  ssize_t fsize;

  if((fd = open(filename, O_RDONLY)) == -1 ||
     (fsize = fileSize(fd)) == -1) {
    retcode = ret_t::OpenFailed;
    goto error;
  }

  size = fsize;
  if(!(data = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0))) {
    retcode = ret_t::OpenFailed;
    goto error;
  }

  DEBUGMSG("opened '" << filename << "' for reading" << std::endl);

  if(!(elf = elf_memory((char *)data, size))) {
    retcode = ret_t::ElfReadError;
    goto error;
  }

  if(!checkCompatibility(elf)) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

  if(elf_getshdrstrndx(elf, &shdrstrndx) ||
     !initializeSegments(elf, segments)) {
    retcode = ret_t::ElfReadError;
    goto error;
  }

  // TODO load in all sections?

  if(getSectionByType(SHT_SYMTAB, symtab) != ret_t::Success)
    DEBUGMSG("binary is stripped - no symbol table" << std::endl);

  // Cache the code section & segment containing the code
  if(getSectionByName(".text", codeSection) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

  if(getSegmentByAddress(codeSection.address(),
                         codeSegment) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

  buildSectionName(buf, SECTION_FUNCTIONS);
  if(getSectionByName(buf.c_str(), functions) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }
  functions.setEntrySize(sizeof(function_record));

  buildSectionName(buf, SECTION_STACK_SLOTS);
  if(getSectionByName(buf.c_str(), stackSlots) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }
  stackSlots.setEntrySize(sizeof(stack_slot));

  buildSectionName(buf, SECTION_UNWIND);
  if(getSectionByName(buf.c_str(), unwind) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }
  unwind.setEntrySize(sizeof(unwind_loc));
  goto finish;

error:
  cleanup();
finish:
  return retcode;
}

void Binary::cleanup() {
  if(elf) elf_end(elf);
  elf = nullptr;
  if(data) munmap(data, size);
  data = nullptr;
  size = 0;
  if(fd != -1) close(fd);
  fd = -1;
  segments.clear();
  DEBUG(
    filename = nullptr;
    shdrstrndx = UINT64_MAX;
  )
}

byte_iterator Binary::getData(uintptr_t addr, const Segment &segment) const {
  uintptr_t fileAddr;
  off_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    fileAddr = (uintptr_t)data + segment.fileOffset() + offset;
    if(binaryContains(fileAddr))
      return byte_iterator((unsigned char *)fileAddr,
                           segment.fileSize() - offset);
  }
  return byte_iterator::empty();
}

byte_iterator Binary::getData(uintptr_t addr) const {
  Segment tmp;
  if(getSegmentByAddress(addr, tmp) != ret_t::Success)
    return byte_iterator::empty();
  else return getData(addr, tmp);
}

size_t
Binary::getRemainingMemSize(uintptr_t addr, const Segment &segment) const {
  size_t remaining = 0;
  size_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    if(offset <= segment.memorySize())
      remaining = segment.memorySize() - offset;
  }
  return remaining;
}

size_t Binary::getRemainingMemSize(uintptr_t addr) const {
  Segment tmp;
  if(getSegmentByAddress(addr, tmp) != ret_t::Success) return 0;
  else return getRemainingMemSize(addr, tmp);
}

size_t
Binary::getRemainingFileSize(uintptr_t addr, const Segment &segment) const {
  size_t remaining = 0;
  size_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    if(offset < segment.fileSize()) remaining = segment.fileSize() - offset;
  }
  return remaining;
}

size_t Binary::getRemainingFileSize(uintptr_t addr) const {
  Segment tmp;
  if(getSegmentByAddress(addr, tmp) != ret_t::Success) return 0;
  else return getRemainingFileSize(addr, tmp);
}

/**
 * Return whether the address is contained within a function.
 * @param func the function record
 * @param addr the virtual address
 * @return true if contained or false otherwise
 */
static bool funcContains(const function_record *func, uintptr_t addr)
{ return CONTAINS_ABOVE(addr, func->addr, func->code_size); }

/**
 * Return whether the address comes before the start of the function in the
 * virtual address space.
 * @param func the function record
 * @param addr the virtual address
 * @return true if addr comes before the function or false otherwise
 */
static bool lessThanFunc(const function_record *func, uintptr_t addr)
{ return addr < func->addr; }

Binary::func_iterator
Binary::getFunctions(uintptr_t start, uintptr_t end) const {
  ssize_t idx;
  size_t count;
  const function_record *record;

  if(end <= start) return func_iterator::empty();

  // Find the first function containing start or starting directly after it
  idx = findRight<function_record, uintptr_t, funcContains, lessThanFunc>
                 (functions.getEntries(), functions.getNumEntries(), start);
  if(idx < 0) return func_iterator::empty();
  record = functions.getEntries();

  // Find all remaining functions in the range
  for(count = idx; count < functions.getNumEntries(); count++)
    if(record[count].addr >= end) break;

  return func_iterator(&record[idx], count - idx);
}

template<typename T, typename it>
static inline it getIterator(const Binary::EntrySection<T> &section,
                             size_t offset, size_t num) {
  size_t entries = section.getNumEntries(), remaining = entries - offset;
  if(remaining <= 0) return it::empty();
  if(remaining < num)
    WARN("Function record indicated more entries than available" << std::endl);
  entries = std::min<ssize_t>(remaining, num);
  return it(&section.getEntries()[offset], entries);
}

Binary::slot_iterator
Binary::getStackSlots(const function_record *func) const {
  return getIterator<stack_slot, slot_iterator>(stackSlots,
                                                func->stack_slot.offset,
                                                func->stack_slot.num);
}

Binary::unwind_iterator
Binary::getUnwindLocations(const function_record *func) const {
  return getIterator<unwind_loc, unwind_iterator>(unwind,
                                                  func->unwind.offset,
                                                  func->unwind.num);
}

ret_t Binary::getSectionByName(const char *name, Section &section) {
  size_t len = strnlen(name, 512);
  const char *curName;
  Elf_Scn *scn = nullptr;
  GElf_Shdr shdr;

  while((scn = elf_nextscn(elf, scn))) {
    if(gelf_getshdr(scn, &shdr) != &shdr) return ret_t::ElfReadError;
    if((curName = elf_strptr(elf, shdrstrndx, shdr.sh_name)) &&
       strncmp(name, curName, len) == 0)
      return section.initialize(elf, name, shdr, scn);
  }

  return ret_t::NoSuchSection;
}

ret_t Binary::getSectionByType(uint32_t type, Section &section) {
  const char *name;
  Elf_Scn *scn = nullptr;
  GElf_Shdr shdr;

  while((scn = elf_nextscn(elf, scn))) {
    if(gelf_getshdr(scn, &shdr) != &shdr) return ret_t::ElfReadError;
    if(shdr.sh_type == type) {
      name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
      return section.initialize(elf, name, shdr, scn);
    }
  }

  return ret_t::NoSuchSection;
}

ret_t Binary::getSegmentByAddress(uintptr_t addr, Segment &segment) const {
  for(auto &seg : segments) {
    if(seg.contains(addr)) {
      segment = seg;
      return ret_t::Success;
    }
  }
  return ret_t::NoSuchSection;
}

