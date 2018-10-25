#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "binary.h"
#include "log.h"
#include "utils.h"

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

  DEBUGMSG("Section '" << name << "':" << std::endl);
  DEBUGMSG("  Address: 0x" << std::hex << header.sh_addr << std::endl);
  DEBUGMSG("  File offset: 0x" << std::hex << header.sh_offset << std::endl);
  DEBUGMSG("  Size: " << header.sh_size << " bytes" << std::endl);

  return ret_t::Success;
}

ret_t Binary::SymbolTable::initialize(Elf *elf,
                                      const char *name,
                                      GElf_Shdr &header,
                                      Elf_Scn *section) {
  ret_t code = Section::initialize(elf, name, header, section);
  if(code != ret_t::Success) return code;
  if(!elf_getdata(section, data)) return ret_t::ElfReadError;
  return ret_t::Success;
}

// TODO if we end up doing this more than once we should go ahead and cache the
// entire symbol table in a map (with name as a key) for faster lookups
uintptr_t Binary::SymbolTable::getSymbolAddress(const std::string &sym) const {
  size_t count = header.sh_size / header.sh_entsize;
  GElf_Sym symEntry;
  for(size_t i = 0; i < count; i++) {
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
  if(elf_kind(e) != ELF_K_ELF) return false;
  if(gelf_getclass(e) != ELFCLASS64) return false;
  // TODO other ELF checks?
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

    DEBUGMSG("Segment " << i << ":" << std::endl);
    DEBUGMSG("  Address: 0x" << std::hex << segments[i].address() << std::endl);
    DEBUGMSG("  File offset: 0x" << segments[i].fileOffset() << std::endl);
    DEBUGMSG("  File size: " << std::dec << segments[i].fileSize() << std::endl);
    DEBUGMSG("  Memory size: " << segments[i].memorySize() << std::endl);
    DEBUGMSG("  Type: 0x" << std::hex << segments[i].type() << std::endl);
    DEBUGMSG("  Flags: 0x" << std::hex << segments[i].flags() << std::endl);
  }

  return true;
}

static inline ssize_t fileSize(int fd) {
  struct stat buf;
  assert(fd >= 0 && "Invalid file descriptor");
  if(fstat(fd, &buf) == -1) return -1;
  else return buf.st_size;
}

ret_t Binary::initialize() {
  bool foundCodeSeg = false;
  ret_t retcode = ret_t::Success;

  if((fd = open(filename, O_RDONLY)) == -1 ||
     (size = fileSize(fd)) == -1 ||
     !(data = mmap(nullptr, size, PROT_READ, MAP_SHARED, fd, 0))) {
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
    INFO("binary is stripped - no symbol table" << std::endl);

  // Cache the code section & segment containing the code
  if(getSectionByName(".text", codeSection) != ret_t::Success) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

  for(auto &seg : segments) {
    if(seg.contains(codeSection.address())) {
      // TODO if segments becomes larger we should convert codeSegment to a
      // reference to avoid copying by value
      assert(seg.contains(codeSection.address() + codeSection.size()));
      codeSegment = seg;
      foundCodeSeg = true;
    }
  }

  if(!foundCodeSeg) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

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

const void *Binary::getData(uintptr_t addr, const Segment &segment) const {
  uintptr_t fileAddr;
  off_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    fileAddr = (uintptr_t)data + segment.fileOffset() + offset;
    if(binaryContains(fileAddr)) return (void *)fileAddr;
  }
  return nullptr;
}

const void * Binary::getData(uintptr_t addr) const {
  Segment tmp;
  if(getSegmentByAddress(addr, tmp) != ret_t::Success) return nullptr;
  else return getData(addr, tmp);
}

size_t
Binary::getRemainingMemSize(uintptr_t addr, const Segment &segment) const {
  size_t remaining = 0;
  off_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    assert(offset <= segment.memorySize() && "Invalid segment memory size");
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
  off_t offset;
  if(segment.contains(addr)) {
    offset = addr - segment.address();
    assert(offset <= segment.memorySize() && "Invalid segment memory size");
    if(offset < segment.fileSize()) remaining = segment.fileSize() - offset;
  }
  return remaining;
}

size_t Binary::getRemainingFileSize(uintptr_t addr) const {
  Segment tmp;
  if(getSegmentByAddress(addr, tmp) != ret_t::Success) return 0;
  else return getRemainingFileSize(addr, tmp);
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
      const char *name = elf_strptr(elf, shdrstrndx, shdr.sh_name);
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

