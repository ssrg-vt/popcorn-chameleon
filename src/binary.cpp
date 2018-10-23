#include <cstring>
#include <fcntl.h>
#include <unistd.h>

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
  if(!(this->data = elf_getdata(section, nullptr))) return ret_t::ElfReadError;

  DEBUGMSG("Section '" << name << "':" << std::endl);
  DEBUGMSG("  Address: 0x" << std::hex << header.sh_addr << std::endl);
  DEBUGMSG("  File offset: 0x" << header.sh_offset << std::endl);
  DEBUGMSG("  Size: " << std::dec << header.sh_size << " bytes" << std::endl);

  return ret_t::Success;
}

void *Binary::Section::getData(uintptr_t addr) {
  uintptr_t start = address();
  if(start <= addr && addr < (start + size()))
    return (char *)data->d_buf + addr - start;
  else return nullptr;
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

ret_t Binary::initialize() {
  ret_t retcode = ret_t::Success;

  if((fd = open(filename, O_RDONLY)) == -1) {
    retcode = ret_t::OpenFailed;
    goto error;
  }

  DEBUGMSG("opened '" << filename << "' for reading" << std::endl);

  if(!(elf = elf_begin(fd, ELF_C_READ, nullptr))) {
    retcode = ret_t::ElfReadError;
    goto error;
  }

  if(!checkCompatibility(elf)) {
    retcode = ret_t::InvalidElf;
    goto error;
  }

  if(elf_getshdrstrndx(elf, &shdrstrndx) ||
     !initializeSegments(elf, segments) ||
     getSectionByName(".text", code) != ret_t::Success) {
    retcode = ret_t::ElfReadError;
    goto error;
  }

  if(getSectionByType(SHT_SYMTAB, symtab) != ret_t::Success)
    INFO("binary is stripped - no symbol table" << std::endl);

  goto finish;
error:
  cleanup();
finish:
  return retcode;
}

void Binary::cleanup() {
  if(elf) elf_end(elf);
  elf = nullptr;
  if(fd != -1) close(fd);
  fd = -1;
  DEBUG(
    filename = nullptr;
    shdrstrndx = UINT64_MAX;
  )
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

