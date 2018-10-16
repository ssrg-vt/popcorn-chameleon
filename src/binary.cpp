#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include "binary.h"
#include "log.h"

using namespace chameleon;

ret_t Binary::initLibELF() {
  if(elf_version(EV_CURRENT) == EV_NONE) return ret_t::ElfFailed;
  else return ret_t::Success;
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
    DEBUGMSG("  Type: " << segments[i].type() << std::endl);
    DEBUGMSG("  Flags: " << segments[i].flags() << std::endl);
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

  // TODO check that it's an ELF file and executable?

  if(!(elf = elf_begin(fd, ELF_C_READ, nullptr)) ||
     elf_getshdrstrndx(elf, &shdrstrndx) ||
     getSectionByName(".text", code) != ret_t::Success ||
     !initializeSegments(elf, segments)) {
    retcode = ret_t::ElfReadError;
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
      return section.initialize(name, shdr, scn);
  }

  return ret_t::NoSuchSection;
}

ret_t Binary::Section::initialize(const char *name,
                                  GElf_Shdr &header,
                                  Elf_Scn *section) {
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

