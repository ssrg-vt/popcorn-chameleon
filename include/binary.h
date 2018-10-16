/**
 * class Binary
 *
 * Implements reading information from a binary file on disk.
 *
 * Author: Rob Lyerly <rlyerly@vt.edu>
 * Date: 10/12/2018
 */

#ifndef _BINARY_H
#define _BINARY_H

#include <string>
#include <elf.h>
#include <gelf.h>
#include <libelf.h>
#include <vector>
#include "types.h"

namespace chameleon {

class Binary {
public:
  /**
   * A section in the binary.
   */
  class Section {
  public:
    std::string name;

    uintptr_t address() const { return header.sh_addr; }
    uintptr_t fileOffset() const { return header.sh_offset; }
    uintptr_t size() const { return header.sh_size; }

    /**
     * Initialize the object with a given name, header and section.  Also
     * grabs the actual section contents.
     * @param name the section name
     * @param header the section header from libelf
     * @param section the section descriptor from libelf
     * @return a return code describing the outcome
     */
    ret_t initialize(const char *name, GElf_Shdr &header, Elf_Scn *section);

    /**
     * Retrieve a pointer to the section data for a given address.
     * @param addr the address in the section
     * @return pointer to data at the address or null for invalid addresses
     */
    void *getData(uintptr_t addr);

  private:
    /* The actual section data.  Hidden to enforce out-of-bounds checks */
    GElf_Shdr header;
    Elf_Scn *section;
    Elf_Data *data;
  };

  /**
   * A program segment loaded by the OS at application startup.
   */
  class Segment {
  public:
    /**
     * Segment type.  Corresponds to the p_type field in the program header.
     */
    enum Type {
      Null = 0,          /* unused */
      Load,              /* loadable segment */
      Dynamic,           /* dynamic linking information */
      Interpreter,       /* path to interpreter */
      Note,              /* auxiliary implementation-specific information */
      ProgramHeaderTable /* program header table */
    };

    /**
     * Segment permission flags.  Corresponds to the p_flags field in the
     * program header.
     */
    enum Flags {
      Executable = 1,
      Writable = 1 << 1,
      Readable = 1 << 2
    };

    Segment(GElf_Phdr &header) : header(header) {}

    uintptr_t address() const { return header.p_vaddr; }
    uintptr_t fileOffset() const { return header.p_offset; }
    uintptr_t fileSize() const { return header.p_filesz; }
    uintptr_t memorySize() const { return header.p_memsz; }
    Type type() const { return (Type)header.p_type; }
    uint64_t flags() const { return header.p_flags; }
    bool isExecutable() const { return header.p_flags & Flags::Executable; }
    bool isWritable() const { return header.p_flags & Flags::Writable; }
    bool isReadable() const { return header.p_flags & Flags::Readable; }

  private:
    GElf_Phdr header;
  };

  /**
   * Construct a binary object.  Does not initialize the object for reading,
   * users should call initialize().
   * @param filename name of binary
   */
  Binary() = delete;
  Binary(const char *filename) : filename(filename), fd(-1), elf(nullptr),
                                 shdrstrndx(UINT64_MAX) {}
  ~Binary() { cleanup(); }

  /**
   * libelf is a diva and requires checking versions before we can use it.
   * @return a return code describing the outcome
   */
  static ret_t initLibELF();

  /**
   * Initialize a binary for access.
   * @return a return code describing the outcome
   */
  ret_t initialize();

  /**
   * Clean up a binary object, including closing all open file descriptors.
   */
  void cleanup();

  /**
   * Field getters - return what you ask for.
   */
  const Section &getCodeSection() const { return code; }

private:
  const char *filename;
  int fd;

  /* ELF metadata & relevant sections */
  Elf *elf;
  size_t shdrstrndx;
  Section code;
  std::vector<Segment> segments;

  /**
   * Search for a section by name and populate the section object argument.
   * @param name name of the section to find
   * @param section a Section object to be populated
   * @return a return code describing the outcome
   */
  ret_t getSectionByName(const char *name, Section &section);
};

}

#endif /* _BINARY_H */

