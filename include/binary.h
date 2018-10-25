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
    /**
     * Zero-initialize all fields; users must call initialize() to set up the
     * section.
     */
    Section() : name(""), elf(nullptr), header({0}), section(nullptr) {}

    const std::string &getName() const { return name; }
    uintptr_t address() const { return header.sh_addr; }
    uintptr_t fileOffset() const { return header.sh_offset; }
    uintptr_t size() const { return header.sh_size; }
    bool contains(uintptr_t addr) const {
      return header.sh_addr <= addr &
             addr < (header.sh_addr + header.sh_size);
    }

    /**
     * Initialize the object with an ELF object, name, header and section.
     * @param elf pointer to Elf object
     * @param name the section name
     * @param header the section header from libelf
     * @param section the section descriptor from libelf
     * @return a return code describing the outcome
     */
    virtual ret_t initialize(Elf *elf,
                             const char *name,
                             GElf_Shdr &header,
                             Elf_Scn *section);

  protected:
    std::string name;
    Elf *elf;
    GElf_Shdr header;
    Elf_Scn *section;
  };

  /**
   * The symbol table section.
   */
  class SymbolTable : public Section {
  public:
    /**
     * Identical to Section::initialize() except additionally grabs the actual
     * section contents for symbol lookups.
     * @param elf pointer to Elf object
     * @param name the section name
     * @param header the section header from libelf
     * @param section the section descriptor from libelf
     * @return a return code describing the outcome
     */
    ret_t initialize(Elf *elf,
                     const char *name,
                     GElf_Shdr &header,
                     Elf_Scn *section) override;

    /**
     * Get the virtual address of a symbol.
     * @param symbol the symbol
     * @return the symbol's virtual address
     */
    uintptr_t getSymbolAddress(const std::string &sym) const;

  private:
    Elf_Data *data;
  };

  /**
   * A program segment in the binary which contains 0 or more sections.  Some
   * segments may be loaded at startup which comprises the application's image
   * in memory.
   *
   * Note that there is a difference between a segment's on-disk size and
   * in-memory size; the ELF standard allows on-disk sizes to be less than or
   * equal to in-memory sizes to allow efficient on-disk representations for
   * zeroed regions of memory to accomodate .bss or padding regions.
   */
  class Segment {
  public:
    /**
     * Segment type.  Corresponds to the p_type field in the program header.
     */
    enum Type {
      Null = PT_NULL,              /* unused */
      Load = PT_LOAD,              /* loadable segment */
      Dynamic = PT_DYNAMIC,        /* dynamic linking information */
      Interpreter = PT_INTERP,     /* path to interpreter */
      Note = PT_NOTE,              /* implementation-specific information */
      ProgramHeaderTable = PT_PHDR /* program header table */
    };

    /**
     * Segment permission flags.  Corresponds to the p_flags field in the
     * program header.
     */
    enum Flags {
      Executable = PF_X,
      Writable = PF_W,
      Readable = PF_R
    };

    Segment() : header({0}) {}
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
    bool contains(uintptr_t addr) const {
      return header.p_vaddr <= addr &&
             addr < (header.p_vaddr + header.p_memsz);
    }

  private:
    GElf_Phdr header;
  };

  /**
   * Construct a binary object.  Does not initialize the object for reading,
   * users should call initialize().
   * @param filename name of binary
   */
  Binary() = delete;
  Binary(const char *filename) : filename(filename), fd(-1), data(nullptr),
                                 size(0), elf(nullptr), shdrstrndx(UINT64_MAX)
                                 {}
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
   * Clean up a binary object, including closing all open file descriptors and
   * objects instantiated during initialization.
   */
  void cleanup();

  /**
   * Field getters - return what you ask for.
   */
  const Section &getCodeSection() const { return codeSection; }
  const Segment &getCodeSegment() const { return codeSegment; }

  /**
   * Get pointer to the binary's data contained inside a particular segment.
   * @param addr a virtual memory address contained in segment
   * @param segment the segment containing addr
   * @return pointer to the file's contents or nullptr if addr is out-of-bounds
   *         of the segment
   */
  const void *getData(uintptr_t addr, const Segment &segment) const;

  /**
   * Get a pointer to the binary's data at a particular virtual address.
   * @param addr a virtual memory address
   * @return pointer to the file's contents or nullptr if addr is out-of-bounds
   */
  const void *getData(uintptr_t addr) const;

  /**
   * Get the remaining size, in bytes, from a virtual address to the end of the
   * the segment argument.
   *
   * @param addr a virtual memory address contained in segment
   * @param segment the segment containing addr
   * @return bytes remaining in the segment
   */
  size_t getRemainingMemSize(uintptr_t addr, const Segment &segment) const;

  /**
   * Get the remaining size, in bytes, from a virtual address to the end of its
   * containing segment.
   *
   * @param addr a virtual memory address contained in segment
   * @return bytes remaining in the segment
   */
  size_t getRemainingMemSize(uintptr_t addr) const;

  /**
   * Get the remaining size, in bytes, from a virtual address to the end of the
   * on-disk representation of the segment argument.  Note that this may *not*
   * necessarily be the remaining size of the segment's in-memory
   * representation (see Segment description above).
   *
   * @param addr a virtual memory address contained in segment
   * @param segment the segment containing addr
   * @return bytes remaining in the on-disk representation of the segment
   */
  size_t getRemainingFileSize(uintptr_t addr, const Segment &segment) const;

  /**
   * Get the remaining size, in bytes, from a virtual address to the end of the
   * on-disk representation of its containing segment. Note that this may *not*
   * necessarily be the remaining size of the segment's in-memory
   * representation (see Segment description above).
   *
   * @param addr a virtual memory address contained in segment
   * @return bytes remaining in the on-disk representation of the segment
   */
  size_t getRemainingFileSize(uintptr_t addr) const;

  /**
   * Return the symbol's virtual address from the symbol table.
   * @param sym the symbol
   * @return the symbol's virtual address or 0 if not found
   */
  uintptr_t getSymbolAddress(std::string &sym)
  { return symtab.getSymbolAddress(sym); }

private:
  /* Raw file access */
  const char *filename;
  int fd;
  void *data;
  size_t size;

  /* ELF metadata & relevant sections */
  Elf *elf;
  size_t shdrstrndx;
  std::vector<Segment> segments;

  /* Special segments/sections we care about */
  Section codeSection;
  Segment codeSegment;
  SymbolTable symtab;

  /**
   * Return whether an address is within the mapped file's boundaries.  Note:
   * does *not* apply to virtual addresses of the binary, but rather addresses
   * inside the mapped file in our virtual memory.  Used for error checking.
   * @return true if contained within or false otherwise
   */
  bool binaryContains(uintptr_t addr) const
  { return (uintptr_t)data <= addr && addr < ((uintptr_t)data + size); }

  /**
   * Search for a section by name and populate the section object argument.
   * @param name name of the section to find
   * @param section a Section object to be populated
   * @return a return code describing the outcome
   */
  ret_t getSectionByName(const char *name, Section &section);

  /**
   * Search for a section by type and populate the section object argument with
   * the first one found.
   * @param type the ELF section type
   * @param section a Section object to be populated
   * @return a return code describing the outcome
   */
  ret_t getSectionByType(uint32_t type, Section &section);

  /**
   * Search for the segment containing a virtual address.
   * @param addr the virtual memory address
   * @param segment output argument into which the segment will be written
   * @return a return code describing the outcome
   */
  ret_t getSegmentByAddress(uintptr_t addr, Segment &segment) const;
};

}

#endif /* _BINARY_H */

