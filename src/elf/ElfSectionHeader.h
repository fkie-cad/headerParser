#ifndef HEADER_PARSER_ELF_SECTION_HEADER_H
#define HEADER_PARSER_ELF_SECTION_HEADER_H

#include <stdint.h>

typedef struct Elf32SectionHeader {
    uint32_t sh_name;
    uint32_t sh_type;
    uint32_t sh_flags;
    uint32_t sh_addr;
    uint32_t sh_offset;
    uint32_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint32_t sh_addralign;
    uint32_t sh_entsize;
} Elf32SectionHeader;

typedef struct Elf64SectionHeader {
    // index into the section header string table section, giving the location of a null-terminated string.
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    // The virtual address where this section starts in memory.
    // It's set to 0 if the section won't reside in memory.
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    // Some sections hold a table of fixed-size entries, such as a symbol table.
    // For such a section, this member gives the size in bytes of each entry.
    // The member contains 0 if the section does not hold a table of fixed-size entries.
    uint64_t sh_entsize;
} Elf64SectionHeader;

#endif
