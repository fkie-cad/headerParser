#ifndef HEADER_PARSER_ELF_HEADER_OFFSETS_H
#define HEADER_PARSER_ELF_HEADER_OFFSETS_H

#include <stdint.h>

typedef struct ElfFileHeaderOffsets
{
	uint8_t EI_MAG0; // magic bytes
	uint8_t EI_MAG1;
	uint8_t EI_MAG2;
	uint8_t EI_MAG3;
	uint8_t EI_CLASS; // bitness
	uint8_t EI_DATA; // endian
	uint8_t EI_VERSION; // elf version
	uint8_t EI_OSABI; // target os
	uint8_t EI_ABIVERSION;
	uint8_t EI_PAD;
	uint8_t e_type;
	uint8_t e_machine; // instruction set architecture
	uint8_t e_version;
	uint8_t e_entry; // address where execution starts
	uint8_t e_phoff; // start of the program header table
	uint8_t e_shoff; // start of the section header table
	uint8_t e_flags;
	uint8_t e_ehsize; // size of this header
	uint8_t e_phentsize; // size of a program header table entry
	uint8_t e_phnum; // number of entries in the program header table
	uint8_t e_shentsize; // size of a section header table entry
	uint8_t e_shnum; // number of entries in the section header table
	uint8_t e_shstrndx; // index of the section header table entry that contains the section names
} ElfFileHeaderOffsets;

const ElfFileHeaderOffsets Elf32FileHeaderOffsets = {
	.EI_MAG0 = 0, // uint8_t
	.EI_MAG1 = 1, // uint8_t
	.EI_MAG2 = 2, // uint8_t
	.EI_MAG3 = 3, // uint8_t
	.EI_CLASS = 4, // uint8_t
	.EI_DATA = 5, // uint8_t
	.EI_VERSION = 6, // uint8_t
	.EI_OSABI = 7, // uint8_t
	.EI_ABIVERSION = 8, // uint8_t
	.EI_PAD = 9, // uint8_t[7]
	.e_type = 16, // uint16_t
	.e_machine = 18, // uint16_t
	.e_version = 20, // uint32_t
	.e_entry = 24, // uint32_t
	.e_phoff = 28, // uint32_t
	.e_shoff = 32, // uint32_t
	.e_flags = 36, // uint32_t
	.e_ehsize = 40, // uint16_t
	.e_phentsize = 42, // uint16_t
	.e_phnum = 44, // uint16_t
	.e_shentsize = 46, // uint16_t
	.e_shnum = 48, // uint16_t
	.e_shstrndx = 50 // uint16_t
};

const ElfFileHeaderOffsets Elf64FileHeaderOffsets = {
	.EI_MAG0 = 0, // uint8_t
	.EI_MAG1 = 1, // uint8_t
	.EI_MAG2 = 2, // uint8_t
	.EI_MAG3 = 3, // uint8_t
	.EI_CLASS = 4, // uint8_t
	.EI_DATA = 5, // uint8_t
	.EI_VERSION = 6, // uint8_t
	.EI_OSABI = 7, // uint8_t
	.EI_ABIVERSION = 8, // uint8_t
	.EI_PAD = 9, // uint8_t[7]
	.e_type = 16, // uint16_t
	.e_machine = 18, // uint16_t
	.e_version = 20, // uint32_t
	.e_entry = 24, // uint64_t
	.e_phoff = 32, // uint64_t
	.e_shoff = 40, // uint64_t
	.e_flags = 48, // uint32_t
	.e_ehsize = 52, // uint16_t
	.e_phentsize = 54, // uint16_t
	.e_phnum = 56, // uint16_t
	.e_shentsize = 58, // uint16_t
	.e_shnum = 60, // uint16_t
	.e_shstrndx = 62 // uint16_t
};

typedef struct ElfProgramHeaderOffsets {
	uint8_t p_type;
	uint8_t p_flags;
	uint8_t p_offset;
	uint8_t p_vaddr;
	uint8_t p_paddr;
	uint8_t p_filesz;
	uint8_t p_memsz;
	uint8_t p_align;
} ElfProgramHeaderOffsets;

// different ordering to x64
const ElfProgramHeaderOffsets Elf32ProgramHeaderOffsets = {
	.p_type = 0,
	.p_offset = 4,
	.p_vaddr = 8,
	.p_paddr = 12,
	.p_filesz = 16,
	.p_memsz = 20,
	.p_flags = 24,
	.p_align = 28
};

const ElfProgramHeaderOffsets Elf64ProgramHeaderOffsets = {
	.p_type = 0,
	.p_flags = 4,
	.p_offset = 8,
	.p_vaddr = 16,
	.p_paddr = 24,
	.p_filesz = 32,
	.p_memsz = 40,
	.p_align = 48
};

typedef struct ElfSectionHeaderOffsets {
	uint8_t	sh_name;
	uint8_t	sh_type;
	uint8_t	sh_flags;
	uint8_t	sh_addr;
	uint8_t	sh_offset;
	uint8_t	sh_size;
	uint8_t	sh_link;
	uint8_t	sh_info;
	uint8_t	sh_addralign;
	uint8_t	sh_entsize;
} ElfSectionHeaderOffsets;

const ElfSectionHeaderOffsets Elf32SectionHeaderOffsets = {
	.sh_name = 0,
	.sh_type = 4,
	.sh_flags = 8,
	.sh_addr = 12,
	.sh_offset = 16,
	.sh_size = 20,
	.sh_link = 24,
	.sh_info = 28,
	.sh_addralign = 32,
	.sh_entsize = 36
};

const ElfSectionHeaderOffsets Elf64SectionHeaderOffsets = {
	.sh_name = 0,
	.sh_type = 4,
	.sh_flags = 8,
	.sh_addr = 16,
	.sh_offset = 24,
	.sh_size = 32,
	.sh_link = 40,
	.sh_info = 44,
	.sh_addralign = 48,
	.sh_entsize = 56
};

#endif
