#ifndef HEADER_PARSER_ELF_PROGRAM_HEADER_H
#define HEADER_PARSER_ELF_PROGRAM_HEADER_H

#include <stdint.h>

typedef struct Elf32ProgramHeader {
	uint32_t p_type;
	uint32_t p_offset;
	uint32_t p_vaddr;
	uint32_t p_paddr;
	uint32_t p_filesz;
	uint32_t p_memsz;
	uint32_t p_flags;
	uint32_t p_align;
} Elf32ProgramHeader;

typedef struct Elf64ProgramHeader {
	uint32_t p_type;
	// The lower 3 bits are RWX like normal UNIX filesystem permissions
	// code segements should be marked as read and execute only (1+4=5), data sections as read and write ( 2+4=6)
	uint32_t p_flags;
	// This member gives the offset from the beginning of the file at which the first byte of the segment resides.
	// Is where the data you want to map into memory starts in the file.
	// But again, remember, only for PT_LOAD segments does data actually get read from the file and mapped into memory
	uint64_t p_offset;
	// Virtual address at which the first byte of the segment resides in memory, i.e. will be mapped at.
	uint64_t p_vaddr;
	// On systems for which physical addressing is relevant, this member is reserved for the segment's physical address.
	// Because System V ignores physical addressing for application programs,
	// this member has unspecified contents for executable files and shared objects.
	uint64_t p_paddr;
	// This member gives the number of bytes in the file image of the segment; it may be zero.
	uint64_t p_filesz;
	// This member gives the number of bytes in the memory image of the segment; it may be zero.
	// If p_memsz is > p_filesz, the extra space is used for the .bss area.
	uint64_t p_memsz;
	uint64_t p_align;
} Elf64ProgramHeader;

#endif
