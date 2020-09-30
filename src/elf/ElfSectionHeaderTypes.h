#ifndef HEADER_PARSER_ELF_SH_TYPES_H
#define HEADER_PARSER_ELF_SH_TYPES_H

#include <stdint.h>

struct Elf_Section_Header_Types
{
	uint32_t SHT_NULL; /* Section header table entry unused */
	uint32_t SHT_PROGBITS; /* Program data */
	uint32_t SHT_SYMTAB; /* Symbol table */
	uint32_t SHT_STRTAB; /* String table */
	uint32_t SHT_RELA; /* Relocation entries with addends */
	uint32_t SHT_HASH; /* Symbol hash table */
	uint32_t SHT_DYNAMIC; /* Dynamic linking information */
	uint32_t SHT_NOTE; /* Notes */
	uint32_t SHT_NOBITS; /* Program space with no data (bss) */
	uint32_t SHT_REL; /* Relocation entries, no addends */
	uint32_t SHT_SHLIB; /* Reserved */
	uint32_t SHT_DYNSYM; /* Dynamic linker symbol table */
	uint32_t SHT_INIT_ARRAY; /* Array of constructors */
	uint32_t SHT_FINI_ARRAY; /* Array of destructors */
	uint32_t SHT_PREINIT_ARRAY; /* Array of pre-constructors */
	uint32_t SHT_GROUP; /* Section group */
	uint32_t SHT_SYMTAB_SHNDX; /* Extended section indeces */
	uint32_t SHT_NUM; /* Number of defined types.  */
	uint32_t SHT_LOOS; /* Start OS-specific.  */
	uint32_t SHT_GNU_ATTRIBUTES; /* Object attributes.  */
	uint32_t SHT_GNU_HASH; /* GNU-style hash table.  */
	uint32_t SHT_GNU_LIBLIST; /* Prelink library list */
	uint32_t SHT_CHECKSUM; /* Checksum for DSO content.  */
	uint32_t SHT_LOSUNW; /* Sun-specific low bound.  */
	uint32_t SHT_SUNW_move;
	uint32_t SHT_SUNW_COMDAT;
	uint32_t SHT_SUNW_syminfo;
	uint32_t SHT_GNU_verdef; /* Version definition section.  */
	uint32_t SHT_GNU_verneed; /* Version needs section.  */
	uint32_t SHT_GNU_versym; /* Version symbol table.  */
	uint32_t SHT_HISUNW; /* Sun-specific high bound.  */
	uint32_t SHT_HIOS; /* End OS-specific type */
	uint32_t SHT_LOPROC; /* Start of processor-specific */
	uint32_t SHT_HIPROC; /* End of processor-specific */
	uint32_t SHT_LOUSER; /* Start of application-specific */
	uint32_t SHT_HIUSER; /* End of application-specific */
};

const struct Elf_Section_Header_Types ElfSectionHeaderTypes = {
	.SHT_NULL = 0,     /* Section header table entry unused */
	.SHT_PROGBITS = 1,     /* Program data */
	.SHT_SYMTAB = 2,     /* Symbol table */
	.SHT_STRTAB = 3,     /* String table */
	.SHT_RELA = 4,    /* Relocation entries with addends */
	.SHT_HASH = 5,     /* Symbol hash table */
	.SHT_DYNAMIC = 6,     /* Dynamic linking information */
	.SHT_NOTE = 7,     /* Notes */
	.SHT_NOBITS = 8,     /* Program space with no data (bss) */
	.SHT_REL = 9,     /* Relocation entries, no addends */
	.SHT_SHLIB = 10,        /* Reserved */
	.SHT_DYNSYM = 11,        /* Dynamic linker symbol table */
	.SHT_INIT_ARRAY = 14,        /* Array of constructors */
	.SHT_FINI_ARRAY = 15,        /* Array of destructors */
	.SHT_PREINIT_ARRAY = 16,        /* Array of pre-constructors */
	.SHT_GROUP = 17,        /* Section group */
	.SHT_SYMTAB_SHNDX = 18,        /* Extended section indeces */
	.SHT_NUM = 19,        /* Number of defined types.  */
	.SHT_LOOS = 0x60000000,    /* Start OS-specific.  */
	.SHT_GNU_ATTRIBUTES = 0x6ffffff5,   /* Object attributes.  */
	.SHT_GNU_HASH = 0x6ffffff6,    /* GNU-style hash table.  */
	.SHT_GNU_LIBLIST = 0x6ffffff7,    /* Prelink library list */
	.SHT_CHECKSUM = 0x6ffffff8,    /* Checksum for DSO content.  */
	.SHT_LOSUNW = 0x6ffffffa,    /* Sun-specific low bound.  */
	.SHT_SUNW_move = 0x6ffffffa,
	.SHT_SUNW_COMDAT = 0x6ffffffb,
	.SHT_SUNW_syminfo = 0x6ffffffc,
	.SHT_GNU_verdef = 0x6ffffffd,    /* Version definition section.  */
	.SHT_GNU_verneed = 0x6ffffffe,    /* Version needs section.  */
	.SHT_GNU_versym = 0x6fffffff,    /* Version symbol table.  */
	.SHT_HISUNW = 0x6fffffff,    /* Sun-specific high bound.  */
	.SHT_HIOS = 0x6fffffff,    /* End OS-specific type */
	.SHT_LOPROC = 0x70000000,   /* Start of processor-specific */
	.SHT_HIPROC = 0x7fffffff,    /* End of processor-specific */
	.SHT_LOUSER = 0x80000000,    /* Start of application-specific */
	.SHT_HIUSER = 0x8fffffff,    /* End of application-specific */
};
#endif