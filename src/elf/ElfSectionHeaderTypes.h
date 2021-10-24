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



// Dynamic section entry.
typedef struct
{
    int32_t d_tag;			/* Dynamic entry type */
    union
    {
        uint32_t d_val;			/* Integer value */
        uint32_t d_ptr;			/* Address value */
    } d_un;
} Elf32_Dyn;

typedef struct
{
    int64_t d_tag;			/* Dynamic entry type */
    union
    {
        uint64_t d_val;		/* Integer value */
        uint64_t d_ptr;			/* Address value */
    } d_un;
} Elf64_Dyn;

/* Legal values for d_tag (dynamic entry type).  */

#define DT_NULL		0		/* Marks end of dynamic section */
#define DT_NEEDED	1		/* Name of needed library */
#define DT_PLTRELSZ	2		/* Size in bytes of PLT relocs */
#define DT_PLTGOT	3		/* Processor defined value */
#define DT_HASH		4		/* Address of symbol hash table */
#define DT_STRTAB	5		/* Address of string table */
#define DT_SYMTAB	6		/* Address of symbol table */
#define DT_RELA		7		/* Address of Rela relocs */
#define DT_RELASZ	8		/* Total size of Rela relocs */
#define DT_RELAENT	9		/* Size of one Rela reloc */
#define DT_STRSZ	10		/* Size of string table */
#define DT_SYMENT	11		/* Size of one symbol table entry */
#define DT_INIT		12		/* Address of init function */
#define DT_FINI		13		/* Address of termination function */
#define DT_SONAME	14		/* Name of shared object */
#define DT_RPATH	15		/* Library search path (deprecated) */
#define DT_SYMBOLIC	16		/* Start symbol search here */
#define DT_REL		17		/* Address of Rel relocs */
#define DT_RELSZ	18		/* Total size of Rel relocs */
#define DT_RELENT	19		/* Size of one Rel reloc */
#define DT_PLTREL	20		/* Type of reloc in PLT */
#define DT_DEBUG	21		/* For debugging; unspecified */
#define DT_TEXTREL	22		/* Reloc might modify .text */
#define DT_JMPREL	23		/* Address of PLT relocs */
#define	DT_BIND_NOW	24		/* Process relocations of object */
#define	DT_INIT_ARRAY	25		/* Array with addresses of init fct */
#define	DT_FINI_ARRAY	26		/* Array with addresses of fini fct */
#define	DT_INIT_ARRAYSZ	27		/* Size in bytes of DT_INIT_ARRAY */
#define	DT_FINI_ARRAYSZ	28		/* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH	29		/* Library search path */
#define DT_FLAGS	30		/* Flags for the object being loaded */
#define DT_ENCODING	32		/* Start of encoded range */
#define DT_PREINIT_ARRAY 32		/* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ 33		/* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX	34		/* Address of SYMTAB_SHNDX section */
#define	DT_NUM		35		/* Number used */
#define DT_LOOS		0x6000000d	/* Start of OS-specific */
#define DT_HIOS		0x6ffff000	/* End of OS-specific */
#define DT_LOPROC	0x70000000	/* Start of processor-specific */
#define DT_HIPROC	0x7fffffff	/* End of processor-specific */
#define	DT_PROCNUM	DT_MIPS_NUM	/* Most used by any processor */



typedef struct {
    // An index into the object file's symbol string table, which holds the character representations of the symbol names.
    // If the value is nonzero, the value represents a string table index that gives the symbol name. Otherwise, the symbol table entry has no name.
    uint32_t st_name;
    // The value of the associated symbol.
    // The value can be an absolute value or an address, depending on the context. See Symbol Values.
    uint32_t st_value;
    // Many symbols have associated sizes.
    // For example, a data object's size is the number of bytes that are contained in the object.
    // This member holds the value zero if the symbol has no size or an unknown size.
    uint32_t st_size;
    // The symbol's type and binding attributes.
    unsigned char st_info;
    // Symbol visibility
    unsigned char st_other;
    // Section index
    uint16_t st_shndx;
} Elf32_Sym;
typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;
typedef struct Elf_Sym_Offsets {
    uint8_t	st_name;
    uint8_t	st_info;
    uint8_t	st_other;
    uint8_t	st_shndx;
    uint8_t	st_value;
    uint8_t	st_size;
} Elf_Sym_Offsets;
const Elf_Sym_Offsets Elf32SymOffsets = {
    .st_name = 0,
    .st_value = 4,
    .st_size = 8,
    .st_info = 12,
    .st_other = 13,
    .st_shndx = 14,
};
const Elf_Sym_Offsets Elf64SymOffsets = {
    .st_name = 0,
    .st_info = 4,
    .st_other = 5,
    .st_shndx = 6,
    .st_value = 8,
    .st_size = 16,
};
// st_info
#define ELF32_ST_BIND(info)          ((info) >> 4)
#define ELF32_ST_TYPE(info)          ((info) & 0xf)
#define ELF32_ST_INFO(bind, type)    (((bind)<<4)+((type)&0xf))

#define ELF64_ST_BIND(info)          ((info) >> 4)
#define ELF64_ST_TYPE(info)          ((info) & 0xf)
#define ELF64_ST_INFO(bind, type)    (((bind)<<4)+((type)&0xf))

// st_other
#define ELF32_ST_VISIBILITY(o)       ((o)&0x3)
#define ELF64_ST_VISIBILITY(o)       ((o)&0x3)

#define ELF_STV_DEFAULT   (0x00) // default visibility rules
#define ELF_STV_INTERNAL  (0x01) // Processor specific hidden class
#define ELF_STV_HIDDEN    (0x02) // symbol is not available for reference in other modules
#define ELF_STV_PROTECTED (0x03) // protected symbol.

// Local symbol. These symbols are not visible outside the object file containing their definition. Local symbols of the same name can exist in multiple files without interfering with each other.
#define ELF_STB_LOCAL (0)
// Global symbols. These symbols are visible to all object files being combined. One file's definition of a global symbol will satisfy another file's undefined reference to the same global symbol.
#define ELF_STB_GLOBAL (1)
// Weak symbols. These symbols resemble global symbols, but their definitions have lower precedence.
#define ELF_STB_WEAK (2)
// STB_LOOS - STB_HIOS
// Values in this inclusive range are reserved for operating system-specific semantics.
#define ELF_STB_LOOS (10)
#define ELF_STB_HIOS (12)
//STB_LOPROC - STB_HIPROC
//Values in this inclusive range are reserved for processor-specific semantics.
#define ELF_STB_LOPROC (13)
#define ELF_STB_HIPROC (15)

// Global and weak symbols differ in two major ways:
// When the link-editor combines several relocatable object files, it does not allow multiple definitions of STB_GLOBAL symbols with the same name. On the other hand, if a defined global symbol exists, the appearance of a weak symbol with the same name will not cause an error. The link-editor honors the global definition and ignores the weak ones.
// Similarly, if a common symbol exists, the appearance of a weak symbol with the same name does not cause an error. The link-editor uses the common definition and ignores the weak one. A common symbol has the st_shndx field holding SHN_COMMON. See "Symbol Resolution".
// When the link-editor searches archive libraries it extracts archive members that contain definitions of undefined or tentative global symbols. The member's definition can be either a global or a weak symbol.
// The link-editor, by default, does not extract archive members to resolve undefined weak symbols. Unresolved weak symbols have a zero value. The use of -z weakextract overrides this default behavior. It enables weak references to cause the extraction of archive members.


// The symbol type is not specified.
#define ELF_STT_NOTYPE (0x00)
// This symbol is associated with a data object, such as a variable, an array, and so forth.
#define ELF_STT_OBJECT (0x01)
// This symbol is associated with a function or other executable code.
#define ELF_STT_FUNC (0x02)
// This symbol is associated with a section. Symbol table entries of this type exist primarily for relocation and normally have STB_LOCAL binding.
#define ELF_STT_SECTION (0x03)
// Conventionally, the symbol's name gives the name of the source file associated with the object file. A file symbol has STB_LOCAL binding and its section index is SHN_ABS. This symbol, if present, precedes the other STB_LOCAL symbols for the file. Symbol index 1 of the SHT_SYMTAB is an STT_FILE symbol representing the file itself. Conventionally, this symbols is followed by the files STT_SECTION symbols, and any global symbols that have been reduced to locals.
#define ELF_STT_FILE (0x04)
// This symbol labels an uninitialized common block. It is treated exactly the same as STT_OBJECT.
#define ELF_STT_COMMON (0x05)
// STT_LOOS - STT_HIOS
// Values in this inclusive range are reserved for operating system-specific semantics.
#define ELF_STT_LOOS (0x0a)
#define ELF_STT_HIOS (0xc)
// STT_LOPROC - STT_HIPROC
// Values in this inclusive range are reserved for processor-specific semantics.
#define ELF_STT_LOPROC (0x0d)
//#define ELF_STT_SPARC_REGISTER (0x0d)
#define ELF_STT_HIPROC (0x0f)


#endif
