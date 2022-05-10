#ifndef HEADER_PARSER_MACHO_FILE_HEADER_H
#define HEADER_PARSER_MACHO_FILE_HEADER_H

#include <stdint.h>

#define MACH_O_SEG_NAME_LN (0x10)

const unsigned char MAGIC_MACH_O_BYTES_32[4] = { 0xFE, 0xED, 0xFA, 0xCE };
const unsigned char MAGIC_MACH_O_BYTES_64[4] = { 0xFE, 0xED, 0xFA, 0xCF };
const unsigned char MAGIC_MACH_O_BYTES_32_RV[4] = { 0xCE, 0xFA, 0xED, 0xFE };
const unsigned char MAGIC_MACH_O_BYTES_64_RV[4] = { 0xCF, 0xFA, 0xED, 0xFE };

#define MAGIC_MACH_O_BYTES_LN (0x4)

#define SIZE_OF_MACHO_O_HEADER (0x1C)
#define SIZE_OF_MACHO_O_HEADER_64 (0x20)

#define SIZE_OF_MACHO_O_BUILD_VERSION_COMMAND_32 0x1C
#define SIZE_OF_MACHO_O_BUILD_VERSION_COMMAND_64 0x20
#define SIZE_OF_MACHO_O_LOAD_COMMAND (0x8)
#define SIZE_OF_MACHO_O_UUID_COMMAND (0x18)
#define SIZE_OF_MACHO_O_DY_SYMTAB_COMMAND (0x50)
#define SIZE_OF_MACHO_O_DYLIB_COMMAND (0x18)
#define SIZE_OF_MACHO_O_DYLD_INFO_COMMAND (0x30)
#define SIZE_OF_MACHO_O_LINKED_IT_DATA_COMMAND (0x10)
#define SIZE_OF_MACHO_O_MAIN_DYLIB_COMMAND (0x18)
#define SIZE_OF_MACHO_O_PREBOUND_DYLIB_COMMAND (0x14)
#define SIZE_OF_MACHO_O_ROUTINES_COMMAND_32 (0x28)
#define SIZE_OF_MACHO_O_ROUTINES_COMMAND_64 (0x48)
#define SIZE_OF_MACHO_O_SEGMENT_HEADER_32 (0x38)
#define SIZE_OF_MACHO_O_SEGMENT_HEADER_64 (0x48)
#define SIZE_OF_MACHO_O_SECTION_HEADER_32 (0x44)
#define SIZE_OF_MACHO_O_SECTION_HEADER_64 (0x50)
#define SIZE_OF_MACHO_O_SOURCE_VERSION_COMMAND (0x10)
#define SIZE_OF_MACHO_O_SUB_COMMAND (0x0C)
#define SIZE_OF_MACHO_O_SYMTAB_COMMAND (0x18)
#define SIZE_OF_MACHO_O_THREAD_COMMAND (0x10)
#define SIZE_OF_MACHO_O_VERSION_MIN_COMMAND (0x10)


typedef uint32_t cpu_type_t;
typedef uint32_t cpu_subtype_t;
typedef uint32_t vm_prot_t;

struct load_command {
    uint32_t cmd;
    uint32_t cmdsize;
};

/*
 * The mach header appears at the very beginning of the object file; it
 * is the same for both 32-bit and 64-bit architectures.
 */
typedef struct mach_header {
    uint32_t magic;		/* mach magic number identifier */
    cpu_type_t cputype;	/* cpu specifier */
    cpu_subtype_t cpusubtype;	/* machine specifier */
    uint32_t filetype;	/* type of file */
    uint32_t ncmds;		/* number of load commands */
    uint32_t sizeofcmds;	/* the size of all the load commands */
    uint32_t flags;		/* flags */
} MachHeader;

// file types
#define	MH_OBJECT	0x1		/* relocatable object file */
#define	MH_EXECUTE	0x2		/* demand paged executable file */
#define	MH_FVMLIB	0x3		/* fixed VM shared library file */
#define	MH_CORE		0x4		/* core file */
#define	MH_PRELOAD	0x5		/* preloaded executable file */
#define	MH_DYLIB	0x6		/* dynamically bound shared library */
#define	MH_DYLINKER	0x7		/* dynamic link editor */
#define	MH_BUNDLE	0x8		/* dynamically bound bundle file */
#define	MH_DYLIB_STUB	0x9		/* shared library stub for static */
// linking only, no section contents
#define	MH_DSYM		0xa		/* companion file with only debug */
//  sections
#define	MH_KEXT_BUNDLE	0xb		/* x86_64 kexts */

// Constants for the flags field of the mach_header
#define	MH_NOUNDEFS	0x1 /* the object file has no undefined references */
#define	MH_INCRLINK	0x2 /* the object file is the output of an incremental link against a base file and can't be link edited again */
#define MH_DYLDLINK	0x4 /* the object file is input for the dynamic linker and can't be staticly link edited again */
#define MH_BINDATLOAD 0x8 /* the object file's undefined references are bound by the dynamic linker when loaded. */
#define MH_PREBOUND	0x10 /* the file has its dynamic undefined references prebound. */
#define MH_SPLIT_SEGS 0x20 /* the file has its read-only and read-write segments split */
#define MH_LAZY_INIT 0x40 /* the shared library init routine is to be run lazily via catching memory faults to its writeable segments (obsolete) */
#define MH_TWOLEVEL	0x80 /* the image is using two-level name space bindings */
#define MH_FORCE_FLAT 0x100 /* the executable is forcing all images to use flat name space bindings */
#define MH_NOMULTIDEFS 0x200 /* this umbrella guarantees no multiple defintions of symbols in its sub-images so the two-level namespace hints can always be used. */
#define MH_NOFIXPREBINDING 0x400 /* do not have dyld notify the prebinding agent about this executable */
#define MH_PREBINDABLE 0x800 /* the binary is not prebound but can have its prebinding redone. only used when MH_PREBOUND is not set. */
#define MH_ALLMODSBOUND 0x1000 /* indicates that this binary binds to all two-level namespace modules of its dependent libraries. only used when MH_PREBINDABLE and MH_TWOLEVEL are both set. */
#define MH_SUBSECTIONS_VIA_SYMBOLS 0x2000/* safe to divide up the sections into sub-sections via symbols for dead code stripping */
#define MH_CANONICAL 0x4000 /* the binary has been canonicalized via the unprebind operation */
#define MH_WEAK_DEFINES	0x8000 /* the final linked image contains external weak symbols */
#define MH_BINDS_TO_WEAK 0x10000 /* the final linked image uses weak symbols */
#define MH_ALLOW_STACK_EXECUTION 0x20000 /* When this bit is set, all stacks in the task will be given stack execution privilege.  Only used in MH_EXECUTE filetypes. */
#define MH_ROOT_SAFE 0x40000 /* When this bit is set, the binary declares it is safe for use in processes with uid zero */
#define MH_SETUID_SAFE 0x80000 /* When this bit is set, the binary declares it is safe for use in processes when issetugid() is true */
#define MH_NO_REEXPORTED_DYLIBS 0x100000 /* When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported */
#define	MH_PIE 0x200000 /* When this bit is set, the OS will load the main executable at a random address.  Only used in MH_EXECUTE filetypes. */
#define	MH_DEAD_STRIPPABLE_DYLIB 0x400000 /* Only for use on dylibs.  When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib. */
#define MH_HAS_TLV_DESCRIPTORS 0x800000 /* Contains a section of type S_THREAD_LOCAL_VARIABLES */
#define MH_NO_HEAP_EXECUTION 0x1000000	/* When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes. */

#define LC_REQ_DYLD 0x80000000
#define	LC_SEGMENT	0x1	/* segment of this file to be mapped */
#define	LC_SYMTAB	0x2	/* link-edit stab symbol table info */
#define	LC_SYMSEG	0x3	/* link-edit gdb symbol table info (obsolete) */
#define	LC_THREAD	0x4	/* thread */
#define	LC_UNIXTHREAD	0x5	/* unix thread (includes a stack) */
#define	LC_LOADFVMLIB	0x6	/* load a specified fixed VM shared library */
#define	LC_IDFVMLIB	0x7	/* fixed VM shared library identification */
#define	LC_IDENT	0x8	/* object identification info (obsolete) */
#define LC_FVMFILE	0x9	/* fixed VM file inclusion (internal use) */
#define LC_PREPAGE      0xa     /* prepage command (internal use) */
#define	LC_DYSYMTAB	0xb	/* dynamic link-edit symbol table info */
#define	LC_LOAD_DYLIB	0xc	/* load a dynamically linked shared library */
#define	LC_ID_DYLIB	0xd	/* dynamically linked shared lib ident */
#define LC_LOAD_DYLINKER 0xe	/* load a dynamic linker */
#define LC_ID_DYLINKER	0xf	/* dynamic linker identification */
#define	LC_PREBOUND_DYLIB 0x10	/* modules prebound for a dynamically */
/*  linked shared library */
#define	LC_ROUTINES	0x11	/* image routines */
#define	LC_SUB_FRAMEWORK 0x12	/* sub framework */
#define	LC_SUB_UMBRELLA 0x13	/* sub umbrella */
#define	LC_SUB_CLIENT	0x14	/* sub client */
#define	LC_SUB_LIBRARY  0x15	/* sub library */
#define	LC_TWOLEVEL_HINTS 0x16	/* two-level namespace lookup hints */
#define	LC_PREBIND_CKSUM  0x17	/* prebind checksum */
#define	LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD) /* load a dynamically linked shared library that is allowed to be missing (all symbols are weak imported). */
#define	LC_SEGMENT_64	0x19	/* 64-bit segment of this file to be mapped */
#define	LC_ROUTINES_64	0x1a	/* 64-bit image routines */
#define LC_UUID		0x1b	/* the uuid */
#define LC_RPATH       (0x1c | LC_REQ_DYLD)    /* runpath additions */
#define LC_CODE_SIGNATURE 0x1d	/* local of code signature */
#define LC_SEGMENT_SPLIT_INFO 0x1e /* local of info to split segments */
#define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
#define	LC_LAZY_LOAD_DYLIB 0x20	/* delay load of dylib until first use */
#define	LC_ENCRYPTION_INFO 0x21	/* encrypted segment information */
#define	LC_DYLD_INFO 	0x22	/* compressed dyld information */
#define	LC_DYLD_INFO_ONLY (0x22|LC_REQ_DYLD)	/* compressed dyld information only */
#define	LC_LOAD_UPWARD_DYLIB (0x23 | LC_REQ_DYLD) /* load upward dylib */
#define LC_VERSION_MIN_MACOSX 0x24   /* build for MacOSX min OS version */
#define LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
#define LC_FUNCTION_STARTS 0x26 /* compressed table of function start addresses */
#define LC_DYLD_ENVIRONMENT 0x27 /* string for dyld to treat like environment variable */
#define LC_MAIN (0x28|LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
#define LC_DATA_IN_CODE 0x29 /* table of non-instructions in __text */
#define LC_SOURCE_VERSION 0x2A /* source version used to build binary */
#define LC_DYLIB_CODE_SIGN_DRS 0x2B /* Code signing DRs copied from linked dylibs */
#define LC_ENCRYPTION_INFO_64 0x2C // 64-bit encrypted segment information
#define LC_LINKER_OPTION 0x2D // linker options in MH_OBJECT files
#define LC_LINKER_OPTIMIZATION_HINT 0x2E // optimization hints in MH_OBJECT files
#define LC_VERSION_MIN_TVOS 0x2F // build for AppleTV min OS version
#define LC_VERSION_MIN_WATCHOS 0x30 // build for Watch min OS version
#define LC_NOTE 0x31 // arbitrary data included within a Mach-O file
#define LC_BUILD_VERSION 0x32 // build for platform min OS version

typedef struct version_32 {
    uint16_t v0;
    uint8_t v1;
    uint8_t v2;
} Version32;

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
typedef struct mach_header_64 {
    uint32_t magic;		/* mach magic number identifier */
    cpu_type_t cputype;	/* cpu specifier */
    cpu_subtype_t cpusubtype;	/* machine specifier */
    uint32_t filetype;	/* type of file */
    uint32_t ncmds;		/* number of load commands */
    uint32_t sizeofcmds;	/* the size of all the load commands */
    uint32_t flags;		/* flags */
    uint32_t reserved;	/* reserved */
} MachHeader64;

typedef struct mach_0_load_command
{
    uint32_t cmd;
    uint32_t cmdsize;
} LoadCommand;

#define MACH_O_UUID_LN (0x10)

typedef struct UuidCommand
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint8_t uuid[MACH_O_UUID_LN];
} UuidCommand;

typedef struct SegmentCommand32 {
    uint32_t  cmd;
    uint32_t  cmdsize;
    char      segname[MACH_O_SEG_NAME_LN];
    uint32_t  vmaddr;
    uint32_t  vmsize;
    uint32_t  fileoff;
    uint32_t  filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t  nsects;
    uint32_t  flags;
} SegmentCommand32;

typedef struct SegmentCommand64 {
    uint32_t  cmd;
    uint32_t  cmdsize;
    char      segname[MACH_O_SEG_NAME_LN];
    uint64_t  vmaddr;
    uint64_t  vmsize;
    uint64_t  fileoff;
    uint64_t  filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t  nsects;
    uint32_t  flags;
} SegmentCommand64;

/* Constants for the flags field of the segment_command */
#define	SG_HIGHVM	0x1	/* the file contents for this segment is for the high part of the VM space, the low part is zero filled (for stacks in core files) */
#define	SG_FVMLIB	0x2	/* this segment is the VM that is allocated by a fixed VM library, for overlap checking inthe link editor */
#define	SG_NORELOC	0x4	/* this segment has nothing that was relocated in it and nothing relocated to it, that is it maybe safely replaced without relocation*/
#define SG_PROTECTED_VERSION_1	0x8 /* This segment is protected.  If the segment starts at file offset 0, the first page of the segment is not protected.  All other pages of the segment are protected. */

typedef struct MachOSection
{
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
} MachOSection;

typedef struct section_64 { /* for 64-bit architectures */
    char		sectname[16];	/* name of this section */
    char		segname[16];	/* segment this section goes in */
    uint64_t	addr;		/* memory address of this section */
    uint64_t	size;		/* size in bytes of this section */
    uint32_t	offset;		/* file offset of this section */
    uint32_t	align;		/* section alignment (power of 2) */
    uint32_t	reloff;		/* file offset of relocation entries */
    uint32_t	nreloc;		/* number of relocation entries */
    uint32_t	flags;		/* flags (section type and attributes)*/
    uint32_t	reserved1;	/* reserved (for offset or index) */
    uint32_t	reserved2;	/* reserved (for count or sizeof) */
    uint32_t	reserved3;	/* reserved */
} MachOSection64;

/*
 * The flags field of a section structure is separated into two parts a section
 * type and section attributes.  The section types are mutually exclusive (it
 * can only have one type) but the section attributes are not (it may have more
 * than one attribute).
 */
#define SECTION_TYPE		 0x000000ff	/* 256 section types */
#define SECTION_ATTRIBUTES	 0xffffff00	/*  24 section attributes */

/* Constants for the type of a section */
#define S_REGULAR  0x0 /* regular section */
#define S_ZEROFILL  0x1 /* zero fill on demand section */
#define S_CSTRING_LITERALS 0x2 /* section with only literal C strings*/
#define S_4BYTE_LITERALS 0x3 /* section with only 4 byte literals */
#define S_8BYTE_LITERALS 0x4 /* section with only 8 byte literals */
#define S_LITERAL_POINTERS 0x5 /* section with only pointers to */
/*  literals */
/*
 * For the two types of symbol pointers sections and the symbol stubs section
 * they have indirect symbol table entries.  For each of the entries in the
 * section the indirect symbol table entries, in corresponding order in the
 * indirect symbol table, start at the index stored in the reserved1 field
 * of the section structure.  Since the indirect symbol table entries
 * correspond to the entries in the section the number of indirect symbol table
 * entries is inferred from the size of the section divided by the size of the
 * entries in the section.  For symbol pointers sections the size of the entries
 * in the section is 4 bytes and for symbol stubs sections the byte size of the
 * stubs is stored in the reserved2 field of the section structure.
 */
#define S_NON_LAZY_SYMBOL_POINTERS 0x6 /* section with only non-lazy symbol pointers */
#define S_LAZY_SYMBOL_POINTERS  0x7 /* section with only lazy symbol pointers */
#define S_SYMBOL_STUBS   0x8 /* section with only symbol stubs, byte size of stub in the reserved2 field */
#define S_MOD_INIT_FUNC_POINTERS 0x9 /* section with only function          pointers for initialization*/
#define S_MOD_TERM_FUNC_POINTERS 0xa /* section with only function pointers for termination */
#define S_COALESCED   0xb /* section contains symbols that are to be coalesced */
#define S_GB_ZEROFILL   0xc /* zero fill on demand section (that can be larger than 4 gigabytes) */
#define S_INTERPOSING   0xd /* section with only pairs of function pointers for interposing */
#define S_16BYTE_LITERALS  0xe /* section with only 16 byte literals */
#define S_DTRACE_DOF   0xf /* section contains DTrace Object Format */
#define S_LAZY_DYLIB_SYMBOL_POINTERS 0x10 /* section with only lazy symbol pointers to lazy loaded dylibs */
/*
 * Section types to support thread local variables
 */
#define S_THREAD_LOCAL_REGULAR                   0x11  /* template of initial values for TLVs */
#define S_THREAD_LOCAL_ZEROFILL                  0x12  /* template of initial values for TLVs */
#define S_THREAD_LOCAL_VARIABLES                 0x13  /* TLV descriptors */
#define S_THREAD_LOCAL_VARIABLE_POINTERS         0x14  /* pointers to TLV descriptors */
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS    0x15  /* functions to call to initialize TLV values */

/*
 * Constants for the section attributes part of the flags field of a section
 * structure.
 */
#define SECTION_ATTRIBUTES_USR  0xff000000 /* User setable attributes */
#define S_ATTR_PURE_INSTRUCTIONS 0x80000000 /* section contains only true machine instructions */
#define S_ATTR_NO_TOC    0x40000000 /* section contains coalesced symbols that are not to be in a ranlib table of contents */
#define S_ATTR_STRIP_STATIC_SYMS 0x20000000 /* ok to strip static symbols in this section in files with the MH_DYLDLINK flag */
#define S_ATTR_NO_DEAD_STRIP  0x10000000 /* no dead stripping */
#define S_ATTR_LIVE_SUPPORT  0x08000000 /* blocks are live if they reference live blocks */
#define S_ATTR_SELF_MODIFYING_CODE 0x04000000 /* Used with i386 code stubs written on by dyld */
/*
 * If a segment contains any sections marked with S_ATTR_DEBUG then all
 * sections in that segment must have this attribute.  No section other than
 * a section marked with this attribute may reference the contents of this
 * section.  A section with this attribute may contain no symbols and must have
 * a section type S_REGULAR.  The static linker will not copy section contents
 * from sections with this attribute into its output file.  These sections
 * generally contain DWARF debugging info.
 */
#define S_ATTR_DEBUG   0x02000000 /* a debug section */
#define SECTION_ATTRIBUTES_SYS  0x00ffff00 /* system setable attributes */
#define S_ATTR_SOME_INSTRUCTIONS 0x00000400 /* section contains some machine instructions */
#define S_ATTR_EXT_RELOC  0x00000200 /* section has external relocation entries */
#define S_ATTR_LOC_RELOC  0x00000100 /* section has local relocation entries */

typedef struct twolevel_hints_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t offset;
    uint32_t nhints;
} TwolevelHintsCommand;

//struct twolevel_hint
//{
//	uint32_t isub_image:8,
//	itoc:24;
//};

union lc_str
{
    uint32_t offset;// 0 4
#ifndef __LP64__
    char *ptr;
#endif
};

typedef struct dylib
{
    union lc_str name; // 0x0
    uint32_t timestamp; // 0x4
    uint32_t current_version; // 0x8
    uint32_t compatibility_version; // 0x1c
} Dylib; // 0x10

typedef struct dylib_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    struct dylib dylib; // 0x8
} DylibCommand; // 0x18

typedef struct prebound_dylib_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    union lc_str name; // 0x8
    uint32_t nmodules; // 0xC
    union lc_str linked_modules; // 0x10
} PreboundDylibCommand; // 0x14

// LC_THREAD | LC_UNIXTHREAD
typedef struct thread_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    uint32_t flavor; // 0x8
    uint32_t count; // 0xC
//	struct cpu_thread_state state; // 0x
} ThreadCommand; // 0x10

// LC_ROUTINES
typedef struct routines_command
{
    uint32_t cmd; // 0x00
    uint32_t cmdsize; // 0x04
    uint32_t init_address; // 0x08
    uint32_t init_module; // 0x0C
    uint32_t reserved1; // 0x10
    uint32_t reserved2; // 0x14
    uint32_t reserved3; // 0x18
    uint32_t reserved4; // 0x1C
    uint32_t reserved5; // 0x20
    uint32_t reserved6; // 0x24
} RoutinesCommand; // 0x28

// LC_ROUTINES_64
typedef struct routines_command_64
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    uint64_t init_address; // 0x8
    uint64_t init_module; // 0x10
    uint64_t reserved1; // 0x18
    uint64_t reserved2; // 0x20
    uint64_t reserved3; // 0x28
    uint64_t reserved4; // 0x30
    uint64_t reserved5; // 0x38
    uint64_t reserved6; // 0x40
} RoutinesCommand64; // 0x48

typedef struct sub_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    union lc_str name; // 0x8
} SubCommand; // 0x0C

typedef SubCommand SubFrameworkCommand; // LC_SUB_FRAMEWORK
typedef SubCommand SubUmbrellaCommand; // LC_SUB_UMBRELLA
typedef SubCommand SubLibraryCommand; // LC_SUB_LIBRARY
typedef SubCommand SubClientCommand; // LC_SUB_CLIENT
typedef SubCommand DyLinkerCommand; // LC_SUB_CLIENT

// LC_SYMTAB
typedef struct symtab_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    uint32_t symoff; // 0x8
    uint32_t nsyms; // 0xC
    uint32_t stroff; // 0x10
    uint32_t strsize; // 0x14
} SymtabCommand; // 0x18

// entry of symtab
struct nlist
{
    union {
#ifndef __LP64__
        char *n_name; // The n_name field is not used in Mach-O files
#endif
        int32_t n_strx; // index into string table
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    int16_t n_desc;
    uint32_t n_value;
};

struct nlist_64 {
    union {
        uint32_t  n_strx; /* index into the string table */
    } n_un;
    uint8_t n_type;        /* type flag, see below */
    uint8_t n_sect;        /* section number or NO_SECT */
    uint16_t n_desc;       /* see <mach-o/stab.h> */
    uint64_t n_value;      /* value of this symbol (or stab offset) */
};

// LC_DYSYMTAB
typedef struct dysymtab_command
{
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4
    uint32_t ilocalsym; // 0x8
    uint32_t nlocalsym; // 0xC
    uint32_t iextdefsym; // 0x10
    uint32_t nextdefsym; // 0x14
    uint32_t iundefsym; // 0x18
    uint32_t nundefsym; // 0x1C
    uint32_t tocoff; // 0x20
    uint32_t ntoc; // 0x24
    uint32_t modtaboff; // 0x28
    uint32_t nmodtab; // 0x2C
    uint32_t extrefsymoff; // 0x30
    uint32_t nextrefsyms; // 0x34
    uint32_t indirectsymoff; // 0x38
    uint32_t nindirectsyms; // 0x3C
    uint32_t extreloff; // 0x40
    uint32_t nextrel; // 0x44
    uint32_t locreloff; // 0x48
    uint32_t nlocrel; // 0x4C
} DySymtabCommand; // 0x50

struct dylib_table_of_contents
{
    uint32_t symbol_index;
    uint32_t module_index;
};

struct dylib_module
{
    uint32_t module_name;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t irefsym;
    uint32_t nrefsym;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextrel;
    uint32_t nextrel;
    uint32_t iinit_iterm;
    uint32_t ninit_nterm;
    uint32_t objc_module_info_addr;
    uint32_t objc_module_info_size;
};

struct dylib_module_64
{
    uint32_t module_name;
    uint32_t iextdefsym;
    uint32_t nextdefsym;
    uint32_t irefsym;
    uint32_t nrefsym;
    uint32_t ilocalsym;
    uint32_t nlocalsym;
    uint32_t iextrel;
    uint32_t nextrel;
    uint32_t iinit_iterm;
    uint32_t ninit_nterm;
    uint32_t objc_module_info_size;
    uint64_t objc_module_info_addr;
};

/*
 * The version_min_command contains the min OS version on which this
 * binary was built to run.
 */
// LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS
typedef struct version_min_command {
    uint32_t cmd; // 0x0
    uint32_t cmdsize; // 0x4 sizeof(struct min_version_command)
    uint32_t version; //0x8 X.Y.Z is encoded in nibbles xxxx.yy.zz
    uint32_t reserved; // 0xC zero
} VersionMinCommand; // 0x10

typedef struct linked_it_data_command
{
    uint32_t cmd;//0x0
    uint32_t cmdsize;//0x4
    uint32_t offset;//0x8
    uint32_t size; // 0xC
} LinkedItDataCommand;// 0x10

typedef LinkedItDataCommand CodeSignatureCommand; // LC_CODE_SIGNATURE
typedef LinkedItDataCommand SegmentSplitInfoCommand; // LC_SEGMENT_SPLIT_INFO
typedef LinkedItDataCommand FunctionStartsCommand; // LC_FUNCTION_STARTS
typedef LinkedItDataCommand DataInCodeCommand; // LC_DATA_IN_CODE
typedef LinkedItDataCommand DylibCodeSignDRSCommand; // LC_DYLIB_CODE_SIGN_DRS
typedef LinkedItDataCommand LinkeOptimizationHintCommand; // LC_LINKER_OPTIMIZATION_HINT

typedef struct dyld_info_command {
    uint32_t   cmd;      /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
    uint32_t   cmdsize;      /* sizeof(struct dyld_info_command) */
    uint32_t   rebase_off;  /* file offset to rebase info  */
    uint32_t   rebase_size; /* size of rebase info   */
    uint32_t   bind_off;    /* file offset to binding info   */
    uint32_t   bind_size;   /* size of binding info  */
    uint32_t   weak_bind_off;   /* file offset to weak binding info   */
    uint32_t   weak_bind_size;  /* size of weak binding info  */
    uint32_t   lazy_bind_off;   /* file offset to lazy binding info */
    uint32_t   lazy_bind_size;  /* size of lazy binding infs */
    uint32_t   export_off;  /* file offset to lazy binding info */
    uint32_t   export_size; /* size of lazy binding infos */
} DyldInfoCommand; // 0x30

typedef struct source_version_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t version;
} SourceVersionCommand; // 0x10

typedef struct main_dylib_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entry_off;
    uint64_t stack_size;
} MainDylibCommand; // 0x18

typedef struct
{
    uint32_t tool;      // enum for the tool
    uint32_t version;   // version of the tool
} build_tool_version;

// LC_BUILD_VERSION
typedef struct build_version_command
{
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t platform;  // platform
    uint32_t minos;     // X.Y.Z is encoded in nibbles xxxx.yy.zz
    uint32_t sdk;       // X.Y.Z is encoded in nibbles xxxx.yy.zz
    uint32_t ntools;
    build_tool_version* tools; // [ntools]
} BuildVersionCommand;

#endif
