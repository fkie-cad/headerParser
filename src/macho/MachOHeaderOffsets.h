#ifndef HEADER_PARSER_MACHO_HEADER_OFFSETS_H
#define HEADER_PARSER_MACHO_HEADER_OFFSETS_H

#include <stdint.h>

typedef struct Mach_Header_Offsets {
    uint8_t magic;		/* mach magic number identifier */
    uint8_t cputype;	/* cpu specifier */
    uint8_t cpusubtype;	/* machine specifier */
    uint8_t filetype;	/* type of file */
    uint8_t ncmds;		/* number of load commands */
    uint8_t sizeofcmds;	/* the size of all the load commands */
    uint8_t flags;		/* flags */
    uint8_t reserved;	/* flags */
} Mach_Header_Offsets;

static const struct Mach_Header_Offsets MachHeaderOffsets = {
    .magic = 0,       /* mach magic number identifier */
    .cputype = 4,     /* cpu specifier */
    .cpusubtype = 8,  /* machine specifier */
    .filetype = 12,   /* type of file */
    .ncmds = 16,      /* number of load commands */
    .sizeofcmds = 20, /* the size of all the load commands */
    .flags = 24,      /* flags */
    .reserved = 28,   /* flags */
};

typedef struct Load_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
} Load_Command_Offsets;

static const struct Load_Command_Offsets LoadCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4
};

typedef struct Uuid_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t uuid;
} Uuid_Command_Offsets;

static const struct Uuid_Command_Offsets UuidCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .uuid = 8
};

typedef struct Segment_Command_Offsets {
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t segname;
    uint8_t vmaddr;
    uint8_t vmsize;
    uint8_t fileoff;
    uint8_t filesize;
    uint8_t maxprot;
    uint8_t initprot;
    uint8_t nsects;
    uint8_t flags;
} Segment_Command_Offsets;

static const struct Segment_Command_Offsets SegmentCommandOffsets32 = {
    .cmd = 0,
    .cmdsize = 4,
    .segname = 8,
    .vmaddr = 24,
    .vmsize = 28,
    .fileoff = 32,
    .filesize = 36,
    .maxprot = 40,
    .initprot = 44,
    .nsects = 48,
    .flags = 52,
};

static const struct Segment_Command_Offsets SegmentCommandOffsets64 = {
    .cmd = 0,
    .cmdsize = 4,
    .segname = 8,
    .vmaddr = 24,
    .vmsize = 32,
    .fileoff = 40,
    .filesize = 48,
    .maxprot = 56,
    .initprot = 60,
    .nsects = 64,
    .flags = 68,
};

typedef struct MachO_Section_Offsets
{
    uint8_t sectname;
    uint8_t segname;
    uint8_t addr;
    uint8_t size;
    uint8_t offset;
    uint8_t align;
    uint8_t reloff;
    uint8_t nreloc;
    uint8_t flags;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t reserved3;
} MachO_Section_Offsets;

static const MachO_Section_Offsets MachOsectionOffsets32 = {
    .sectname = 0,
    .segname = 16,
    .addr = 32,
    .size = 36,
    .offset = 40,
    .align = 44,
    .reloff = 48,
    .nreloc = 52,
    .flags = 56,
    .reserved1 = 60,
    .reserved2 = 64,
//	.reserved3 = 64,
};

static const struct MachO_Section_Offsets MachOsectionOffsets64 = {
    .sectname = 0,
    .segname = 16,
    .addr = 32,
    .size = 40,
    .offset = 48,
    .align = 52,
    .reloff = 56,
    .nreloc = 60,
    .flags = 64,
    .reserved1 = 68,
    .reserved2 = 72,
    .reserved3 = 76
};

typedef struct Twolevel_Hints_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t offset;
    uint8_t nhints;
} Twolevel_Hints_Command_Offsets;

static const struct Twolevel_Hints_Command_Offsets TwolevelHintsCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .offset = 8,
    .nhints = 12,
};

typedef struct Dylib_Offsets
{
    uint8_t name;
    uint8_t timestamp;
    uint8_t current_version;
    uint8_t compatibility_version;
} Dylib_Offsets;

static const Dylib_Offsets DylibOffsets = {
    .name = 0,
    .timestamp = 4,
    .current_version = 8,
    .compatibility_version = 12
};

typedef struct Dylib_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t dylib;
} Dylib_Command_Offsets;

static const Dylib_Command_Offsets DylibCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .dylib = 8
};

typedef struct Prebound_Dylib_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t name;
    uint8_t nmodules;
    uint8_t linked_modules;
} Prebound_Dylib_Command_Offsets;

static const Prebound_Dylib_Command_Offsets PreboundDylibCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .name = 8,
    .nmodules = 12,
    .linked_modules = 16
};


typedef struct Sub_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t name;
} Sub_Command_Offsets;

static const Sub_Command_Offsets SubCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .name = 8,
};

typedef struct Symtab_Command_Offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t symoff;
    uint8_t nsyms;
    uint8_t stroff;
    uint8_t strsize;
} Symtab_Command_Offsets;

static const Symtab_Command_Offsets SymtabCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .symoff = 8,
    .nsyms = 12,
    .stroff = 16,
    .strsize = 20,
};

typedef struct dysymtab_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t ilocalsym;
    uint8_t nlocalsym;
    uint8_t iextdefsym;
    uint8_t nextdefsym;
    uint8_t iundefsym;
    uint8_t nundefsym;
    uint8_t tocoff;
    uint8_t ntoc;
    uint8_t modtaboff;
    uint8_t nmodtab;
    uint8_t extrefsymoff;
    uint8_t nextrefsyms;
    uint8_t indirectsymoff;
    uint8_t nindirectsyms;
    uint8_t extreloff;
    uint8_t nextrel;
    uint8_t locreloff;
    uint8_t nlocrel;
} Dysymtab_Command_Offsets;

static const Dysymtab_Command_Offsets DySymtabCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .ilocalsym = 8,
    .nlocalsym = 12,
    .iextdefsym = 16,
    .nextdefsym = 20,
    .iundefsym = 24,
    .nundefsym = 28,
    .tocoff = 32,
    .ntoc = 36,
    .modtaboff = 40,
    .nmodtab = 44,
    .extrefsymoff = 48,
    .nextrefsyms = 52,
    .indirectsymoff = 56,
    .nindirectsyms = 60,
    .extreloff = 64,
    .nextrel = 68,
    .locreloff = 72,
    .nlocrel = 76,
};

typedef struct routines_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t init_address;
    uint8_t init_module;
    uint8_t reserved1;
    uint8_t reserved2;
    uint8_t reserved3;
    uint8_t reserved4;
    uint8_t reserved5;
    uint8_t reserved6;
} Routines_Command_Offsets;

static const Routines_Command_Offsets RoutinesCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .init_module = 8,
    .reserved1 = 12,
    .reserved2 = 16,
    .reserved3 = 20,
    .reserved4 = 24,
    .reserved5 = 28,
    .reserved6 = 32,
};

static const Routines_Command_Offsets RoutinesCommand64Offsets = {
    .cmd = 0,
    .cmdsize = 4,
    .init_module = 8,
    .reserved1 = 16,
    .reserved2 = 24,
    .reserved3 = 32,
    .reserved4 = 40,
    .reserved5 = 48,
    .reserved6 = 56,
};

typedef struct version_min_command_offsets {
    uint8_t cmd;
    uint8_t cmdsize;	/* sizeof(struct min_version_command) */
    uint8_t version;	/* X.Y.Z is encoded in nibbles xxxx.yy.zz */
    uint8_t reserved;	/* zero */
} Version_Min_Command_Offsets;

static const Version_Min_Command_Offsets VersionMinCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .version = 8,
    .reserved = 12,
};

typedef struct thread_command_offset
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t flavor;
    uint8_t count;
    uint8_t state;
} Thread_Command_Offsets;

static const Thread_Command_Offsets ThreadCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .flavor = 8,
    .count = 12,
    .state = 16,
};

typedef struct linked_it_data_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t offset;
    uint8_t size;
} Linked_It_Data_Command_Offsets;

static const Linked_It_Data_Command_Offsets LinkedItDataCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .offset = 8,
    .size = 12,
};

typedef struct dyld_info_command_offsets {
    uint8_t cmd;      /* LC_DYLD_INFO or LC_DYLD_INFO_ONLY */
    uint8_t cmdsize;      /* sizeof(struct dyld_info_command) */
    uint8_t rebase_off;  /* file offset to rebase info  */
    uint8_t rebase_size; /* size of rebase info   */
    uint8_t bind_off;    /* file offset to binding info   */
    uint8_t bind_size;   /* size of binding info  */
    uint8_t weak_bind_off;   /* file offset to weak binding info   */
    uint8_t weak_bind_size;  /* size of weak binding info  */
    uint8_t lazy_bind_off;   /* file offset to lazy binding info */
    uint8_t lazy_bind_size;  /* size of lazy binding infs */
    uint8_t export_off;  /* file offset to lazy binding info */
    uint8_t export_size; /* size of lazy binding infos */
} Dyld_Info_Command_Offsets;

static const Dyld_Info_Command_Offsets DyldInfoCommandOffsets =  {
    .cmd = 0,
    .cmdsize = 4,
    .rebase_off = 8,
    .rebase_size = 12,
    .bind_off = 16,
    .bind_size = 20,
    .weak_bind_off = 24,
    .weak_bind_size = 28,
    .lazy_bind_off = 32,
    .lazy_bind_size = 36,
    .export_off = 40,
    .export_size = 44,
};

typedef struct source_version_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t version;
} Source_Version_Command_Offsets;

static const Source_Version_Command_Offsets SourceVersionCommandOffsets =  {
    .cmd = 0,
    .cmdsize = 4,
    .version = 8,
};

typedef struct main_dylib_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t entry_off;
    uint8_t stack_size;
} Main_Dylib_Command_Offsets;

static const Main_Dylib_Command_Offsets MainDylibCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .entry_off = 8,
    .stack_size = 16,
};

typedef struct build_verison_command_offsets
{
    uint8_t cmd;
    uint8_t cmdsize;
    uint8_t platform;
    uint8_t minos;
    uint8_t sdk;
    uint8_t ntools;
    uint8_t tools;
} Build_Version_Command_Offsets;

static const Build_Version_Command_Offsets BuildVersionCommandOffsets = {
    .cmd = 0,
    .cmdsize = 4,
    .platform = 8,
    .minos = 12,
    .sdk = 16,
    .ntools = 20,
    .tools = 24,
};

#endif
