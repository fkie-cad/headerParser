#ifndef HEADER_PARSER_PE_SECTION_CHARACTERISTICS_H
#define HEADER_PARSER_PE_SECTION_CHARACTERISTICS_H

#include <stdint.h>

struct PE_Section_Characteristics
{
    uint32_t Reserved0;
    uint32_t Reserved1;
    uint32_t Reserved2;
    uint32_t Reserved3;
    uint32_t IMAGE_SCN_TYPE_NO_PAD; // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    uint32_t Reserved4;
    uint32_t IMAGE_SCN_CNT_CODE; // The section contains executable code.
    uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA; // The section contains initialized data.
    uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA; // The section contains uninitialized data.
    uint32_t IMAGE_SCN_LNK_OTHER; // Reserved for future use.
    uint32_t IMAGE_SCN_LNK_INFO; // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    uint32_t Reserved5;
    uint32_t IMAGE_SCN_LNK_REMOVE; // The section will not become part of the image. This is valid only for object files.
    uint32_t IMAGE_SCN_LNK_COMDAT; // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    uint32_t IMAGE_SCN_GPREL; // The section contains data referenced through the global pointer (GP).
    uint32_t IMAGE_SCN_MEM_PURGEABLE; // Reserved for future use.
    uint32_t IMAGE_SCN_MEM_16BIT; // Reserved for future use.
    uint32_t IMAGE_SCN_MEM_LOCKED; // Reserved for future use.
    uint32_t IMAGE_SCN_MEM_PRELOAD; // Reserved for future use.
    uint32_t IMAGE_SCN_ALIGN_1BYTES; // Align data on a 1-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_2BYTES; // Align data on a 2-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_4BYTES; // Align data on a 4-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_8BYTES; // Align data on an 8-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_16BYTES; // Align data on a 16-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_32BYTES; // Align data on a 32-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_64BYTES; // Align data on a 64-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_128BYTES; // Align data on a 128-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_256BYTES; // Align data on a 256-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_512BYTES; // Align data on a 512-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_1024BYTES; // Align data on a 1024-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_2048BYTES; // Align data on a 2048-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_4096BYTES; // Align data on a 4096-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_ALIGN_8192BYTES; // Align data on an 8192-byte boundary. Valid only for object files.
    uint32_t IMAGE_SCN_LNK_NRELOC_OVFL; //  section contains extended relocations.
    uint32_t IMAGE_SCN_MEM_DISCARDABLE; // The section can be discarded as needed.
    uint32_t IMAGE_SCN_MEM_NOT_CACHED; // The section cannot be cached.
    uint32_t IMAGE_SCN_MEM_NOT_PAGED; // The section is not pageable.
    uint32_t IMAGE_SCN_MEM_SHARED; // The section can be shared in memory.
    uint32_t IMAGE_SCN_MEM_EXECUTE; // The section can be executed as code.
    uint32_t IMAGE_SCN_MEM_READ; // The section can be read.
    uint32_t IMAGE_SCN_MEM_WRITE; // The section can be written to.
};

const struct PE_Section_Characteristics PESectionCharacteristics = {
    .Reserved0 = 0x00000000,
    .Reserved1 = 0x00000001,
    .Reserved2 = 0x00000002,
    .Reserved3 = 0x00000004,
    .IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
    .Reserved4 = 0x00000010,
    .IMAGE_SCN_CNT_CODE = 0x00000020,
    .IMAGE_SCN_CNT_INITIALIZED_DATA =0x00000040,
    .IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    .IMAGE_SCN_LNK_OTHER = 0x00000100,
    .IMAGE_SCN_LNK_INFO = 0x00000200,
    .Reserved5 = 0x00000400,
    .IMAGE_SCN_LNK_REMOVE = 0x00000800,
    .IMAGE_SCN_LNK_COMDAT = 0x00001000,
    .IMAGE_SCN_GPREL = 0x00008000,
    .IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
    .IMAGE_SCN_MEM_16BIT = 0x00020000,
    .IMAGE_SCN_MEM_LOCKED = 0x00040000,
    .IMAGE_SCN_MEM_PRELOAD = 0x00080000,
    .IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
    .IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
    .IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
    .IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
    .IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
    .IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
    .IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
    .IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
    .IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
    .IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
    .IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
    .IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
    .IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
    .IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
    .IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    .IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
    .IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
    .IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
    .IMAGE_SCN_MEM_SHARED = 0x10000000,
    .IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    .IMAGE_SCN_MEM_READ = 0x40000000,
    .IMAGE_SCN_MEM_WRITE = 0x80000000
};

#endif
