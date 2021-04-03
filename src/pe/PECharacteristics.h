#ifndef HEADER_PARSER_PE_PE_CHARACTERISTICS_H
#define HEADER_PARSER_PE_PE_CHARACTERISTICS_H

#include <stdint.h>

struct PE_COFF_Characteristics
{
    uint16_t IMAGE_FILE_RELOCS_STRIPPED; // Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.
    uint16_t IMAGE_FILE_EXECUTABLE_IMAGE; // The file is executable (there are no unresolved external references).
    uint16_t IMAGE_FILE_LINE_NUMS_STRIPPED; // COFF line numbers were stripped from the file.
    uint16_t IMAGE_FILE_LOCAL_SYMS_STRIPPED; // COFF symbol table entries were stripped from file.
    uint16_t IMAGE_FILE_AGGRESIVE_WS_TRIM; // Aggressively trim the working set. This value is obsolete.
    uint16_t IMAGE_FILE_LARGE_ADDRESS_AWARE; // The application can handle addresses larger than 2 GB.
    uint16_t IMAGE_FILE_BYTES_REVERSED_LO; // The bytes of the word are reversed. This flag is obsolete.
    uint16_t IMAGE_FILE_32BIT_MACHINE; // The computer supports 32-bit words.
    uint16_t IMAGE_FILE_DEBUG_STRIPPED; // Debugging information was removed and stored separately in another file.
    uint16_t IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP; // If the image is on removable media, copy it to and run it from the swap file.
    uint16_t IMAGE_FILE_NET_RUN_FROM_SWAP; // If the image is on the network, copy it to and run it from the swap file.
    uint16_t IMAGE_FILE_SYSTEM; // The image is a system file.
    uint16_t IMAGE_FILE_DLL; // The image is a DLL file. While it is an executable file, it cannot be run directly.
    uint16_t IMAGE_FILE_UP_SYSTEM_ONLY; // The file should be run only on a uniprocessor computer.
    uint16_t IMAGE_FILE_BYTES_REVERSED_HI; // The bytes of the word are reversed. This flag is obsolete.
};

static const struct PE_COFF_Characteristics PECoffCharacteristics = {
    .IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    .IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    .IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
    .IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
    .IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
    .IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    .IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    .IMAGE_FILE_32BIT_MACHINE = 0x0100,
    .IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    .IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
    .IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
    .IMAGE_FILE_SYSTEM = 0x1000,
    .IMAGE_FILE_DLL = 0x2000,
    .IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    .IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
};

//struct PE_Dll_Characteristics
//{
//	uint16_t Reserved1; // 0x0001 must be zero.
//	uint16_t Reserved2; // 0x0002 must be zero.
//	uint16_t Reserved4; // 0x0004 must be zero.
//	uint16_t Reserved8; // 0x0008 must be zero.
//	uint16_t IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA; // Image can handle a high entropy 64-bit virtual address space.
//	uint16_t IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE; // DLL can be relocated at load time.
//	uint16_t IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY; // Code Integrity checks are enforced.
//	uint16_t IMAGE_DLLCHARACTERISTICS_NX_COMPAT; // Image is NX compatible.
//	uint16_t IMAGE_DLLCHARACTERISTICS_NO_ISOLATION; // Isolation aware, but do not isolate the image.
//	uint16_t IMAGE_DLLCHARACTERISTICS_NO_SEH; // Does not use structured exception (SE) handling. No SE handler may be called in this image.
//	uint16_t IMAGE_DLLCHARACTERISTICS_NO_BIND; // Do not bind the image.
//	uint16_t IMAGE_DLLCHARACTERISTICS_APPCONTAINER; // Image must execute in an AppContainer.
//	uint16_t IMAGE_DLLCHARACTERISTICS_WDM_DRIVER; // A WDM driver.
//	uint16_t IMAGE_DLLCHARACTERISTICS_GUARD_CF; // Image supports Control Flow Guard.
//	uint16_t IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE; // Terminal Server aware.
//};

typedef enum PEDllCharacteristics
{
    Reserved1 = 0x0001, // must be zero.
    Reserved2 = 0x0002, // must be zero.
    Reserved4 = 0x0004, // must be zero.
    Reserved8 = 0x0008, // must be zero.
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020, // Image can handle a high entropy 64-bit virtual address space.
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040, // DLL can be relocated at load time.
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080, // Code Integrity checks are enforced.
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100, // Image is NX compatible.
    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200, // Isolation aware, but do not isolate the image.
    IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400, // Does not use structured exception (SE) handling. No SE handler may be called in this image.
    IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800, // Do not bind the image.
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER = 0x1000, // Image must execute in an AppContainer.
    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000, // A WDM driver.
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000, // Image supports Control Flow Guard.
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000, // Terminal Server aware.
} PEDllCharacteristics;

#endif
