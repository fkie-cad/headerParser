#ifndef HEADER_PARSER_PE_HEADER_OFFSETS_H
#define HEADER_PARSER_PE_HEADER_OFFSETS_H

#include <stdint.h>

struct PE_Image_Dos_Header_Offsets
{
	uint8_t signature; // char[2] = { 'M', 'Z' };
	uint8_t lastsize;
	uint8_t nblocks;
	uint8_t nreloc;
	uint8_t hdrsize;
	uint8_t minalloc;
	uint8_t maxalloc;
	uint8_t ss; // void* : 2 byte value
	uint8_t sp; // void* : 2 byte value
	uint8_t checksum;
	uint8_t ip; // void* : 2 byte value
	uint8_t cs; // void* : 2 byte value
	uint8_t relocpos;
	uint8_t noverlay;
	uint8_t reserved1; // * uint16_t
	uint8_t oem_id;
	uint8_t oem_info;
	uint8_t reserved2; // 10 * uint16_t
	uint8_t e_lfanew; // uint32_t : Offset to the 'PE\0\0' signature relative to the beginning of the file
};
static struct PE_Image_Dos_Header_Offsets PEImageDosHeaderOffsets = {
	.signature = 0,
	.lastsize = 2,
	.nblocks = 4,
	.nreloc = 6,
	.hdrsize = 8,
	.minalloc = 10,
	.maxalloc = 12,
	.ss = 14, // 2 byte value
	.sp = 16, // 2 byte value
	.checksum = 18,
	.ip = 20, // 2 byte value
	.cs = 22, // 2 byte value
	.relocpos = 24,
	.noverlay = 26,
	.reserved1 = 28,
	.oem_id = 36,
	.oem_info = 38,
	.reserved2 = 40,
	.e_lfanew = 60 // Offset to the 'PE\0\0' signature relative to the beginning of the file
};

struct PE_Coff_File_Header_Offsets
{
	uint8_t Machine; // The number that identifies the type of target machine. For more information, see Machine Types.
	uint8_t NumberOfSections; // The number of sections. This indicates the size of the section table, which immediately follows the headers.
	uint8_t TimeDateStamp; // The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.
	uint8_t PointerToSymbolTable; // The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated.
	uint8_t NumberOfSymbols; // The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.
	uint8_t SizeOfOptionalHeader; // The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file. For a description of the header format, see Optional Header (Image Only).
	uint8_t Characteristics; // The flags that indicate the attributes of the file. For specific flag values, see Characteristics.
};

static const struct PE_Coff_File_Header_Offsets PECoffFileHeaderOffsets = {
	.Machine = 0, // uint16_t
	.NumberOfSections = 2, // uint16_t
	.TimeDateStamp = 4, // uint32_t
	.PointerToSymbolTable = 8, // uint32_t
	.NumberOfSymbols = 12, // uint32_t
	.SizeOfOptionalHeader = 16, // uint16_t
	.Characteristics = 18 // uint16_t
};

typedef struct PEOptionalHeaderOffsets
{
	// offset(32/64) ; size(32/64)
	// 0 ; 2
	uint8_t Magic; // The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
//	2 ; 1
	uint8_t MajorLinkerVersion; // The linker major version number.
//	3 ;	1
	uint8_t MinorLinkerVersion; // The linker minor version number.
//	4 ; 4
	uint8_t SizeOfCode; // The size of the code (text) section, or the sum of all code sections if there are multiple sections.
//	8 ; 4
	uint8_t SizeOfInitializedData; // The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
//	12 ; 4
	uint8_t SizeOfUninitializedData; // The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
//	16 ; 4
	uint8_t AddressOfEntryPoint; // The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
//	20 ; 4
	uint8_t BaseOfCode; // The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.

	//  32-bit specific, not present in 64-bit
//	24 ; 4
	uint8_t BaseOfData; // The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.

	// Optional Header Windows-Specific Fields (Image Only)
//	28/24 ; 4/8
	uint8_t ImageBase; // The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
//	32/32 ; 4
	uint8_t SectionAlignment; // The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
//	36/36 ; 4
	uint8_t FileAlignment; // The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture's page size, then FileAlignment must match SectionAlignment.
//	40/40 ; 2
	uint8_t MajorOperatingSystemVersion; // The major version number of the required operating system.
//	42/42 ; 2
	uint8_t MinorOperatingSystemVersion; // The minor version number of the required operating system.
//	44/44 ; 2
	uint8_t MajorImageVersion; // The major version number of the image.
//	46/46 ; 2
	uint8_t MinorImageVersion; // The minor version number of the image.
//	48/48 ; 2
	uint8_t MajorSubsystemVersion; // The major version number of the subsystem.
//	50/50 ; 2
	uint8_t MinorSubsystemVersion; // The minor version number of the subsystem.
//	52/52 ; 4
	uint8_t Win32VersionValue; // Reserved, must be zero.
//	56/56 ; 4
	uint8_t SizeOfImage; // The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
//	60/60 ; 4
	uint8_t SizeOfHeaders; // The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
//	64/64 ; 4
	uint8_t CheckSum; // The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
//	68/68 ; 2
	uint8_t Subsystem; // The subsystem that is required to run this image. For more information, see Windows Subsystem.
//	70/70 ; 2
	uint8_t DllCharacteristics; // For more information, see DLL Characteristics later in this specification.
//	72/72 ; 4/8
	uint8_t SizeOfStackReserve; // The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
//	76/80 ; 4/8
	uint8_t SizeOfStackCommit; // The size of the stack to commit.
//	80/88 ; 4/8
	uint8_t SizeOfHeapReserve; // The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
//	84/96 ; 4/8
	uint8_t SizeOfHeapCommit; // The size of the local heap space to commit.
//	88/104 ; 4
	uint8_t LoaderFlags; // Reserved, must be zero.
//	92/108 ; 4
	uint8_t NumberOfRvaAndSizes; // The number of data-directory entries in the remainder of the optional header. Each describes a location and size.

	// Optional Header Data Directories (Image Only)
	uint8_t DataDirectories; //
//	96/112 ; 8
//	uint8_t ExportTable; // The export table address and size. For more information see .edata Section (Image Only).
//	104/120 ; 8
//	uint8_t ImportTable; // The import table address and size. For more information, see The .idata Section.
//	112/128 ; 8
//	uint8_t ResourceTable; // The resource table address and size. For more information, see The .rsrc Section.
//	120/136 ; 8
//	uint8_t ExceptionTable; // The exception table address and size. For more information, see The .pdata Section.
//	128/144 ; 8
//	uint8_t CertificateTable; // The attribute certificate table address and size. For more information, see The Attribute Certificate Table (Image Only).
//	136/152 ; 8
//	uint8_t Base Relocation Table; // The base relocation table address and size. For more information, see The .reloc Section (Image Only).
//	144/160 ; 8
//	uint8_t Debug; // The debug data starting address and size. For more information, see The .debug Section.
//	152/168 ; 8
//	uint8_t Architecture; // Reserved, must be 0
//	160/176 ; 8
//	uint8_t Global Ptr; // The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
//	168/184 ; 8
//	uint8_t TLS Table; // The thread local storage (TLS) table address and size. For more information, The .tls Section.
//	176/192 ; 8
//	uint8_t Load Config Table; // The load configuration table address and size. For more information, The Load Configuration Structure (Image Only).
//	184/200 ; 8
//	uint8_t Bound Import; // The bound import table address and size.
//	192/208 ; 8
//	uint8_t IAT; // The import address table address and size. For more information, see Import Address Table.
//	200/216 ; 8
//	uint8_t Delay Import Descriptor; // The delay import descriptor address and size. For more information, see Delay-Load Import Tables (Image Only).
//	208/224 ; 8
//	uint8_t CLR Runtime Header; // The CLR runtime header address and size. For more information, see The .cormeta Section (Object Only).
//	216/232 ; 8
//	uint8_t Reserved; // must be zero
} PEOptionalHeaderOffsets;

static const struct PEOptionalHeaderOffsets PEOptional32HeaderOffsets = {
	.Magic = 0, // uint16_t
	.MajorLinkerVersion = 2, // uint8_t
	.MinorLinkerVersion = 3, // uint8_t
	.SizeOfCode = 4, // uint32_t
	.SizeOfInitializedData = 8, // uint32_t The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
	.SizeOfUninitializedData = 12, // uint32_t The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
	.AddressOfEntryPoint = 16, // uint32_t
	.BaseOfCode = 20, // uint32_t The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
	.BaseOfData = 24, // uint32_t 32 bit specific. offset 0 for 64 The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
	.ImageBase = 28,// uint32_t : The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
	.SectionAlignment = 32, // uint32_t
	.FileAlignment = 36, // uint32_t
	.MajorOperatingSystemVersion = 40, // uint16_t The major version number of the required operating system.
	.MinorOperatingSystemVersion = 42, // uint16_t The major version number of the required operating system.
	.MajorImageVersion = 44, // uint16_t The major version number of the image
	.MinorImageVersion = 46, // uint16_t The minor version number of the image.
	.MajorSubsystemVersion = 48, // uint16_t The major version number of the subsystem.
	.MinorSubsystemVersion = 50,// uint16_t The minor version number of the subsystem.
	.Win32VersionValue = 52, // uint32 Reserved, must be zero.
	.SizeOfImage = 56, // uint32_t
	.SizeOfHeaders = 60, // uint32_t The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
	.CheckSum = 64, // uint32_t The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
	.Subsystem = 68, // uint16_t
	.DllCharacteristics = 70, // uint16_t
	.SizeOfStackReserve = 72, // uint32_t The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	.SizeOfStackCommit  = 76, // uint32_t The size of the stack to commit.
	.SizeOfHeapReserve = 80, // uint32_t The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	.SizeOfHeapCommit = 84, // uint32_t The size of the local heap space to commit.
	.LoaderFlags = 88, // uint32_t Reserved, must be zero.
	.NumberOfRvaAndSizes = 92, // uint32_t
	.DataDirectories = 96, // [NumberOfRvaAndSizes]
};

const struct PEOptionalHeaderOffsets PEOptional64HeaderOffsets = {
	.Magic = 0, // uint16_t
	.MajorLinkerVersion = 2, // uint8_t
	.MinorLinkerVersion = 3, // uint8_t
	.SizeOfCode = 4, // uint32_t
	.SizeOfInitializedData = 8, // uint32_t The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
	.SizeOfUninitializedData = 12, // uint32_t The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
	.AddressOfEntryPoint = 16, // uint32_t
	.BaseOfCode = 20, // uint32_t The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
	.ImageBase = 24,// uint64_t : The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
	.SectionAlignment = 32, // uint32_t : The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
	.FileAlignment = 36, // uint32_t : The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
	.MajorOperatingSystemVersion = 40, // uint16_t The major version number of the required operating system.
	.MinorOperatingSystemVersion = 42, // uint16_t The major version number of the required operating system.
	.MajorImageVersion = 44, // uint16_t The major version number of the image
	.MinorImageVersion = 46, // uint16_t The minor version number of the image.
	.MajorSubsystemVersion = 48, // uint16_t The major version number of the subsystem.
	.MinorSubsystemVersion = 50,// uint16_t The minor version number of the subsystem.
	.Win32VersionValue = 52, // uint32 Reserved, must be zero.
	.SizeOfImage = 56, // uint32_t : The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
	.SizeOfHeaders = 60, // uint32_t The combined size of an MS-DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
	.CheckSum = 64, // uint32_t The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
	.Subsystem = 68, // uint16_t
	.DllCharacteristics = 70, // uint16_t
	.SizeOfStackReserve = 72, // uint64_t The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	.SizeOfStackCommit  = 80, // uint64_t The size of the stack to commit.
	.SizeOfHeapReserve = 88, // uint64_t The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	.SizeOfHeapCommit = 96, // uint64_t The size of the local heap space to commit.
	.LoaderFlags = 104, // uint32_t Reserved, must be zero.
	// The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
	.NumberOfRvaAndSizes = 108, // uint32_t
	.DataDirectories = 112, // [NumberOfRvaAndSizes]

	// DATA DIRECTORY :
//	96/112
//	8
//	Export Table // The export table address and size. For more information see .edata Section (Image Only).
//	104/120
//	8
//	Import Table // The import table address and size. For more information, see The .idata Section.
//	112/128
//	8
//	Resource Table // The resource table address and size. For more information, see The .rsrc Section.
//	120/136
//	8
//	Exception Table // The exception table address and size. For more information, see The .pdata Section.
//	128/144
//	8
//	Certificate Table // The attribute certificate table address and size. For more information, see The Attribute Certificate Table (Image Only).
//	136/152
//	8
//	Base Relocation Table // The base relocation table address and size. For more information, see The .reloc Section (Image Only).
//	144/160
//	8
//	Debug // The debug data starting address and size. For more information, see The .debug Section.
//	152/168
//	8
//	Architecture // Reserved, must be 0
//	160/176
//	8
//	Global Ptr // The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
//	168/184
//	8
//	TLS Table // The thread local storage (TLS) table address and size. For more information, The .tls Section.
//	176/192
//	8
//	Load Config Table // The load configuration table address and size. For more information, The Load Configuration Structure (Image Only).
//	184/200
//	8
//	Bound Import // The bound import table address and size.
//	192/208
//	8
//	IAT // The import address table address and size. For more information, see Import Address Table.
//	200/216
//	8
//	Delay Import Descriptor // The delay import descriptor address and size. For more information, see Delay-Load Import Tables (Image Only).
//	208/224
//	8
//	CLR Runtime Header // The CLR runtime header address and size. For more information, see The .cormeta Section (Object Only).
//	216/232
//	8
//	Reserved, must be zero
};

// predefined offsets for the data directory
//#define IMAGE_DIRECTORY_ENTRY_EXPORT 0 // Export Directory
//#define IMAGE_DIRECTORY_ENTRY_IMPORT 1 // Import Directory
//#define IMAGE_DIRECTORY_ENTRY_RESOURCE 2 // Resource Directory
//#define IMAGE_DIRECTORY_ENTRY_EXCEPTION 3 // Exception Directory
//#define IMAGE_DIRECTORY_ENTRY_SECURITY 4 // Security Directory
//#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5 // Base Relocation Table
//#define IMAGE_DIRECTORY_ENTRY_DEBUG 6 // Debug Directory
//// IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7 // (X86 usage)
//#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7 // Architecture Specific Data
//#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8 // RVA of GP
//#define IMAGE_DIRECTORY_ENTRY_TLS 9 // TLS Directory
//#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10 // Load Configuration Directory
//#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11 // Bound Import Directory in headers
//#define IMAGE_DIRECTORY_ENTRY_IAT 12 // Import Address Table
//#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13 // Delay Load Import Descriptors
//#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14 // COM Runtime descriptor

// Each row of the section table is, in effect, a section header.
// This table immediately follows the optional header, if any.
// This positioning is required because the file header does not contain a direct pointer to the section table.
// Instead, the location of the section table is determined by calculating the location of the first byte after the headers.
// Make sure to use the size of the optional header as specified in the file header.
// 40 bytes per entry
struct PE_Section_Header_Offsets
{
	// An 8-byte, null-padded UTF-8 encoded string.
	// If the string is exactly 8 characters long, there is no terminating null.
	// For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table.
	// Executable images do not use a string table and do not support section names longer than 8 characters.
	// Long names in object files are truncated if they are emitted to an executable file.
	uint8_t Name;
	uint8_t VirtualSize; // The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only for executable images and should be set to zero for object files.
	uint8_t VirtualAddress; // For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory. For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
	uint8_t SizeOfRawData; // The size of the section (for object files) or the size of the initialized data on disk (for image files). For executable images, this must be a multiple of FileAlignment from the optional header. If this is less than VirtualSize, the remainder of the section is zero-filled. Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well. When a section contains only uninitialized data, this field should be zero.
	uint8_t PointerToRawData; // The file pointer to the first page of the section within the COFF file. For executable images, this must be a multiple of FileAlignment from the optional header. For object files, the value should be aligned on a 4-byte boundary for best performance. When a section contains only uninitialized data, this field should be zero.
	uint8_t PointerToRelocations; // The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
	uint8_t PointerToLinenumbers; // The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF debugging information is deprecated.
	uint8_t NumberOfRelocations; // The number of relocation entries for the section. This is set to zero for executable images.
	uint8_t NumberOfLinenumbers; // The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated.
	uint8_t Characteristics; // The flags that describe the characteristics of the section. For more information, see Section Flags.
};
static const struct PE_Section_Header_Offsets PESectionHeaderOffsets = {
	.Name = 0, // char[8]
	.VirtualSize = 8, // uint32_t
	.VirtualAddress = 12, // uint32_t
	.SizeOfRawData = 16, // uint32_t
	.PointerToRawData = 20, // uint32_t
	.PointerToRelocations = 24, // uint32_t
	.PointerToLinenumbers = 28, // uint32_t
	.NumberOfRelocations = 32, // uint16_t
	.NumberOfLinenumbers = 34, // uint16_t
	.Characteristics = 36, // uint32_t
};

struct PE_Image_Import_Descriptor_Offsets {
	uint8_t Union;
	uint8_t TimeDateStamp;                  // 0 if not bound,
	uint8_t ForwarderChain;                 // -1 if no forwarders
	uint8_t Name;
	uint8_t FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
};

static const struct PE_Image_Import_Descriptor_Offsets PEImageImportDescriptorOffsets = {
	.Union = 0,
	.TimeDateStamp = 4,
	.ForwarderChain = 8,
	.Name = 12,
	.FirstThunk = 16,
};

struct PE_Image_Thunk_Data_32_Offsets {
	uint8_t u1;
};

static const struct PE_Image_Thunk_Data_32_Offsets PEImageThunkData32Offsets = {
	.u1 = 0
};

struct PE_Image_Thunk_Data_64_Offsets {
	uint8_t u1;
};

static const struct PE_Image_Thunk_Data_64_Offsets PEImageThunkData64Offsets = {
	.u1 = 0
};

struct PE_Image_Import_By_Name_Offsets {
	uint8_t Hint;
	uint8_t Name;
};

static const struct PE_Image_Import_By_Name_Offsets PEImageImportByNameOffsets = {
	.Hint = 0,
	.Name = 2
};
 
struct Pe_Image_Delay_Import_Descriptor_Offsets {
	uint8_t grAttrs;
	uint8_t szName;
	uint8_t phmod;
	uint8_t pIAT;
	uint8_t pINT;
	uint8_t pBoundIAT;
	uint8_t pUnloadIAT;
	uint8_t dwTimeStamp;
};

static const struct Pe_Image_Delay_Import_Descriptor_Offsets PeImageDelayImportDescriptorOffsets = {
	.grAttrs = 0,
	.szName = 4,
	.phmod = 8,
	.pIAT = 12,
	.pINT = 16,
	.pBoundIAT = 20,
	.pUnloadIAT = 24,
	.dwTimeStamp = 28,
};

struct Pe_Image_Export_Directory_Offsets {
	uint8_t Characteristics;
	uint8_t TimeDateStamp;
	uint8_t MajorVersion;
	uint8_t MinorVersion;
	uint8_t Name;
	uint8_t Base;
	uint8_t NumberOfFunctions;
	uint8_t NumberOfNames;
	uint8_t AddressOfFunctions;
	uint8_t AddressOfNames;
	uint8_t AddressOfNameOrdinals;
};

static const struct Pe_Image_Export_Directory_Offsets PeImageExportDirectoryOffsets = {
	.Characteristics = 0,
	.TimeDateStamp = 4,
	.MajorVersion = 8,
	.MinorVersion = 10,
	.Name = 12,
	.Base = 16,
	.NumberOfFunctions = 20,
	.NumberOfNames = 24,
	.AddressOfFunctions = 28,
	.AddressOfNames = 32,
	.AddressOfNameOrdinals = 36
};

struct Pe_Attribute_Certificate_Table_Offsets {
	uint8_t dwLength; // Specifies the length of the attribute certificate entry.
	uint8_t wRevision; // Contains the certificate version number. For details, see the following text.
	uint8_t wCertificateType; // Specifies the type of content in bCertificate. For details, see the following text.
	uint8_t bCertificate; // Contains a certificate, such as an Authenticode signature. For details, see the following text.
};

static const struct Pe_Attribute_Certificate_Table_Offsets PeAttributeCertificateTableOffsets = {
	0,
	4,
	6,
	8
};

struct Pe_Image_Resource_Directory_Entry_Offsets {
	uint8_t Name;
	uint8_t OffsetToData;
};
struct Pe_Image_Resource_Directory_Entry_Offsets PeImageResourceDirectoryEntryOffsets = {
	.Name = 0,
	.OffsetToData = 4
};

struct Pe_Image_Resource_Directory_Offsets {
	uint8_t Characteristics;
	uint8_t TimeDateStamp;
	uint8_t MajorVersion;
	uint8_t MinorVersion;
	uint8_t NumberOfNamedEntries;
	uint8_t NumberOfIdEntries;
//	uint8_t DirectoryEntries;
};

struct Pe_Image_Resource_Directory_Offsets PeImageResourceDirectoryOffsets = {
	.Characteristics = 0,
	.TimeDateStamp = 4,
	.MajorVersion = 8,
	.MinorVersion = 10,
	.NumberOfNamedEntries = 12,
	.NumberOfIdEntries = 14
//	.DirectoryEntries = 16
};

struct Pe_Image_Resource_Dir_String_U_Offsets {
	uint8_t Length;
	uint8_t NameString;
};

struct Pe_Image_Resource_Dir_String_U_Offsets PeImageResourceDirStringUOffsets = {
	.Length = 0,
	.NameString = 2
};

struct Pe_Image_Resource_Data_Entry_Offsets {
	uint8_t OffsetToData;
	uint8_t Size;
	uint8_t CodePage;
	uint8_t Reserved;
};

struct Pe_Image_Resource_Data_Entry_Offsets PeImageResourceDataEntryOffsets = {
	.OffsetToData = 0,
	.Size = 4,
	.CodePage = 8,
	.Reserved = 12
};

#endif
