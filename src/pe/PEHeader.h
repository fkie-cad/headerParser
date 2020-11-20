#ifndef HEADER_PARSER_PE_HEADER_H
#define HEADER_PARSER_PE_HEADER_H

#include <stdint.h>
#include <wchar.h>

const unsigned char MAGIC_PE_BYTES[2] = { 0x4D, 0x5A };
const unsigned char MAGIC_PE_SIGNATURE[4] = { 0x50, 0x45, 0x00, 0x00 };
const unsigned char MAGIC_NE_SIGNATURE[2] = { 0x4E, 0x45 };
const unsigned char MAGIC_LE_SIGNATURE[2] = { 0x4C, 0x45 };
const unsigned char MAGIC_LX_SIGNATURE[2] = { 0x4C, 0x58 };
//const unsigned char MAGIC_NE_SIGNATURE[4] = { 0x4E, 0x45, 0x05, 0x3C };
//const unsigned char MAGIC_NE_SIGNATURE[4] = { 0x4E, 0x45, 0x06, 0x01 };
const unsigned char MAGIC_DOS_STUB_BEGINNING[] = { 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21 };
const uint8_t MAGIC_DOS_STUB_BEGINNING_LN = 9;

uint8_t PE_DOS_STUB_OFFSET = 0x45;

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#endif
#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32 0x80000000
#endif

enum PEHeaderSizes {
	MAGIC_PE_BYTES_LN=2,
	SIZE_OF_MAGIC_PE_SIGNATURE=4,
	SIZE_OF_MAGIC_NE_SIGNATURE=2,
	SIZE_OF_MAGIC_LE_SIGNATURE=2,
	SIZE_OF_MAGIC_LX_SIGNATURE=2,
	IMAGE_SIZEOF_SHORT_NAME=8,
	PE_RESOURCE_ENTRY_SIZE=8,
	PE_THUNK_DATA_32_SIZE=4,
	PE_THUNK_DATA_64_SIZE=8,
	NUMBER_OF_RVA_AND_SIZES=16,
	SIZE_OF_SYM_ENT=18,
	PE_IMPORT_DESCRIPTOR_SIZE = 20,
	PE_RESOURCE_DIRECTORY_SIZE = 16,
	PE_RESOURCE_DATA_ENTRY_SIZE = 16,
	PE_EXPORT_DIRECTORY_SIZE = 40,
	PE_SECTION_HEADER_SIZE=40
};

typedef struct PEImageDosHeader
{
	char signature[MAGIC_PE_BYTES_LN]; // = { 'M', 'Z' }
	uint16_t lastsize;
	uint16_t nblocks;
	uint16_t nreloc;
	uint16_t hdrsize;
	uint16_t minalloc;
	uint16_t maxalloc;
	uint16_t ss; // 2 byte value
	uint16_t sp; // 2 byte value
	uint16_t checksum;
	uint16_t ip; // 2 byte value
	uint16_t cs; // 2 byte value
	uint16_t relocpos;
	uint16_t noverlay;
	uint16_t reserved1[4];
	uint16_t oem_id;
	uint16_t oem_info;
	uint16_t reserved2[10];
	uint32_t e_lfanew; // Offset to the 'PE\0\0' signature relative to the beginning of the file
} PEImageDosHeader;

const uint8_t PE_COFF_FILE_HEADER_SIZE = 20;

typedef struct PECoffFileHeader
{
	uint16_t Machine; // The number that identifies the type of target machine. For more information, see Machine Types.
	uint16_t NumberOfSections; // The number of sections. This indicates the size of the section table, which immediately follows the headers.
	uint32_t TimeDateStamp; // The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.
	// The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
	// This value should be zero for an image because COFF debugging information is deprecated.
	uint32_t PointerToSymbolTable;
	// The number of entries in the symbol table.
	// This data can be used to locate the string table, which immediately follows the symbol table.
	// This value should be zero for an image because COFF debugging information is deprecated.
	// sizeof(Symbol) = 18
	uint32_t NumberOfSymbols;
	// The size of the optional header, which is required for executable files but not for object files.
	// This value should be zero for an object file.
	// For a description of the header format, see Optional Header (Image Only).
	uint16_t SizeOfOptionalHeader;
	// The flags that indicate the attributes of the file.
	// For specific flag values, see Characteristics.
	uint16_t Characteristics;
} PECoffFileHeader;

// COFF String Table
//
// Immediately following the COFF symbol table is the COFF string table.
// The position of this table is found by taking the symbol table address in the COFF header and adding the number of symbols multiplied by the size of a symbol.
//
// At the beginning of the COFF string table are 4 bytes that contain the total size (in bytes) of the rest of the string table.
// This size includes the size field itself, so that the value in this location would be 4 if no strings were present.
//
// Following the size are null-terminated strings that are pointed to by symbols in the COFF symbol table.
const uint32_t PE_STRING_TABLE_SIZE_INFO_SIZE = 4;

typedef struct pe_data_directory
{
	// VirtualAddress, is actually the RVA of the table. The
	// RVA is the address of the table relative to the base address of the image when the table is loaded.
	uint32_t VirtualAddress;
	// The size in bytes.
	uint32_t Size;
} PEDataDirectory;

enum ImageDirectoryEntries {
	IMAGE_DIRECTORY_ENTRY_EXPORT, // 0
	IMAGE_DIRECTORY_ENTRY_IMPORT, // 1
	IMAGE_DIRECTORY_ENTRY_RESOURCE, // 2
	IMAGE_DIRECTORY_ENTRY_EXCEPTION, // 3
	IMAGE_DIRECTORY_ENTRY_CERTIFICATE, // 4
	IMAGE_DIRECTORY_ENTRY_BASE_RELOC, // 5
	IMAGE_DIRECTORY_ENTRY_DEBUG, // 6
	IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, // 7
	IMAGE_DIRECTORY_ENTRY_GLOBAL_PTR, // 8
	IMAGE_DIRECTORY_ENTRY_TLS, // 9
	IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, // 10
	IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, // 11
	IMAGE_DIRECTORY_ENTRY_IAT, // 12
	IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, // 13
	IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME_HEADER, // 14
	IMAGE_DIRECTORY_ENTRY_RESERVED, // 15
};

/**
 * 64 bit version of the PE Optional Header also known as IMAGE_OPTIONAL_HEADER64
 */
typedef struct PE64OptHeader
{
	uint16_t Magic;
	char MajorLinkerVersion;
	char MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;  //The RVA of the code entry point
	// The address that is relative to the image base of the beginning-of-code section when it is loaded into memory
	uint32_t BaseOfCode;
	uint32_t BaseOfData; // 32 bit specific,
	// The next 21 fields are an extension to the COFF optional header format
	// The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K.
	// The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000.
	// The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOSVersion;
	uint16_t MinorOSVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	//	The size of the PE header and the section (object) table.
	//	The raw data for the sections starts immediately after all the header component
	uint32_t SizeOfHeaders;
	uint32_t Checksum;
	uint16_t Subsystem;
	uint16_t DLLCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	// Can have any number of elements, matching the number in NumberOfRvaAndSizes.
	// However, it is always 16 in (normal) PE files.
	PEDataDirectory* DataDirectory;
} PE64OptHeader;

/*
 * 32 bit version of the PE Optional Header also known as IMAGE_OPTIONAL_HEADER
*/
typedef struct PE32OptHeader
{
	uint16_t Magic; //decimal number 267 => 32 bit, 523 => 64 bit, and 263 =>ROM image.
	char MajorLinkerVersion;
	char MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;  //The RVA of the code entry point
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	/*The next 21 fields are an extension to the COFF optional header format*/
	uint32_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOSVersion;
	uint16_t MinorOSVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t Checksum;
	uint16_t Subsystem;
	uint16_t DLLCharacteristics;
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	PEDataDirectory* DataDirectory;
} PE32OptHeader;

typedef struct PEImageSectionHeader
{
	// An 8-byte, null-padded UTF-8 encoded string.
	// If the string is exactly 8 characters long, there is no terminating null.
	// For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table.
	// Executable images do not use a string table and do not support section names longer than 8 characters.
	// Long names in object files are truncated if they are emitted to an executable file.
	char Name[IMAGE_SIZEOF_SHORT_NAME];
	// The total size of the section when loaded into memory.
	// If this value is greater than SizeOfRawData, the section is zero-padded.
	// This field is valid only for executable images and should be set to zero for object files.
	union {
//		For OBJ files, this field indicates the physical address of the section.
//		To find the physical address in an OBJ file of the next section, add the SizeOfRawData value to the physical address of the current section.
		uint32_t PhysicalAddress;
		uint32_t VirtualSize;
	} Misc;
	// For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory.
	// For object files, this field is the address of the first byte before relocation is applied;
	// for simplicity, compilers should set this to zero.
	// Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
	uint32_t VirtualAddress;
	// The size of the section (for object files) or the size of the initialized data on disk (for image files).
	// For executable images, this must be a multiple of FileAlignment from the optional header.
	// If this is less than VirtualSize, the remainder of the section is zero-filled.
	// Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well.
	// When a section contains only uninitialized data, this field should be zero.
	uint32_t SizeOfRawData;
	// The file pointer to the first page of the section within the COFF file.
	// For executable images, this must be a multiple of FileAlignment from the optional header.
	// For object files, the value should be aligned on a 4-byte boundary for best performance.
	// When a section contains only uninitialized data, this field should be zero.
	uint32_t PointerToRawData;
	// The file pointer to the beginning of relocation entries for the section.
	// This is set to zero for executable images or if there are no relocations.
	uint32_t PointerToRelocations;
	// The file pointer to the beginning of line-number entries for the section.
	// This is set to zero if there are no COFF line numbers.
	// This value should be zero for an image because COFF debugging information is deprecated.
	uint32_t PointerToLinenumbers;
	// The number of relocation entries for the section.
	// This is set to zero for executable images.
	uint16_t NumberOfRelocations;
	// The number of line-number entries for the section.
	// This value should be zero for an image because COFF debugging information is deprecated.
	uint16_t NumberOfLinenumbers;
	// The flags that describe the characteristics of the section. For more information, see Section Characteristics Flags.
	uint32_t Characteristics;
} PEImageSectionHeader;

typedef struct PEImageImportDescriptor {
	union {
		uint32_t Characteristics;            // 0 for terminating null import descriptor
		uint32_t OriginalFirstThunk;         // RVA to original unbound INT (Import Name Table) (an Array of PIMAGE_THUNK_DATA)
	};
	uint32_t TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)
	uint32_t ForwarderChain;                 // -1 if no forwarders
	uint32_t Name;							// RVA to the name of the module. I.e  xxx.dll
	uint32_t FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} PEImageImportDescriptor;

typedef struct PEImageThunkData32 {
	union {
		uint32_t ForwarderString;      // PBYTE 
		uint32_t Function;             // Puint32_t
		uint32_t Ordinal;
		uint32_t AddressOfData;        // PIMAGE_IMPORT_BY_NAME
	};
} PEImageThunkData32;

typedef struct PEImageThunkData64 {
	union {
		uint64_t ForwarderString;  // PBYTE 
		uint64_t Function;         // Puint64_t
		uint64_t Ordinal;          // uint16_t number
		uint64_t AddressOfData;    // RVA to PIMAGE_IMPORT_BY_NAME
	};
} PEImageThunkData64;

typedef struct PEImageImportByName {
	uint16_t Hint;
	char* Name; // NULL terminated ASCII string following the Hint.
//	char Name[1];
} PEImageImportByName;

// _IMAGE_DELAY_IMPORT_DESCRIPTOR
typedef struct PeImageDelayImportDescriptor {
	uint32_t grAttrs;
	uint32_t szName;
	uint32_t phmod;
	uint32_t pIAT;
	uint32_t pINT;
	uint32_t pBoundIAT;
	uint32_t pUnloadIAT;
	uint32_t dwTimeStamp;
} PeImageDelayImportDescriptor;

typedef struct PE_IMAGE_EXPORT_DIRECTORY
{
	// This field appears to be unused and is always set to 0.
	uint32_t Characteristics;
	// The time/date stamp indicating when this file was created.
	uint32_t TimeDateStamp;
	// These fields appear to be unused and are set to 0.
	uint16_t MajorVersion;
	uint16_t MinorVersion;
	// The RVA of an ASCIIZ string with the name of this DLL.
	uint32_t Name;
	// The starting ordinal number for exported functions.
	// For example, if the file exports functions with ordinal values of 10, 11, and 12, this field contains 10.
	// To obtain the exported ordinal for a function,
	// you need to add this value to the appropriate element of the AddressOfNameOrdinals array.
	uint32_t Base;
	// The number of elements in the AddressOfFunctions array.
	// This value is also the number of functions exported by this module.
	// Theoretically, this value could be different than the NumberOfNames field (next), but actually they're always the same.
	uint32_t NumberOfFunctions;
	// The number of elements in the AddressOfNames array.
	// This value seems always to be identical to the NumberOfFunctions field, and so is the number of exported functions.
	uint32_t NumberOfNames;
	// This field is an RVA and points to an array of function addresses.
	// The function addresses are the entry points (RVAs) for each exported function in this module.
	uint32_t AddressOfFunctions;
	// This field is an RVA and points to an array of string pointers.
	// The strings are the names of the exported functions in this module.
	uint32_t AddressOfNames;
	// This field is an RVA and points to an array of WORDs.
	// The WORDs are the export ordinals of all the exported functions in this module.
	// However, don't forget to add in the starting ordinal number specified in the Base field.
	uint32_t AddressOfNameOrdinals;
} PE_IMAGE_EXPORT_DIRECTORY;
// The requirements for exporting a function are a name, an address, and an export ordinal.
// Not in a structure array of these structures.
// Instead, each component of an exported entry is an element in an array.
// There are three of these arrays (AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals),
// and they are all parallel to one another.

typedef struct PeAttributeCertificateTable {
	uint32_t dwLength; // Specifies the length of the attribute certificate entry.
	uint16_t wRevision; // Contains the certificate version number. For details, see the following text.
	uint16_t wCertificateType; // Specifies the type of content in bCertificate. For details, see the following text.
	unsigned char* bCertificate; // Contains a certificate, such as an Authenticode signature. The headerParser uses this as a file offset pointer to the location of the certificate.
} PeAttributeCertificateTable;

// Subsequent entries are accessed by advancing that entry's dwLength bytes,
// rounded up to an 8-byte multiple, from the start of the current attribute certificate entry.
// This continues until the sum of the rounded dwLength values equals the Size value from the Certificates Table entry in the Optional Header Data Directory.
// If the sum of the rounded dwLength values does not equal the Size value, t
// then either the attribute certificate table or the Size field is corrupted.

#define WIN_CERT_REVISION_1_0 (0x0100) // Version 1, legacy version of the Win_Certificate structure. It is supported only for purposes of verifying legacy Authenticode signatures
#define WIN_CERT_REVISION_2_0 (0x0200) // Version 2 is the current version of the Win_Certificate structure.

#define WIN_CERT_TYPE_X509 (0x0001) // bCertificate contains an X.509 Certificate. Not Supported
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002) // bCertificate contains a PKCS#7 SignedData structure
#define WIN_CERT_TYPE_RESERVED_1 (0x0003) //  Reserved
#define WIN_CERT_TYPE_TS_STACK_SIGNED (0x0004) // Terminal Server Protocol Stack Certificate signing. Not Supported

typedef struct PE_IMAGE_RESOURCE_DIRECTORY_ENTRY {
//	This field contains either an integer ID or a pointer to a structure that contains a string name.
//	If the high bit (0x80000000) is zero, this field is interpreted as an integer ID.
//	If the high bit is nonzero, the lower 31 bits are an offset (relative to the start of the resources) to an IMAGE_RESOURCE_DIR_STRING_U structure.
//	This structure contains a WORD character count, followed by a UNICODE string with the resource name.
	union {
		struct {
			uint32_t NameOffset:31;
			uint32_t NameIsString:1;
		} NAME_STRUCT;
		uint32_t Name;
		uint16_t Id;
	} NAME_UNION;
//	uint32_t Name;
//	This field is either an offset to another resource directory or a pointer to information about a specific resource instance.
//	If the high bit (0x80000000) is set, this directory entry refers to a subdirectory.
//	The lower 31 bits are an offset (relative to the start of the resources) to another	IMAGE_RESOURCE_DIRECTORY.
//	If the high bit isn't set, the lower 31 bits point to an IMAGE_RESOURCE_DATA_ENTRY structure.
//	The IMAGE_RESOURCE_DATA_ENTRY structure contains the location of the resource's raw data, its size, and its code page.
	union {
		uint32_t OffsetToData;
		struct {
			uint32_t OffsetToDirectory:31;
			uint32_t DataIsDirectory:1;
		} DATA_STRUCT;
	} OFFSET_UNION;
//	uint32_t OffsetToData;
} PE_IMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef struct PE_IMAGE_RESOURCE_DIRECTORY {
//	Theoretically this field could hold flags for the resource, but appears to always to be 0.
	uint32_t Characteristics;
//	The time/date stamp describing the creation time of the resource.
	uint32_t TimeDateStamp;
//	Theoretically these fields would hold a version number for the resource. These field appear to always be set to 0.
	uint16_t MajorVersion;
	uint16_t MinorVersion;
//	The number of array elements that use names and that follow this structure.
	uint16_t NumberOfNamedEntries;
//	The number of array elements that use integer IDs, and which follow this structure.
	uint16_t NumberOfIdEntries;
//	This field isn't really part of the IMAGE_RESOURCE_DIRECTORY structure.
//	Rather, it's an array of IMAGE_RESOURCE_DIRECTORY_ENTRY structures that immediately follow the IMAGE_RESOURCE_DIRECTORY structure.
//	The number of elements in the array is the sum of the NumberOfNamedEntries and NumberOfIdEntries fields.
//	The directory entry elements that have name identifiers (rather than integer IDs) come first in the array.
//	A directory entry can either point at a subdirectory
//	(that is, to another IMAGE_RESOURCE_DIRECTORY),
//	or it can point to the raw data for a resource.
//	PE_IMAGE_RESOURCE_DIRECTORY_ENTRY DirectoryEntries[1];
} PE_IMAGE_RESOURCE_DIRECTORY;

// the resource's name ascii
typedef struct PE_IMAGE_RESOURCE_DIR_STRING {
	uint16_t Length;
	char NameString[1];
} PE_IMAGE_RESOURCE_DIR_STRING;

// the resource's name unicode
typedef struct PE_IMAGE_RESOURCE_DIR_STRING_U {
	uint16_t Length;
	wchar_t NameString[1];
} PE_IMAGE_RESOURCE_DIR_STRING_U;

typedef struct PE_IMAGE_RESOURCE_DIR_STRING_U_PTR {
	uint16_t Length;
	uint16_t* NameString; // size(wchar_t) is not portable, and window unicode uses 2-bytes, gcc 64-bit linux uses 4 bytes
} PE_IMAGE_RESOURCE_DIR_STRING_U_PTR;

// contains the location of the resource's raw data, its size, and its code page
typedef struct PE_IMAGE_RESOURCE_DATA_ENTRY {
	uint32_t OffsetToData;
	uint32_t Size;
	uint32_t CodePage;
	uint32_t Reserved;
} PE_IMAGE_RESOURCE_DATA_ENTRY;

typedef struct PE_BASE_RELOCATION_BLOCK {
	// This field contains the starting RVA for this chunk of relocations. 
	// The offset of each relocation that follows is added to this value to form the actual RVA where the relocation needs to be applied.
	uint32_t VirtualAddress;
	// The size of this structure plus all the WORD relocations that follow. 
	// To determine the number of relocations in this block, subtract the size of an IMAGE_BASE_RELOCATION(8 bytes) from the value of this field, and then divide by 2 (the size of a WORD)
	uint32_t SizeOfBlock;
} PE_BASE_RELOCATION_BLOCK;

typedef struct PE_BASE_RELOCATION_ENTRY {
	union {
		// Bit fields don't work properly => use bit shifftig. 
		//union {
		//	// The bottom 12 bits of each WORD are a relocation offset, 
		//	// and need to be added to the value of the Virtual Address field from this relocation block's header.
		//	uint16_t Offset : 12;
		//	uint16_t Type : 4;
		//};
		uint16_t Data;
	};
} PE_BASE_RELOCATION_ENTRY;

#define PE_IMAGE_REL_BASED_ABSOLUTE (0) // The base relocation is skipped. This type can be used to pad a block.
#define PE_IMAGE_REL_BASED_HIGH (1) // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
#define PE_IMAGE_REL_BASED_LOW (2) // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
#define PE_IMAGE_REL_BASED_HIGHLOW (3) // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
#define PE_IMAGE_REL_BASED_HIGHADJ (4) // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots.
#define PE_IMAGE_REL_BASED_MIPS_JMPADDR (5) // The relocation interpretation is dependent on the machine type. When the machine type is MIPS, the base relocation applies to a MIPS jump instruction.
#define PE_IMAGE_REL_BASED_ARM_MOV32 (5) // This relocation is meaningful only when the machine type is ARM or Thumb. The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair.
#define PE_IMAGE_REL_BASED_RISCV_HIGH20 (5) // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address.
#define PE_IMAGE_REL_BASED_RESERVED (6) // Reserved, must be zero.
#define PE_IMAGE_REL_BASED_THUMB_MOV32 (7) // This relocation is meaningful only when the machine type is Thumb. The base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
#define PE_IMAGE_REL_BASED_RISCV_LOW12I (7) // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format.
#define PE_IMAGE_REL_BASED_RISCV_LOW12S (8) // This relocation is only meaningful when the machine type is RISC-V. The base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format.
#define PE_IMAGE_REL_BASED_MIPS_JMPADDR16 (9) // The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction.
#define PE_IMAGE_REL_BASED_DIR64 (10) // The base relocation applies the difference to the 64-bit field at offset.

// custom

typedef struct StringTable {
	unsigned char *strings;
	uint32_t size;
} StringTable, *PStringTable;

typedef struct SVAS {
	uint32_t VirtualAddress;
	uint32_t VirtualSize;
	uint32_t PointerToRawData;
	uint32_t SizeOfRawData;
} SVAS;

#endif
