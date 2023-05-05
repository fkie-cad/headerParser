#ifndef HEADER_PARSER_PE_HEADER_H
#define HEADER_PARSER_PE_HEADER_H

#ifdef _WIN32
#pragma warning(disable: 4201)                  // nonstandard extension used : nameless struct/union
#endif

#include <stdint.h>
#include <wchar.h>


#define MAGIC_PE_ARCHIV_BYTES_LN (7)
extern const uint8_t MAGIC_PE_ARCHIV_BYTES[MAGIC_PE_ARCHIV_BYTES_LN];

#define MAGIC_PE_BYTES_LN (2)
extern const uint8_t MAGIC_PE_BYTES[MAGIC_PE_BYTES_LN];

#define MAGIC_PE_SIGNATURE_LN (4)
extern const uint8_t MAGIC_PE_SIGNATURE[MAGIC_PE_SIGNATURE_LN];

#define MAGIC_NE_SIGNATURE_LN (2)
extern const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN];

#define MAGIC_LE_SIGNATURE_LN (2)
extern const uint8_t MAGIC_LE_SIGNATURE[MAGIC_LE_SIGNATURE_LN];

#define MAGIC_LX_SIGNATURE_LN (2)
extern const uint8_t MAGIC_LX_SIGNATURE[MAGIC_LX_SIGNATURE_LN];

//#define MAGIC_NE_SIGNATURE_LN (4)
//extern const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN];

//#define MAGIC_NE_SIGNATURE_LN (4)
//extern const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN];

#define MAGIC_DOS_STUB_BEGINNING_LN (9)
extern const uint8_t MAGIC_DOS_STUB_BEGINNING[MAGIC_DOS_STUB_BEGINNING_LN];

#define PE_DOS_STUB_OFFSET (0x45)

#ifndef IMAGE_ORDINAL_FLAG64
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#endif
#ifndef IMAGE_ORDINAL_FLAG32
#define IMAGE_ORDINAL_FLAG32 0x80000000
#endif

enum PEHeaderSizes {
    //MAGIC_PE_BYTES_LN=2,
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
    PE_DELAY_IMPORT_DESCRIPTOR_SIZE = 32,
    PE_BOUND_IMPORT_DESCRIPTOR_SIZE = 8,
    PE_BOUND_FORWARDER_REF_SIZE = 8,
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

#define PE_COFF_FILE_HEADER_SIZE (20)

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
#define PE_STRING_TABLE_SIZE_INFO_SIZE (4)

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

#define IMAGE_DIRECTORY_ENTRY_NAMES_LN (0x10)
extern const char* ImageDirectoryEntryNames[IMAGE_DIRECTORY_ENTRY_NAMES_LN];

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
    // 0 if not bound,
    // -1 if bound, and real date\time stamp is found in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
    // O.W. date/time stamp of DLL bound to (Old BIND)
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;                // -1 if no forwarders
    uint32_t Name;							// RVA to the name of the module. I.e  xxx.dll
    uint32_t FirstThunk;                    // RVA to IAT (if bound this IAT has actual addresses)
} PEImageImportDescriptor;

typedef struct PEImageThunkData32 {
    union {
        uint32_t ForwarderString;      // PBYTE 
        uint32_t Function;             // Puint32_t
        uint32_t Ordinal;              // uint16_t number
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
typedef struct PeImageDelayLoadDescriptor {
    union {
        uint32_t AllAttributes;
        struct {
            uint32_t RvaBased : 1;             // Delay load version 2
            uint32_t ReservedAttributes : 31;
        } DUMMYSTRUCTNAME;
    } Attributes;

    uint32_t DllNameRVA;                       // RVA to the name of the target library (NULL-terminate ASCII string). The name resides in the read - only data section of the image.
    uint32_t ModuleHandleRVA;                  // RVA to the HMODULE caching location (PHMODULE). (In the data section of the image) of the DLL to be delay-loaded. It is used for storage by the routine that is supplied to manage delay-loading.
    uint32_t ImportAddressTableRVA;            // RVA to the start of the IAT (PIMAGE_THUNK_DATA)
    uint32_t ImportNameTableRVA;               // RVA to the start of the name table (PIMAGE_THUNK_DATA::AddressOfData). This matches the layout of the import name table.
    uint32_t BoundImportAddressTableRVA;       // RVA to an optional bound IAT. The default linker behavior is to create a bindable import address table for the delay-loaded DLL. If the DLL is bound, the helper function will attempt to use the bound information instead of calling GetProcAddress on each of the referenced imports. If either the timestamp or the preferred address do not match those of the loaded DLL, the helper function will assume the bound import address table is out of date and will proceed as if it does not exist
    uint32_t UnloadInformationTableRVA;        // RVA to an optional unload info table. This is an exact copy of the delay import address table. If the caller unloads the DLL, this table should be copied back over the delay import address table so that subsequent calls to the DLL continue to use the thunking mechanism correctly.
    uint32_t TimeDateStamp;                    // 0 if not bound, Otherwise, date/time of the target DLL.
} PeImageDelayLoadDescriptor;




typedef struct PE_IMAGE_BOUND_IMPORT_DESCRIPTOR {
    uint32_t TimeDateStamp;
    uint16_t OffsetModuleName;
    uint16_t NumberOfModuleForwarderRefs;
    // Array of zero or more IMAGE_BOUND_FORWARDER_REF follows
} PE_IMAGE_BOUND_IMPORT_DESCRIPTOR, * PPE_IMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct PE_IMAGE_BOUND_FORWARDER_REF {
    uint32_t TimeDateStamp;
    uint16_t OffsetModuleName;
    uint16_t Reserved;
} PE_IMAGE_BOUND_FORWARDER_REF, * PPE_IMAGE_BOUND_FORWARDER_REF;




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
    // This value can be different than the NumberOfNames field (i.e. ntoskrnl.exe). Mostly they're the same, though.
    uint32_t NumberOfFunctions;
    // The number of elements in the AddressOfNames array.
    uint32_t NumberOfNames;
    // The address of the export address table, relative to the image base.
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

// Each entry in the export address table is a field that uses one of two formats in the following table.
// If the address specified is not within the export section(as defined by the address and length that are indicated in the optional header), 
// the field is an export RVA, which is an actual address in code or data.
// Otherwise, the field is a forwarder RVA, which names a symbol in another DLL.
typedef struct PE_EXPORT_ADDRESS_TABLE_ENTRY
{
    union {
        // The address of the exported symbol when loaded into memory, relative to the image base.
        uint32_t ExportRva;
        // The pointer to a null - terminated ASCII string in the export section.
        // This string must be within the range that is given by the export table data directory entry.
        // This string gives the DLL name and the name of the export (for example, "MYDLL.expfunc") or the DLL name and the ordinal number of the export (for example, "MYDLL.#27").
        uint32_t ForwarderRva;
    } rva;
} PE_EXPORT_ADDRESS_TABLE_ENTRY, *PPE_EXPORT_ADDRESS_TABLE_ENTRY;



typedef struct PeAttributeCertificateTable {
    uint32_t dwLength; // Specifies the length of the attribute certificate entry.
    uint16_t wRevision; // Contains the certificate version number. For details, see the following text.
    uint16_t wCertificateType; // Specifies the type of content in bCertificate. For details, see the following text.
    uint8_t* bCertificate; // Contains a certificate, such as an Authenticode signature. The headerParser uses this as a file offset pointer to the location of the certificate.
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




// Resources Layout
// Resource Directory Tables(and Resource Directory Entries)
// A series of tables, one for each group of nodes in the tree.All top - level(Type) nodes are listed in the first table.Entries in this table point to second - level tables.Each second - level tree has the same Type ID but different Name IDs.Third - level trees have the same Type and Name IDs but different Language IDs.
// Each individual table is immediately followed by directory entries, in which each entry has a name or numeric identifier and a pointer to a data description or a table at the next lower level.
// Resource Directory Strings
// Two - byte - aligned Unicode strings, which serve as string data that is pointed to by directory entries.
// Resource Data Description
// An array of records, pointed to by tables, that describe the actual sizeand location of the resource data.These records are the leaves in the resource - description tree.
// Resource Data
// Raw data of the resource section.The size and location information in the Resource Data Descriptions field delimit the individual regions of resource data.

typedef struct PE_IMAGE_RESOURCE_DIRECTORY_ENTRY {
//	This field contains either an integer ID or a pointer to a structure that contains a string name.
//	If the high bit (0x80000000) is zero, this field is interpreted as an integer ID.
//	If the high bit is nonzero, the lower 31 bits are an offset (relative to the start of the resources) to an IMAGE_RESOURCE_DIR_STRING_U structure.
//	This structure contains a uint16_t character count, followed by a UNICODE string with the resource name.
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
    // The size of this structure plus all the uint16_t relocations that follow. 
    // To determine the number of relocations in this block, subtract the size of an IMAGE_BASE_RELOCATION(8 bytes) from the value of this field, and then divide by 2 (the size of a uint16_t)
    uint32_t SizeOfBlock;
} PE_BASE_RELOCATION_BLOCK;

typedef struct PE_BASE_RELOCATION_ENTRY {
    union {
        //union {
        //	uint16_t AllData;
        //	struct {
        //		uint16_t Offset : 12;
        //		uint16_t Type : 4;
        //	} DATA_STRUCT;
        //} Data;
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





typedef struct PE_IMAGE_TLS_DIRECTORY32 {
    uint32_t StartAddressOfRawData;
    uint32_t EndAddressOfRawData;
    uint32_t AddressOfIndex;             // PDWORD
    uint32_t AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    uint32_t SizeOfZeroFill;
    union {
        uint32_t Characteristics;
        struct {
            uint32_t Reserved0 : 20;
            uint32_t Alignment : 4;
            uint32_t Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PE_IMAGE_TLS_DIRECTORY32, * PPE_IMAGE_TLS_DIRECTORY32;
#define PE_IMAGE_TLS_DIRECTORY32_SIZE (sizeof(PE_IMAGE_TLS_DIRECTORY32))

typedef struct PE_IMAGE_TLS_DIRECTORY64 {
    uint64_t StartAddressOfRawData; // The starting address of the TLS template. The template is a block of data that is used to initialize TLS data. The system copies all of this data each time a thread is created, so it must not be corrupted. Note that this address is not an RVA; it is an address for which there should be a base relocation in the .reloc section.
    uint64_t EndAddressOfRawData; // The address of the last byte of the TLS, except for the zero fill. As with the Raw Data Start VA field, this is a VA, not an RVA.
    uint64_t AddressOfIndex; // PDWORD The location to receive the TLS index, which the loader assigns. This location is in an ordinary data section, so it can be given a symbolic name that is accessible to the program.
    uint64_t AddressOfCallBacks; // PIMAGE_TLS_CALLBACK *; The pointer to an array of TLS callback functions. The array is null-terminated, so if no callback function is supported, this field points to 4 bytes set to zero. For 
    uint32_t SizeOfZeroFill; // The size in bytes of the template, beyond the initialized data delimited by the Raw Data Start VA and Raw Data End VA fields. The total template size should be the same as the total size of TLS data in the image file. The zero fill is the amount of data that comes after the initialized nonzero data.
    union {
        uint32_t Characteristics; // The four bits [23:20] describe alignment info. Possible values are those defined as IMAGE_SCN_ALIGN_*, which are also used to describe alignment of section in object files. The other 28 bits are reserved for future use.
        struct {
            uint32_t Reserved0 : 20;
            uint32_t Alignment : 4;
            uint32_t Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
} PE_IMAGE_TLS_DIRECTORY64, * PPE_IMAGE_TLS_DIRECTORY64;
#define PE_IMAGE_TLS_DIRECTORY64_SIZE (sizeof(PE_IMAGE_TLS_DIRECTORY64))

//typedef VOID
//(NTAPI* PIMAGE_TLS_CALLBACK) (
//	PVOID DllHandle,
//	uint32_t Reason,
//	PVOID Reserved
//	);


// Load Configuration Layout
typedef struct PE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY {
    uint16_t Flags;          // Flags to indicate if CI information is available, etc.
    uint16_t Catalog;        // 0xFFFF means not available
    uint32_t CatalogOffset;
    uint32_t Reserved;       // Additional bitmask to be defined later
} PE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY, * PPE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY;

typedef struct PE_IMAGE_LOAD_CONFIG_DIRECTORY32 {
    uint32_t Size; // (Flags that indicate attributes of the file, currently unused.)
    uint32_t TimeDateStamp; // Date and time stamp value.The value is represented in the number of seconds that have elapsed since midnight(00:00 : 00), January 1, 1970, Universal Coordinated Time, according to the system clock.The time stamp can be printed by using the C runtime(CRT) time function.
    uint16_t MajorVersion; // Major version number.
    uint16_t MinorVersion; // Minor version number.
    uint32_t GlobalFlagsClear; // The global loader flags to clear for this process as the loader starts the process.
    uint32_t GlobalFlagsSet; // The global loader flags to set for this process as the loader starts the process.
    uint32_t CriticalSectionDefaultTimeout; // The default timeout value to use for this process's critical sections that are abandoned.
    uint32_t DeCommitFreeBlockThreshold; // Memory that must be freed before it is returned to the system, in bytes.
    uint32_t DeCommitTotalFreeThreshold; // Total amount of free memory, in bytes.
    uint32_t LockPrefixTable;                // VA [x86 only] The VA of a list of addresses where the LOCK prefix is used so that they can be replaced with NOP on single processor machines.
    uint32_t MaximumAllocationSize; // Maximum allocation size, in bytes.
    uint32_t VirtualMemoryThreshold; // Maximum virtual memory size, in bytes.
    uint32_t ProcessAffinityMask; // Setting this field to a non - zero value is equivalent to calling SetProcessAffinityMask with this value during process startup(.exe only)
    uint32_t ProcessHeapFlags; // Process heap flags that correspond to the first argument of the HeapCreate function.These flags apply to the process heap that is created during process startup.
    uint16_t CSDVersion; // The service pack version identifier.
    uint16_t DependentLoadFlags; // 
    uint32_t EditList;                       // VA Reserved for use by the system.
    uint32_t SecurityCookie;                 // VA A pointer to a cookie that is used by Visual C++ or GS implementation.
    uint32_t SEHandlerTable;                 // VA [x86 only] The VA of the sorted table of RVAs of each valid, unique SE handler in the image.
    uint32_t SEHandlerCount;					// [x86 only] The count of unique handlers in the table.
    uint32_t GuardCFCheckFunctionPointer;    // The VA where Control Flow Guard check - function pointer is stored.
    uint32_t GuardCFDispatchFunctionPointer; // The VA where Control Flow Guard dispatch - function pointer is stored.
    uint32_t GuardCFFunctionTable;           // The VA of the sorted table of RVAs of each Control Flow Guard function in the image.
    uint32_t GuardCFFunctionCount; // The count of unique RVAs in the above table.
    uint32_t GuardFlags; // Control Flow Guard related flags.
    PE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity; // Code integrity information.
    uint32_t GuardAddressTakenIatEntryTable; // The VA where Control Flow Guard address taken IAT table is stored.
    uint32_t GuardAddressTakenIatEntryCount; // The count of unique RVAs in the above table.
    uint32_t GuardLongJumpTargetTable;       // VA where Control Flow Guard long jump target table is stored.
    uint32_t GuardLongJumpTargetCount;       // The count of unique RVAs in the above table.
    uint32_t DynamicValueRelocTable;         // VA
    uint32_t CHPEMetadataPointer; // 
    uint32_t GuardRFFailureRoutine;          // VA
    uint32_t GuardRFFailureRoutineFunctionPointer; // VA
    uint32_t DynamicValueRelocTableOffset; // 
    uint16_t DynamicValueRelocTableSection; // 
    uint16_t Reserved2; // 
    uint32_t GuardRFVerifyStackPointerFunctionPointer; // VA
    uint32_t HotPatchTableOffset; // 
    uint32_t Reserved3; // 
    uint32_t EnclaveConfigurationPointer;    // VA
    uint32_t VolatileMetadataPointer;        // 
    uint32_t GuardEHContinuationTable;       // VA 
    uint32_t GuardEHContinuationCount; // The count of unique RVAs in the above table.
} PE_IMAGE_LOAD_CONFIG_DIRECTORY32, * PPE_IMAGE_LOAD_CONFIG_DIRECTORY32;
#define PE_IMAGE_LOAD_CONFIG_DIRECTORY32_SIZE (sizeof(PE_IMAGE_LOAD_CONFIG_DIRECTORY32))


typedef struct PE_IMAGE_LOAD_CONFIG_DIRECTORY64 {
    uint32_t Size;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t GlobalFlagsClear;
    uint32_t GlobalFlagsSet;
    uint32_t CriticalSectionDefaultTimeout;
    uint64_t DeCommitFreeBlockThreshold;
    uint64_t DeCommitTotalFreeThreshold;
    uint64_t LockPrefixTable;                // VA
    uint64_t MaximumAllocationSize;
    uint64_t VirtualMemoryThreshold;
    uint64_t ProcessAffinityMask;
    uint32_t ProcessHeapFlags;
    uint16_t CSDVersion;
    uint16_t DependentLoadFlags;
    uint64_t EditList;                       // VA
    uint64_t SecurityCookie;                 // VA
    uint64_t SEHandlerTable;                 // VA
    uint64_t SEHandlerCount;
    uint64_t GuardCFCheckFunctionPointer;    // VA
    uint64_t GuardCFDispatchFunctionPointer; // VA
    uint64_t GuardCFFunctionTable;           // VA
    uint64_t GuardCFFunctionCount;
    uint32_t GuardFlags;
    PE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    uint64_t GuardAddressTakenIatEntryTable; // VA
    uint64_t GuardAddressTakenIatEntryCount;
    uint64_t GuardLongJumpTargetTable;       // VA
    uint64_t GuardLongJumpTargetCount;
    uint64_t DynamicValueRelocTable;         // VA
    uint64_t CHPEMetadataPointer;            // VA
    uint64_t GuardRFFailureRoutine;          // VA
    uint64_t GuardRFFailureRoutineFunctionPointer; // VA
    uint32_t DynamicValueRelocTableOffset;
    uint16_t DynamicValueRelocTableSection;
    uint16_t Reserved2;
    uint64_t GuardRFVerifyStackPointerFunctionPointer; // VA
    uint32_t HotPatchTableOffset;
    uint32_t Reserved3;
    uint64_t EnclaveConfigurationPointer;     // VA
    uint64_t VolatileMetadataPointer;         // VA
    uint64_t GuardEHContinuationTable;        // VA
    uint64_t GuardEHContinuationCount;
} PE_IMAGE_LOAD_CONFIG_DIRECTORY64, * PPE_IMAGE_LOAD_CONFIG_DIRECTORY64;
#define PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE (sizeof(PE_IMAGE_LOAD_CONFIG_DIRECTORY64))

// GuardFlags
#define PE_IMAGE_GUARD_CF_INSTRUMENTED                    0x00000100 // Module performs control flow integrity checks using system-supplied support
#define PE_IMAGE_GUARD_CFW_INSTRUMENTED                   0x00000200 // Module performs control flow and write integrity checks
#define PE_IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT          0x00000400 // Module contains valid control flow target metadata
#define PE_IMAGE_GUARD_SECURITY_COOKIE_UNUSED             0x00000800 // Module does not make use of the /GS security cookie
#define PE_IMAGE_GUARD_PROTECT_DELAYLOAD_IAT              0x00001000 // Module supports read only delay load IAT
#define PE_IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION   0x00002000 // Delayload import table in its own .didat section (with nothing else in it) that can be freely reprotected
#define PE_IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT 0x00004000 // Module contains suppressed export information. This also infers that the address taken
// taken IAT table is also present in the load config.
#define PE_IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION       0x00008000 // Module enables suppression of exports
#define PE_IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT          0x00010000 // Module contains longjmp target information
#define PE_IMAGE_GUARD_RF_INSTRUMENTED                    0x00020000 // Module contains return flow instrumentation and metadata
#define PE_IMAGE_GUARD_RF_ENABLE                          0x00040000 // Module requests that the OS enable return flow protection
#define PE_IMAGE_GUARD_RF_STRICT                          0x00080000 // Module requests that the OS enable return flow protection in strict mode
#define PE_IMAGE_GUARD_RETPOLINE_PRESENT                  0x00100000 // Module was built with retpoline support
#define PE_IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT      0x00200000 // Module contains EH continuation target information

#define PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK        0xF0000000 // Stride of Guard CF function table encoded in these bits (additional count of bytes per element)
#define PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT       28         // Shift to right-justify Guard CF function table stride

//
// GFIDS table entry flags.
//

#define PE_IMAGE_GUARD_FLAG_FID_SUPPRESSED               0x01       // The containing GFID entry is suppressed
#define PE_IMAGE_GUARD_FLAG_EXPORT_SUPPRESSED            0x02       // The containing GFID entry is export suppressed





typedef struct _PE_IMAGE_EXCEPTION_TABLE_ENTRY {
    uint32_t BeginAddress; // 32-bit MIPS, x64 and Itanium
    union {
        uint32_t EndAddress; // 32-bit MIPS, x64 and Itanium
        uint32_t Flags; // 32-bit MIPS, x64 and Itanium
        struct {  // ARM, PowerPC, SH3 and SH4 Windows CE
            uint32_t PrologLength : 8;
            uint32_t FunctionLength : 22;
            uint32_t BitFlag32 : 1;
            uint32_t ExceptionFlag : 1;
        };
    };
    union {
        uint32_t ExceptionHandler; // 32-bit MIPS
        uint32_t UnwindInformation; // x64 and Itanium, rva to UNWIND_INFO
    };
    uint32_t HandlerData; // 32-bit MIPS
    uint32_t PrologEndAddress; // 32-bit MIPS
} PE_IMAGE_EXCEPTION_TABLE_ENTRY, * PPE_IMAGE_EXCEPTION_TABLE_ENTRY;
#define PE_IMAGE_MIPS_EXCEPTION_TABLE_ENTRY_SIZE (5*sizeof(uint32_t))
#define PE_IMAGE_ARM_EXCEPTION_TABLE_ENTRY_SIZE (2*sizeof(uint32_t))
#define PE_IMAGE_X64_EXCEPTION_TABLE_ENTRY_SIZE (3*sizeof(uint32_t))

//For 32-bit MIPS images, function table entries have the following format:
//Offset	Size	Field	Description
//0 4 Begin Address - The VA of the corresponding function.
//4 4 End Address - The VA of the end of the function.
//8 4 Exception Handler - The pointer to the exception handler to be executed.
//12 4 Handler Data - The pointer to additional information to be passed to the handler.
//16 4 Prolog End Address - The VA of the end of the function's prolog.
// 
//
//For the ARM, PowerPC, SH3 and SH4 Windows CE platforms, function table entries have the following format:
//Offset	Size	Field	Description
//0 4 Begin Address - The VA of the corresponding function.
//4 8 bits - Prolog Length - The number of instructions in the function's prolog.
//    4 22 bits Function Length - The number of instructions in the function.
//    4 1 bit 32-bit Flag - If set, the function consists of 32-bit instructions. If clear, the function consists of 16-bit instructions.
//    4 1 bit Exception Flag - If set, an exception handler exists for the function. Otherwise, no exception handler exists.
// 
//
//For x64 and Itanium platforms, function table entries have the following format:
//Offset	Size	Field	Description
//0 4 Begin Address - The RVA of the corresponding function.
//4 4 End Address - The RVA of the end of the function.
//8 4 Unwind Information - The RVA of the unwind information.

// All addresses are image relative, that is, they're 32-bit offsets from the starting address of the image that contains the function table entry. 
// These entries are sorted, and put in the .pdata section of a PE32+ image. 

//The unwind data info structure is used to record the effects a function has on the stack pointer, and where the nonvolatile registers are saved on the stack:
#define UNW_FLAG_NHANDLER 0x0
#define UNW_FLAG_EHANDLER 0x1
#define UNW_FLAG_UHANDLER 0x2
#define UNW_FLAG_CHAININFO 0x4

//UNWIND_CODE
//   +0x000 CodeOffset       : UChar
//   +0x001 UnwindOp         : Pos 0, 4 Bits
//   +0x001 OpInfo           : Pos 4, 4 Bits
//   +0x000 FrameOffset      : Uint2B
typedef union _PE_UNWIND_CODE {
    struct {
        uint8_t CodeOffset;
        struct {
            uint8_t UnwindOp : 4;
            uint8_t OpInfo   : 4;
        };
    };
    uint16_t FrameOffset;
} PE_UNWIND_CODE, *PPE_UNWIND_CODE;

typedef struct _PE_UNWIND_INFO {
    uint8_t Version         : 3;
    uint8_t Flags           : 5;
    uint8_t SizeOfProlog;
    uint8_t CountOfCodes;
    uint8_t FrameRegister  : 4;
    uint8_t FrameOffset    : 4;
    PE_UNWIND_CODE UnwindCode[1];
    union {
        //
        // If (Flags & UNW_FLAG_EHANDLER)
        //
        uint32_t ExceptionHandler;
        //
        // Else if (Flags & UNW_FLAG_CHAININFO)
        //
        uint32_t FunctionEntry;
    };
    //
    // If (Flags & UNW_FLAG_EHANDLER)
    //
    uint32_t ExceptionData; // an offset to a pointer to a SCOPE_TABLE
} PE_UNWIND_INFO, *PPE_UNWIND_INFO;

typedef struct _PPE_SCOPE_TABLE {
     uint32_t Count;
     struct
     {
         uint32_t BeginAddress; // offset of the first instruction within a __try block located in the function
         uint32_t EndAddress; // offset to the instruction after the last instruction within the __try block (conceptually the __except statement).
         uint32_t HandlerAddress; // offset to the instruction after the last instruction within the __try block (conceptually the __except statement). Or 1 for EXCEPTION_EXECUTE_HANDLER, ...
         uint32_t JumpTarget; // offset to the first instruction in the __except block associated with the __try block
     } ScopeRecord[1];
 } PPE_SCOPE_TABLE, *PPPE_SCOPE_TABLE;




/// 
/// DEBUG TABLE
/// 

typedef struct _PE_DEBUG_TABLE_ENTRY {
    uint32_t Characteristics; // 0 4 Characteristics Reserved, must be zero.
     uint32_t TimeDateStamp; // 4 4  The time and date that the debug data was created. The value of field TimeDateStamp in COFF File Header of a deterministic PE/COFF file does not indicate the date and time when the file was produced and should not be interpreted that way. Instead the value of the field is derived from a hash of the file content. The algorithm used to calculate this value is an implementation detail of the tool that produced the file.
    uint16_t MajorVersion; // 8 2  The major version number of the debug data format.
    uint16_t MinorVersion; // 10 2  The minor version number of the debug data format.
    uint32_t Type; // 12 4  The format of debugging information. This field enables support of multiple debuggers. For more information, see Debug Type.
    uint32_t SizeOfData; // 16 4  The size of the debug data (not including the debug directory itself).
    uint32_t AddressOfRawData; // 20 4  The address of the debug data when loaded, relative to the image base.
    uint32_t PointerToRawData; // 24 4  The file pointer to the debug data.
} PE_DEBUG_TABLE_ENTRY, *PPE_DEBUG_TABLE_ENTRY;
#define PE_DEBUG_TABLE_ENTRY_SIZE (sizeof(PE_DEBUG_TABLE_ENTRY))

//Debug Type
#define PE_IMAGE_DEBUG_TYPE_UNKNOWN (0x0) // An unknown value that is ignored by all tools.
#define PE_IMAGE_DEBUG_TYPE_COFF (0x1) // The COFF debug information (line numbers, symbol table, and string table). This type of debug information is also pointed to by fields in the file headers.
#define PE_IMAGE_DEBUG_TYPE_CODEVIEW (0x2) // The Visual C++ debug information.
#define PE_IMAGE_DEBUG_TYPE_FPO (0x3) // The frame pointer omission (FPO) information. This information tells the debugger how to interpret nonstandard stack frames, which use the EBP register for a purpose other than as a frame pointer.
#define PE_IMAGE_DEBUG_TYPE_MISC (0x4) // The location of DBG file.
#define PE_IMAGE_DEBUG_TYPE_EXCEPTION (0x5) // A copy of .pdata section.
#define PE_IMAGE_DEBUG_TYPE_FIXUP (0x6) // Reserved.
#define PE_IMAGE_DEBUG_TYPE_OMAP_TO_SRC (0x7) // The mapping from an RVA in image to an RVA in source image.
#define PE_IMAGE_DEBUG_TYPE_OMAP_FROM_SRC (0x8) // The mapping from an RVA in source image to an RVA in image.
#define PE_IMAGE_DEBUG_TYPE_BORLAND (0x9) // Reserved for Borland.
#define PE_IMAGE_DEBUG_TYPE_RESERVED10 (0xA) // Reserved.
#define PE_IMAGE_DEBUG_TYPE_CLSID (0xB) // Reserved.
#define PE_IMAGE_DEBUG_TYPE_VC_FEATURE  (0xC)
#define PE_IMAGE_DEBUG_TYPE_POGO (0xD)
#define PE_IMAGE_DEBUG_TYPE_ILTCG (0xE)
#define PE_IMAGE_DEBUG_TYPE_MPX (0xF)
#define PE_IMAGE_DEBUG_TYPE_REPRO (0x10) // PE determinism or reproducibility. The entry doesn't have any data associated with it. All fields of the entry, but Type shall be zero. Presence of this entry indicates that the containing PE/COFF file is deterministic.
#define PE_IMAGE_DEBUG_TYPE_EMBEDED_PDB (0x11) // Embedded Portable PDB Debug Directory Entry (type 17)
#define PE_IMAGE_DEBUG_TYPE_PDB_CHECK_SUM (0x13) // PDB Checksum Debug Directory Entry (type 19). Stores crypto hash of the content of the symbol file the PE/COFF file was built with. More than one entry can be present, in case multiple PDBs were produced during the build of the PE/COFF file (e.g. private and public symbols).
#define PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (0x14) // Extended DLL characteristics bits.
#define PE_IMAGE_DEBUG_TYPE_R2R_PERF_MAP (0x15) // R2R PerfMap Debug Directory Entry (type 21)


#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT                                  0x01
#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT_STRICT_MODE                      0x02
#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE  0x04
#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_DYNAMIC_APIS_ALLOW_IN_PROC              0x08
#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_1                              0x10  // Reserved for CET policy *downgrade* only!
#define PE_IMAGE_DLLCHARACTERISTICS_EX_CET_RESERVED_2                              0x20  // Reserved for CET policy *downgrade* only!

#define GUID_BIN_SIZE (0x10)
#define GUID_STR_SIZE (0x24)
#define GUID_STR_BUFFER_SIZE (GUID_STR_SIZE+1)
typedef struct _PE_CODEVIEW_DBG_H {
    union {
        uint32_t Signature; // 0 4 0x52 0x53 0x44 0x53 (ASCII string: "RSDS")
        uint8_t SignatureA[4]; 
    };
    uint8_t Guid[GUID_BIN_SIZE]; // 4 16 GUID (Globally Unique Identifier) of the associated PDB. Guid and Age are used to match PE/COFF image with the associated PDB.
    uint32_t Age; // 20 4 Iteration of the PDB. The first iteration is 1. The iteration is incremented each time the PDB content is augmented.
    char* PathPtr; // 24 UTF-8 NUL-terminated path to the associated .pdb file
} PE_CODEVIEW_DBG_H, *PPE_CODEVIEW_DBG_H;
#define PE_RDS_SIG (0x53445352)


typedef struct _PE_EMBEDED_PDB_DBG_H {
    union {
        uint32_t Signature; // 0 4 0x4D 0x50 0x44 0x42 (ASCII string: "MPDB")
        uint8_t SignatureA[4]; // 
    };
    uint32_t UncompressedSize; // 4 4 The size of decompressed Portable PDB image
    uint8_t PortablePdbImage[1]; // 8 SizeOfData - 8 Portable PDB image compressed using Deflate algorithm
} PE_EMBEDED_PDB_DBG_H, *PPE_EMBEDED_PDB_DBG_H;


typedef struct _PE_PDB_CHECK_SUM_DBG_H {
    char* AlgorithmName; // 0 AlgNameLength Zero-terminated UTF8 string. The name of the crypho hash algorithm.
    uint8_t* Checksum; // AlgNameLength ChecksumSize Blob. Checksum of the PDB content.
} PE_PDB_CHECK_SUM_DBG_H, *PPE_PDB_CHECK_SUM_DBG_H;

#define PE_PDB_CHECK_SUM_ALOG_SHA256 "SHA256"	32 // The 256-bit secure hash algorithm. Standard: FIPS 180-2, FIPS 198.
#define PE_PDB_CHECK_SUM_ALOG_SHA256_SIZE (0x20)
#define PE_PDB_CHECK_SUM_ALOG_SHA384 "SHA384" // The 384-bit secure hash algorithm. Standard: FIPS 180-2, FIPS 198.
#define PE_PDB_CHECK_SUM_ALOG_SHA384_SIZE (0x30)
#define PE_PDB_CHECK_SUM_ALOG_SHA512 "SHA512" // The 512-bit secure hash algorithm. Standard: FIPS 180-2, FIPS 198.
#define PE_PDB_CHECK_SUM_ALOG_SHA512_SIZE (0x40)


typedef struct _PE_R2R_PERF_MAP_DBG_H {
    union {
        uint32_t Magic; // 0 4 0x52 0x32 0x52 0x4D (ASCII string: "R2RM")
        uint8_t MagicA[4]; // 
    };
    uint8_t Signature[0x10]; // 4 16 Byte sequence uniquely identifying the associated PerfMap
    uint32_t Version; // 20 4 Version number of the PerfMap. Currently only version 1 is supported.
    char Path[1]; // 24 Path UTF-8 NUL-terminated path to the associated .r2rmap file.
} PE_R2R_PERF_MAP_DBG_H, *PPE_R2R_PERF_MAP_DBG_H;



typedef struct _PE_IMAGE_COFF_SYMBOLS_HEADER {
    uint32_t NumberOfSymbols;
    uint32_t LvaToFirstSymbol;
    uint32_t NumberOfLinenumbers;
    uint32_t LvaToFirstLinenumber;
    uint32_t RvaToFirstByteOfCode;
    uint32_t RvaToLastByteOfCode;
    uint32_t RvaToFirstByteOfData;
    uint32_t RvaToLastByteOfData;
} PE_IMAGE_COFF_SYMBOLS_HEADER, *PPE_IMAGE_COFF_SYMBOLS_HEADER;

#define PE_FRAME_FPO   0               
#define PE_FRAME_TRAP  1
#define PE_FRAME_TSS   2
#define PE_FRAME_NONFPO    3

typedef struct _PE_FPO_DATA {
    uint32_t ulOffStart;   // offset 1st byte of function code
    uint32_t cbProcSize;   // # bytes in function
    uint32_t cdwLocals;    // # bytes in locals/4
    uint16_t cdwParams;    // # bytes in params/4
    uint16_t cbProlog : 8; // # bytes in prolog
    uint16_t cbRegs   : 3; // # regs saved
    uint16_t fHasSEH  : 1; // TRUE if SEH in func
    uint16_t fUseBP   : 1; // TRUE if EBP has been allocated
    uint16_t reserved : 1; // reserved for future use
    uint16_t cbFrame  : 2; // frame type
} PE_FPO_DATA;
#define SIZEOF_PE_RFPO_DATA 16


#define PE_IMAGE_DEBUG_MISC_EXENAME    1

typedef struct _PE_IMAGE_DEBUG_MISC {
    uint32_t DataType; // type of misc data, see defines
    uint32_t Length; // total length of record, rounded to four
                                        // byte multiple.
    uint8_t Unicode; // TRUE if data is unicode string
    uint8_t Reserved[3];
    uint8_t Data[1];  // Actual data
} PE_IMAGE_DEBUG_MISC, *PPE_IMAGE_DEBUG_MISC;


//
// Function table extracted from MIPS/ALPHA/IA64 images.  
// Does not contain information needed only for runtime support.  
// Just those fields for each entry needed by a debugger.
//

typedef struct _PE_IMAGE_FUNCTION_ENTRY {
    uint32_t   StartingAddress;
    uint32_t   EndingAddress;
    uint32_t   EndOfPrologue;
} PE_IMAGE_FUNCTION_ENTRY, *PPE_IMAGE_FUNCTION_ENTRY;

typedef struct _PE_IMAGE_FUNCTION_ENTRY64 {
    uint64_t   StartingAddress;
    uint64_t   EndingAddress;
    union {
        uint64_t   EndOfPrologue;
        uint64_t   UnwindInfoAddress;
    } DUMMYUNIONNAME;
} PE_IMAGE_FUNCTION_ENTRY64, *PPE_IMAGE_FUNCTION_ENTRY64;

//
// Debugging information can be stripped from an image file and placed
// in a separate .DBG file, whose file name part is the same as the
// image file name part (e.g. symbols for CMD.EXE could be stripped
// and placed in CMD.DBG).  This is indicated by the IMAGE_FILE_DEBUG_STRIPPED
// flag in the Characteristics field of the file header.  The beginning of
// the .DBG file contains the following structure which captures certain
// information from the image file.  This allows a debug to proceed even if
// the original image file is not accessable.  This header is followed by
// zero of more IMAGE_SECTION_HEADER structures, followed by zero or more
// IMAGE_DEBUG_DIRECTORY structures.  The latter structures and those in
// the image file contain file offsets relative to the beginning of the
// .DBG file.
//
// If symbols have been stripped from an image, the IMAGE_DEBUG_MISC structure
// is left in the image file, but not mapped.  This allows a debugger to
// compute the name of the .DBG file, from the name of the image in the
// IMAGE_DEBUG_MISC structure.
//

typedef struct _PE_IMAGE_SEPARATE_DEBUG_HEADER {
    uint16_t Signature;
    uint16_t Flags;
    uint16_t Machine;
    uint16_t Characteristics;
    uint32_t TimeDateStamp;
    uint32_t CheckSum;
    uint32_t ImageBase;
    uint32_t SizeOfImage;
    uint32_t NumberOfSections;
    uint32_t ExportedNamesSize;
    uint32_t DebugDirectorySize;
    uint32_t SectionAlignment;
    uint32_t Reserved[2];
} PE_IMAGE_SEPARATE_DEBUG_HEADER, *PPE_IMAGE_SEPARATE_DEBUG_HEADER;

// begin_ntoshvp

typedef struct _PE_NON_PAGED_DEBUG_INFO {
    uint16_t Signature;
    uint16_t Flags;
    uint32_t Size;
    uint16_t Machine;
    uint16_t Characteristics;
    uint32_t TimeDateStamp;
    uint32_t CheckSum;
    uint32_t SizeOfImage;
    uint64_t ImageBase;
    //DebugDirectorySize
    //IMAGE_DEBUG_DIRECTORY
} PE_NON_PAGED_DEBUG_INFO, *PPE_NON_PAGED_DEBUG_INFO;

// end_ntoshvp

#ifndef _MAC
#define PE_IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4944
#define PE_NON_PAGED_DEBUG_SIGNATURE      0x494E
#else
#define PE_IMAGE_SEPARATE_DEBUG_SIGNATURE 0x4449  // DI
#define PE_NON_PAGED_DEBUG_SIGNATURE      0x4E49  // NI
#endif

#define PE_IMAGE_SEPARATE_DEBUG_FLAGS_MASK 0x8000
#define PE_IMAGE_SEPARATE_DEBUG_MISMATCH   0x8000  // when DBG was updated, the
                                                // old checksum didn't match.




// custom

typedef struct _StringTable {
    uint8_t *strings;
    uint32_t size;
} StringTable, *PStringTable;

// section addresses and sizes used for offset calculation
typedef struct _SVAS {
    uint32_t VirtualAddress;
    uint32_t VirtualSize;
    uint32_t PointerToRawData;
    uint32_t SizeOfRawData;
} SVAS, *PSVAS;

#endif
