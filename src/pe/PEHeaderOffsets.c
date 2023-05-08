#include "PEHeaderOffsets.h"

struct PE_Image_Dos_Header_Offsets PEImageDosHeaderOffsets = {
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

const struct PE_Coff_File_Header_Offsets PECoffFileHeaderOffsets = {
    .Machine = 0, // uint16_t
    .NumberOfSections = 2, // uint16_t
    .TimeDateStamp = 4, // uint32_t
    .PointerToSymbolTable = 8, // uint32_t
    .NumberOfSymbols = 12, // uint32_t
    .SizeOfOptionalHeader = 16, // uint16_t
    .Characteristics = 18 // uint16_t
};


const struct _PE_Optional_Header_Offsets PEOptional32HeaderOffsets = {
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

const struct _PE_Optional_Header_Offsets PEOptional64HeaderOffsets = {
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

const struct PE_Section_Header_Offsets PESectionHeaderOffsets = {
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

const struct PE_Image_Import_Descriptor_Offsets PEImageImportDescriptorOffsets = {
    .Union = 0,
    .TimeDateStamp = 4,
    .ForwarderChain = 8,
    .Name = 12,
    .FirstThunk = 16,
};

const struct PE_Image_Thunk_Data_32_Offsets PEImageThunkData32Offsets = {
    .u1 = 0
};

const struct PE_Image_Thunk_Data_64_Offsets PEImageThunkData64Offsets = {
    .u1 = 0
};

const struct PE_Image_Import_By_Name_Offsets PEImageImportByNameOffsets = {
    .Hint = 0,
    .Name = 2
};

const struct Pe_Image_Delay_Load_Descriptor_Offsets PeImageDelayLoadDescriptorOffsets = {
    .Attributes = 0,
    .DllNameRVA = 4,
    .ModuleHandleRVA = 8,
    .ImportAddressTableRVA = 12,
    .ImportNameTableRVA = 16,
    .BoundImportAddressTableRVA = 20,
    .UnloadInformationTableRVA = 24,
    .TimeDateStamp = 28,
};

const struct PE_IMAGE_BOUND_IMPORT_DESCRIPTOR_OFFSETS PeImageBoundDescriptorOffsets = {
    .TimeDateStamp = 0,
    .OffsetModuleName = 4,
    .NumberOfModuleForwarderRefs = 6
};

const struct PE_IMAGE_BOUND_FORWARDER_REF_OFFSETS PeImageBoundForwarderRefOffsets = {
    .TimeDateStamp = 0,
    .OffsetModuleName = 4,
    .Reserved = 6
};

const struct Pe_Image_Export_Directory_Offsets PeImageExportDirectoryOffsets = {
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

const struct Pe_Attribute_Certificate_Table_Offsets PeAttributeCertificateTableOffsets = {
    0,
    4,
    6,
    8
};

const struct Pe_Image_Resource_Directory_Entry_Offsets PeImageResourceDirectoryEntryOffsets = {
    .Name = 0,
    .OffsetToData = 4
};

const struct Pe_Image_Resource_Directory_Offsets PeImageResourceDirectoryOffsets = {
    .Characteristics = 0,
    .TimeDateStamp = 4,
    .MajorVersion = 8,
    .MinorVersion = 10,
    .NumberOfNamedEntries = 12,
    .NumberOfIdEntries = 14
//	.DirectoryEntries = 16
};

const struct Pe_Image_Resource_Dir_String_U_Offsets PeImageResourceDirStringUOffsets = {
    .Length = 0,
    .NameString = 2
};

const struct Pe_Image_Resource_Data_Entry_Offsets PeImageResourceDataEntryOffsets = {
    .OffsetToData = 0,
    .Size = 4,
    .CodePage = 8,
    .Reserved = 12
};

const struct PE_BASE_RELOCATION_BLOCK_Offsets PeBaseRelocationBlockOffsets = {
    .VirtualAddress = 0,
    .SizeOfBlock = 4
};

const struct Pe_Base_Relocation_Entry_Offsets PeBaseRelocationEntryOffsets = {
    .Type = 0,
    .Offset = 0
};




const struct  PE_IMAGE_TLS_DIRECTORY_OFFSETS PeImageTlsDirectoryOfsets32 = {
    .StartAddressOfRawData = 0,
    .EndAddressOfRawData = 4,
    .AddressOfIndex = 8,
    .AddressOfCallBacks = 12,
    .SizeOfZeroFill = 16,
    .Characteristics = 20
};
const struct PE_IMAGE_TLS_DIRECTORY_OFFSETS PeImageTlsDirectoryOfsets64 = {
    .StartAddressOfRawData = 0,
    .EndAddressOfRawData = 8,
    .AddressOfIndex = 16,
    .AddressOfCallBacks = 24,
    .SizeOfZeroFill = 32,
    .Characteristics = 36
};






const struct PE_IMAGE_LOAD_CONFIG_CODE_INTEGRITY_OFFSETS PeImageLoadConfigCodeIntegrityOffsets = {
    .Flags = 0,
    .Catalog = 2,
    .CatalogOffset = 4,
    .Reserved = 8,
};


const struct PE_IMAGE_LOAD_CONFIG_DIRECTORY_OFFSETS PeImageLoadConfigDirectoryOffsets32 = {
    .Size = 0, 
    .TimeDateStamp = 4,
    .MajorVersion = 8,
    .MinorVersion = 10,
    .GlobalFlagsClear = 12,
    .GlobalFlagsSet = 16,
    .CriticalSectionDefaultTimeout = 20,
    .DeCommitFreeBlockThreshold = 24,
    .DeCommitTotalFreeThreshold = 28,
    .LockPrefixTable = 32,
    .MaximumAllocationSize = 36,
    .VirtualMemoryThreshold = 40,
    .ProcessAffinityMask = 44,
    .ProcessHeapFlags = 48,
    .CSDVersion = 52,
    .DependentLoadFlags = 54,
    .EditList = 56,
    .SecurityCookie = 60,
    .SEHandlerTable = 64,
    .SEHandlerCount = 68,
    .GuardCFCheckFunctionPointer = 72,
    .GuardCFDispatchFunctionPointer = 76,
    .GuardCFFunctionTable = 80,
    .GuardCFFunctionCount = 84,
    .GuardFlags = 88,
    .CodeIntegrity = 92,
    .GuardAddressTakenIatEntryTable = 104,
    .GuardAddressTakenIatEntryCount = 108,
    .GuardLongJumpTargetTable = 112,
    .GuardLongJumpTargetCount = 116,
    .DynamicValueRelocTable = 120,
    .CHPEMetadataPointer = 124,
    .GuardRFFailureRoutine = 128,
    .GuardRFFailureRoutineFunctionPointer = 132,
    .DynamicValueRelocTableOffset = 136,
    .DynamicValueRelocTableSection = 140, 
    .Reserved2 = 142,
    .GuardRFVerifyStackPointerFunctionPointer = 144,
    .HotPatchTableOffset = 148,
    .Reserved3 = 152,
    .EnclaveConfigurationPointer = 156,
    .VolatileMetadataPointer = 160,
    .GuardEHContinuationTable = 164,
    .GuardEHContinuationCount = 168,
};

const struct PE_IMAGE_LOAD_CONFIG_DIRECTORY_OFFSETS PeImageLoadConfigDirectoryOffsets64 = {
    .Size = 0,
    .TimeDateStamp = 4,
    .MajorVersion = 8,
    .MinorVersion = 10,
    .GlobalFlagsClear = 12,
    .GlobalFlagsSet = 16,
    .CriticalSectionDefaultTimeout = 20,
    .DeCommitFreeBlockThreshold = 24,
    .DeCommitTotalFreeThreshold = 32,
    .LockPrefixTable = 40,
    .MaximumAllocationSize = 48,
    .VirtualMemoryThreshold = 56,
    .ProcessAffinityMask = 64,
    .ProcessHeapFlags = 72,
    .CSDVersion = 76,
    .DependentLoadFlags = 78,
    .EditList = 80,  
    .SecurityCookie = 88,    
    .SEHandlerTable = 96,
    .SEHandlerCount = 104,
    .GuardCFCheckFunctionPointer = 112, 
    .GuardCFDispatchFunctionPointer = 120,
    .GuardCFFunctionTable = 128, 
    .GuardCFFunctionCount = 136,
    .GuardFlags = 144,
    .CodeIntegrity = 148,
    .GuardAddressTakenIatEntryTable = 160,
    .GuardAddressTakenIatEntryCount = 168,
    .GuardLongJumpTargetTable = 176,
    .GuardLongJumpTargetCount = 184,
    .DynamicValueRelocTable = 192,  
    .CHPEMetadataPointer = 200, 
    .GuardRFFailureRoutine = 208,  
    .GuardRFFailureRoutineFunctionPointer = 216,
    .DynamicValueRelocTableOffset = 224,
    .DynamicValueRelocTableSection = 228,
    .Reserved2 = 230,
    .GuardRFVerifyStackPointerFunctionPointer = 232,
    .HotPatchTableOffset = 240,
    .Reserved3 = 244,
    .EnclaveConfigurationPointer = 248,
    .VolatileMetadataPointer = 256, 
    .GuardEHContinuationTable = 264, 
    .GuardEHContinuationCount = 272
};




const struct _PE_IMAGE_EXCEPTION_TABLE_ENTRY_OFFSETS PeImageExceptionTableEntryOffsets = {
    .BeginAddress = 0, 
    .EndAddress = 4,
    .Flags = 4,
    .ExceptionHandler = 8,
    .UnwindInformation = 8,
    .HandlerData = 12,
    .PrologEndAddress = 16,
};




const struct _PE_IMAGE_DEBUG_TABLE_ENTRY_OFFSETS PeImageDebugTableEntryOffsets = {
    .Characteristics = 0, 
    .TimeDateStamp = 4,
    .MajorVersion = 8,
    .MinorVersion = 10,
    .Type = 12,
    .SizeOfData = 16,
    .AddressOfRawData = 20,
    .PointerToRawData = 24,
};

const struct _PE_CODEVIEW_DBG_H_OFFSETS PeCodeViewDbgHOffsets = {
    .Signature = 0, 
    .Guid = 4,
    .Age = 20,
    .Path = 24,
};
