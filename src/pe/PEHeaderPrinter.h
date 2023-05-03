#ifndef HEADER_PARSER_PE_HEADER_PRINTER_H
#define HEADER_PARSER_PE_HEADER_PRINTER_H

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "../Globals.h"
#include "../utils/Converter.h"
#include "../utils/Helper.h"
#include "../utils/blockio.h"
#include "PEHeader.h"
#include "PEHeaderOffsets.h"
#include "PEOptionalHeaderSignature.h"
#include "PEHeaderSectionNameResolution.h"
#include "PEMachineTypes.h"
#include "PEWindowsSubsystem.h"
#include "PECharacteristics.h"

void PE_printImageDosHeader(PEImageDosHeader* idh, size_t start_file_offset);
void PE_printCoffFileHeader(PECoffFileHeader* ch, size_t offset, size_t start_file_offset);
//char* PE_getMachineName(PeMachineTypes type);
void PE_printOptionalHeader(PE64OptHeader* oh, size_t offset, size_t start_file_offset, uint8_t bitness);
void PE_printDataDirectory(PE64OptHeader* oh, size_t offset, uint8_t bitness);
void PE_printImageSectionHeader(PEImageSectionHeader* sh,
                                uint16_t idx,
                                uint16_t size,
                                PECoffFileHeader* ch,
                                size_t offset,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s,
                                PStringTable st);
const char* PE_getSubsystemName(enum PEWinudowsSubsystem type);

void PE_printImageImportTableHeader(PEImageImportDescriptor* impd);
void PE_printImageImportDescriptor(PEImageImportDescriptor* impd, 
                                   size_t offset, 
                                   const char* impd_name);
void PE_printHintFunctionHeader(int bound);
void PE_printImageThunkData(PEImageThunkData64* td, PEImageImportByName* ibn, size_t td_offset, size_t ibn_offset, uint8_t bitness);

void PE_printImageExportDirectoryInfo(PE_IMAGE_EXPORT_DIRECTORY* ied);
void PE_printImageExportDirectoryHeader();
void PE_printImageExportDirectoryEntry(size_t i, 
                                       PE_IMAGE_EXPORT_DIRECTORY *ied,
                                       const char* name, 
                                       size_t name_max, 
                                       uint16_t name_ordinal, 
                                       uint8_t* bytes, 
                                       size_t bytes_max, 
                                       uint32_t rva, 
                                       size_t fo, 
                                       int is_forwarded);

void PE_printImageLoadConfigDirectory(PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
                                      size_t offset,
                                      int bitness,
                                      PLoadConfigTableOffsets to,
                                      size_t file_size,
                                      FILE* fp,
                                      uint8_t* block_s);
void PE_printSizedRVAArray(uint64_t count, 
                           size_t offset, 
                           size_t file_size,
                           FILE* fp,
                           uint8_t* block_s);

void PE_printAttributeCertificateTable(PeAttributeCertificateTable* t, uint8_t n, size_t offset);
const char* PE_getCertificateTypeString(uint16_t type);
void PE_printImageResourceDirectoryEntryHeader(int type, uint16_t n, uint16_t level);
void PE_printImageResourceDirectoryEntry(const PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                         size_t table_fo,
                                         size_t offset,
                                         uint16_t level,
                                         uint16_t id,
                                         uint16_t n,
                                         size_t start_file_offset,
                                         size_t file_size,
                                         FILE* fp,
                                         uint8_t* block_s);

void PE_printImageTLSTableHeader();
void PE_printTLSEntry(PE_IMAGE_TLS_DIRECTORY64* tls, 
                      uint32_t i, 
                      uint8_t bitness, 
                      size_t start_file_offset,
                      size_t s_offset,
                      size_t e_offset,
                      size_t cb_offset,
                      size_t file_size,
                      FILE* fp,
                      uint8_t* block_s);

void PE_printImageBaseRelocationTable();
void PE_printImageBaseRelocationBlockHeader(PE_BASE_RELOCATION_BLOCK* b, 
                                            uint32_t i,
                                            size_t start_file_offset);
void PE_printImageBaseRelocationBlockEntry(PE_BASE_RELOCATION_ENTRY* e);

void PE_printImageDelayImportTableHeader(PeImageDelayLoadDescriptor* did);
void PE_printImageDelayImportDescriptor(PeImageDelayLoadDescriptor* did,
                                        size_t offset, 
                                        const char* dll_name);

void PE_printImageBoundImportTableHeader(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid);
void PE_printImageBoundImportDescriptor(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid, 
                                        size_t offset, 
                                        const char* dll_name);
void PE_printImageBoundForwarderRef(PE_IMAGE_BOUND_FORWARDER_REF* bfr, 
                                    size_t offset, 
                                    const char* dll_name,
                                    uint16_t i, 
                                    uint16_t n);

const char* PE_getImageSecAlignmentString(uint32_t ch);


#define MAX_SPACES (512)
void fillSpaces(char* buf, size_t n, uint16_t level);
//#define MAX_DASHES (512)
//void fillDashes(char* buf, size_t n, uint16_t level);






void PE_printImageDosHeader(PEImageDosHeader* idh, size_t start_file_offset)
{
    printf("PE Image Dos Header:\n");
    printf(" - signature%s: %c|%c\n", fillOffset(PEImageDosHeaderOffsets.signature, 0, start_file_offset), idh->signature[0], idh->signature[1]);
    printf(" - lastsize%s: %u\n", fillOffset(PEImageDosHeaderOffsets.lastsize, 0, start_file_offset), idh->lastsize);
    printf(" - nblocks%s: %u\n", fillOffset(PEImageDosHeaderOffsets.nblocks, 0, start_file_offset), idh->nblocks);
    printf(" - nreloc%s: %u\n", fillOffset(PEImageDosHeaderOffsets.nreloc, 0, start_file_offset), idh->nreloc);
    printf(" - hdrsize%s: %u\n", fillOffset(PEImageDosHeaderOffsets.hdrsize, 0, start_file_offset), idh->hdrsize);
    printf(" - minalloc%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.minalloc, 0, start_file_offset), idh->minalloc);
    printf(" - maxalloc%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.maxalloc, 0, start_file_offset), idh->maxalloc);
    printf(" - ss: 0x%x\n", idh->ss);
    printf(" - sp: 0x%x\n", idh->sp);
    printf(" - checksum%s: %u\n", fillOffset(PEImageDosHeaderOffsets.checksum, 0, start_file_offset), idh->checksum);
    printf(" - ip: 0x%x\n", idh->ip);
    printf(" - cs: 0x%x\n", idh->cs);
    printf(" - relocpos%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.relocpos, 0, start_file_offset), idh->relocpos);
    printf(" - noverlay%s: %u\n", fillOffset(PEImageDosHeaderOffsets.noverlay, 0, start_file_offset), idh->noverlay);
//	printf(" - reserved1: %04x|%04x|%04x|%04x\n", idh->reserved1[0], idh->reserved1[1], idh->reserved1[2], idh->reserved1[3]);
    printf(" - oem_id%s: %u\n", fillOffset(PEImageDosHeaderOffsets.oem_id, 0, start_file_offset), idh->oem_id);
    printf(" - oem_info%s: %u\n", fillOffset(PEImageDosHeaderOffsets.oem_info, 0, start_file_offset), idh->oem_info);
//	printf(" - reserved2: %04x|%04x|%04x|%04x%04x|%04x|%04x|%04x%04x|%04x\n", idh->reserved2[0], idh->reserved2[1], idh->reserved2[2], idh->reserved2[3], idh->reserved2[4], idh->reserved2[5], idh->reserved2[6], idh->reserved2[7], idh->reserved2[8], idh->reserved2[9]);
    printf(" - e_lfanew%s: 0x%x (%u)\n", fillOffset(PEImageDosHeaderOffsets.e_lfanew, 0, start_file_offset), idh->e_lfanew, idh->e_lfanew);
    printf("\n");
}

void PE_printCoffFileHeader(PECoffFileHeader* ch, size_t offset, size_t start_file_offset)
{
    const char* dll_c_pre = "   - ";
    const char dll_c_post = '\n';
    ArchitectureMapEntry* arch = getArchitecture(ch->Machine, pe_arch_id_mapper, pe_arch_id_mapper_size);
    char ch_bin[17];
    char date[32];
    date[0] = 0;
    if (ch->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(ch->TimeDateStamp, date, sizeof(date));
    uint16ToBin(ch->Characteristics, ch_bin);

    printf("Coff File Header:\n");
    printf(" - Machine%s: %s (0x%X)\n", fillOffset(PECoffFileHeaderOffsets.Machine, offset, start_file_offset), arch->arch.name, ch->Machine);
//	printf(" - Machine%s: %s (0x%X)\n", fillOffset(PECoffFileHeaderOffsets.Machine, offset), PE_getMachineName(ch->Machine), ch->Machine);
    printf(" - NumberOfSections%s: %u\n", fillOffset(PECoffFileHeaderOffsets.NumberOfSections, offset, start_file_offset), ch->NumberOfSections);
    printf(" - TimeDateStamp%s: %s (0x%x)\n", fillOffset(PECoffFileHeaderOffsets.TimeDateStamp, offset, start_file_offset), date, ch->TimeDateStamp);
    printf(" - PointerToSymbolTable%s: 0x%X (%u)\n", fillOffset(PECoffFileHeaderOffsets.PointerToSymbolTable, offset, 0), ch->PointerToSymbolTable, ch->PointerToSymbolTable);
    printf(" - NumberOfSymbols%s: %u\n", fillOffset(PECoffFileHeaderOffsets.NumberOfSymbols, offset, start_file_offset), ch->NumberOfSymbols);
    printf(" - SizeOfOptionalHeader%s: %u\n", fillOffset(PECoffFileHeaderOffsets.SizeOfOptionalHeader, offset, start_file_offset), ch->SizeOfOptionalHeader);
    printf(" - Characteristics%s: 0x%X (b%s)\n", fillOffset(PECoffFileHeaderOffsets.Characteristics, offset, start_file_offset), ch->Characteristics, ch_bin);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_RELOCS_STRIPPED,
            "IMAGE_FILE_RELOCS_STRIPPED: Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_EXECUTABLE_IMAGE,
            "IMAGE_FILE_EXECUTABLE_IMAGE. The file is executable (there are no unresolved external references).", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_LINE_NUMS_STRIPPED,
            "IMAGE_FILE_LINE_NUMS_STRIPPED: COFF line numbers were stripped from the file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_LOCAL_SYMS_STRIPPED,
            "IMAGE_FILE_LOCAL_SYMS_STRIPPED: COFF symbol table entries were stripped from file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_AGGRESIVE_WS_TRIM,
            "IMAGE_FILE_AGGRESIVE_WS_TRIM: Aggressively trim the working set. This value is obsolete.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_LARGE_ADDRESS_AWARE,
            "IMAGE_FILE_LARGE_ADDRESS_AWARE: The application can handle addresses larger than 2 GB.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_BYTES_REVERSED_LO,
            "IMAGE_FILE_BYTES_REVERSED_LO: The bytes of the word are reversed. This flag is obsolete.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_32BIT_MACHINE,
            "IMAGE_FILE_32BIT_MACHINE: The computer supports 32-bit words.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_DEBUG_STRIPPED,
            "IMAGE_FILE_DEBUG_STRIPPED: Debugging information was removed and stored separately in another file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
            "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: If the image is on removable media, copy it to and run it from the swap file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_NET_RUN_FROM_SWAP,
            "IMAGE_FILE_NET_RUN_FROM_SWAP: If the image is on the network, copy it to and run it from the swap file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_SYSTEM,
            "IMAGE_FILE_SYSTEM: The image is a system file.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_DLL,
            "IMAGE_FILE_DLL: The image is a DLL file. While it is an executable file, it cannot be run directly.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_UP_SYSTEM_ONLY,
            "IMAGE_FILE_UP_SYSTEM_ONLY: The file should be run only on a uniprocessor computer.", dll_c_pre, dll_c_post);
    printFlag32F(ch->Characteristics, PECoffCharacteristics.IMAGE_FILE_BYTES_REVERSED_HI,
            "IMAGE_FILE_BYTES_REVERSED_HI: The bytes of the word are reversed. This flag is obsolete.", dll_c_pre, dll_c_post);
    printf("\n");
}

void PE_printOptionalHeader(PE64OptHeader* oh, size_t offset, size_t start_file_offset, uint8_t bitness)
{
    PEOptionalHeaderOffsets offsets = (bitness == 32) ? PEOptional32HeaderOffsets : PEOptional64HeaderOffsets;
    const char* magic_string;
    const char* dll_c_pre = "   - ";
    const char dll_c_post = '\n';
    char ch_bin[17];

    uint16ToBin(oh->DLLCharacteristics, ch_bin);

    if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
        magic_string = "32-bit exe";
    else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR64_MAGIC )
        magic_string = "64-bit exe";
    else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_ROM_OPTIONAL_HDR_MAGIC )
        magic_string = "ROM image";
    else
        magic_string = "None";

    printf("Optional Header:\n");
    printf(" - Magic%s: %s (0x%x)\n", fillOffset(offsets.Magic, offset, start_file_offset), magic_string, oh->Magic);
    printf(" - MajorLinkerVersion%s: %u\n", fillOffset(offsets.MajorLinkerVersion, offset, start_file_offset), (uint8_t)oh->MajorLinkerVersion);
    printf(" - MinorLinkerVersion%s: %u\n", fillOffset(offsets.MinorLinkerVersion, offset, start_file_offset), (uint8_t)oh->MinorLinkerVersion);
    printf(" - SizeOfCode%s: 0x%X (%u)\n", fillOffset(offsets.SizeOfCode, offset, start_file_offset), oh->SizeOfCode, oh->SizeOfCode);
    printf(" - SizeOfInitializedData%s: 0x%X (%u)\n", fillOffset(offsets.SizeOfInitializedData, offset, start_file_offset), oh->SizeOfInitializedData, oh->SizeOfInitializedData);
    printf(" - SizeOfUninitializedData%s: 0x%X (%u)\n", fillOffset(offsets.SizeOfUninitializedData, offset, start_file_offset), oh->SizeOfUninitializedData, oh->SizeOfUninitializedData);
    printf(" - AddressOfEntryPoint%s: 0x%X (%u)\n", fillOffset(offsets.AddressOfEntryPoint, offset, start_file_offset), oh->AddressOfEntryPoint, oh->AddressOfEntryPoint);
    printf(" - BaseOfCode%s: 0x%X (%u)\n", fillOffset(offsets.BaseOfCode, offset, start_file_offset), oh->BaseOfCode, oh->BaseOfCode);
    if (bitness == 32) printf(" - BaseOfData%s: 0x%X (%u)\n", fillOffset(offsets.BaseOfData, offset, start_file_offset), oh->BaseOfData, oh->BaseOfData);
//#if defined(_WIN32)
//    printf(" - ImageBase%s: 0x%llX (%llu)\n", fillOffset(offsets.ImageBase, offset, start_file_offset), oh->ImageBase, oh->ImageBase);
//#else
//    printf(" - ImageBase%s: 0x%lX (%lu)\n", fillOffset(offsets.ImageBase, offset, start_file_offset), oh->ImageBase, oh->ImageBase);
//#endif
    printf(" - ImageBase%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.ImageBase, offset, start_file_offset), oh->ImageBase, oh->ImageBase);
    printf(" - SectionAlignment%s: 0x%X (%u)\n", fillOffset(offsets.SectionAlignment, offset, start_file_offset), oh->SectionAlignment, oh->SectionAlignment);
    printf(" - FileAlignment%s: 0x%X (%u)\n", fillOffset(offsets.FileAlignment, offset, start_file_offset), oh->FileAlignment, oh->FileAlignment);
    printf(" - MajorOSVersion%s: 0x%X (%u)\n", fillOffset(offsets.MajorOperatingSystemVersion, offset, start_file_offset), oh->MajorOSVersion, oh->MajorOSVersion);
    printf(" - MinorOSVersion%s: 0x%X (%u)\n", fillOffset(offsets.MinorOperatingSystemVersion, offset, start_file_offset), oh->MinorOSVersion, oh->MinorOSVersion);
    printf(" - MajorImageVersion%s: 0x%X (%u)\n", fillOffset(offsets.MajorImageVersion, offset, start_file_offset), oh->MajorImageVersion, oh->MajorImageVersion);
    printf(" - MinorImageVersion%s: 0x%X (%u)\n", fillOffset(offsets.MinorImageVersion, offset, start_file_offset), oh->MinorImageVersion, oh->MinorImageVersion);
    printf(" - MajorSubsystemVersion%s: 0x%X (%u)\n", fillOffset(offsets.MajorSubsystemVersion, offset, start_file_offset), oh->MajorSubsystemVersion, oh->MajorSubsystemVersion);
    printf(" - MinorSubsystemVersion%s: 0x%X (%u)\n", fillOffset(offsets.MinorSubsystemVersion, offset, start_file_offset), oh->MinorSubsystemVersion, oh->MinorSubsystemVersion);
    printf(" - Win32VersionValue%s: 0x%X (%u)\n", fillOffset(offsets.Win32VersionValue, offset, start_file_offset), oh->Win32VersionValue, oh->Win32VersionValue);
    printf(" - SizeOfImage%s: 0x%X (%u)\n", fillOffset(offsets.SizeOfImage, offset, start_file_offset), oh->SizeOfImage, oh->SizeOfImage);
    printf(" - SizeOfHeaders%s: 0x%X (%u)\n", fillOffset(offsets.SizeOfHeaders, offset, start_file_offset), oh->SizeOfHeaders, oh->SizeOfHeaders);
    printf(" - Checksum%s: 0x%X (%u)\n", fillOffset(offsets.CheckSum, offset, start_file_offset), oh->Checksum, oh->Checksum);
    printf(" - Subsystem%s: %s (0x%x)\n", fillOffset(offsets.Subsystem, offset, start_file_offset), PE_getSubsystemName((enum PEWinudowsSubsystem)oh->Subsystem), oh->Subsystem);
    printf(" - DllCharacteristics%s: 0x%X (b%s)\n", fillOffset(offsets.DllCharacteristics, offset, start_file_offset), oh->DLLCharacteristics, ch_bin);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
            "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA: Image can handle a high entropy 64-bit virtual address space.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
            "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE: DLL can be relocated at load time.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
            "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY: Code Integrity checks are enforced.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
            "IMAGE_DLLCHARACTERISTICS_NX_COMPAT: Image is NX compatible.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
            "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION: Isolation aware, but do not isolate the image.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_SEH,
            "IMAGE_DLLCHARACTERISTICS_NO_SEH: Does not use structured exception (SE) handling. No SE handler may be called in this image.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_NO_BIND,
            "IMAGE_DLLCHARACTERISTICS_NO_BIND: Do not bind the image.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
            "IMAGE_DLLCHARACTERISTICS_APPCONTAINER: Image must execute in an AppContainer.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
            "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER: A WDM driver.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
            "IMAGE_DLLCHARACTERISTICS_GUARD_CF: Image supports Control Flow Guard.", dll_c_pre, dll_c_post);
    printFlag32F(oh->DLLCharacteristics, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE,
            "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE: Terminal Server aware.", dll_c_pre, dll_c_post);
    printf(" - SizeOfStackReserve%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.SizeOfStackReserve, offset, start_file_offset), oh->SizeOfStackReserve, oh->SizeOfStackReserve);
    printf(" - SizeOfStackCommit%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.SizeOfStackCommit, offset, start_file_offset), oh->SizeOfStackCommit, oh->SizeOfStackCommit);
    printf(" - SizeOfHeapReserve%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.SizeOfHeapReserve, offset, start_file_offset), oh->SizeOfHeapReserve, oh->SizeOfHeapReserve);
    printf(" - SizeOfHeapCommit%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.SizeOfHeapCommit, offset, start_file_offset), oh->SizeOfHeapCommit, oh->SizeOfHeapCommit);
    printf(" - NumberOfRvaAndSizes%s: 0x%X (%u)\n", fillOffset(offsets.NumberOfRvaAndSizes, offset, start_file_offset), oh->NumberOfRvaAndSizes, oh->NumberOfRvaAndSizes);
    PE_printDataDirectory(oh, offset, bitness);
    printf("\n");
}

const char* PE_getSubsystemName(enum PEWinudowsSubsystem type)
{
    switch (type)
    {
        case IMAGE_SUBSYSTEM_UNKNOWN : return "IMAGE_SUBSYSTEM_UNKNOWN: An unknown subsystem";
        case IMAGE_SUBSYSTEM_NATIVE : return "IMAGE_SUBSYSTEM_NATIVE: Device drivers and native Windows processes";
        case IMAGE_SUBSYSTEM_WINDOWS_GUI : return "IMAGE_SUBSYSTEM_WINDOWS_GUI: The Windows graphical user interface (GUI) subsystem";
        case IMAGE_SUBSYSTEM_WINDOWS_CUI : return "IMAGE_SUBSYSTEM_WINDOWS_CUI: The Windows character subsystem";
        case IMAGE_SUBSYSTEM_OS2_CUI : return "IMAGE_SUBSYSTEM_OS2_CUI: The OS/2 character subsystem";
        case IMAGE_SUBSYSTEM_POSIX_CUI : return "IMAGE_SUBSYSTEM_POSIX_CUI: The Posix character subsystem";
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS : return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS: Native Win9x driver";
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI : return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: Windows CE";
        case IMAGE_SUBSYSTEM_EFI_APPLICATION : return "IMAGE_SUBSYSTEM_EFI_APPLICATION: An Extensible Firmware Interface (EFI) application";
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER : return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: An EFI driver with boot services";
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER : return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: An EFI driver with run-time services";
        case IMAGE_SUBSYSTEM_EFI_ROM : return "IMAGE_SUBSYSTEM_EFI_ROM: An EFI ROM image";
        case IMAGE_SUBSYSTEM_XBOX : return "IMAGE_SUBSYSTEM_XBOX: XBOX";
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION : return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: Windows boot application";
        default: return "An unknown subsystem";
    }
}

void PE_printDataDirectory(PE64OptHeader* oh, 
                           size_t offset, 
                           uint8_t bitness)
{
    PEOptionalHeaderOffsets offsets = (bitness == 32 ) ? PEOptional32HeaderOffsets : PEOptional64HeaderOffsets;
    size_t dir_offset = offsets.DataDirectories;
    uint8_t size_of_data_entry = sizeof(PEDataDirectory);

    printf(" - DataDirectory      | VirtualAddress |     Size\n");
    printf("   -------------------+----------------+----------\n");
    uint32_t i;
    uint8_t max_nr_of_rva_to_read = 128;
    uint8_t nr_of_rva_to_read = ( oh->NumberOfRvaAndSizes > max_nr_of_rva_to_read ) ? max_nr_of_rva_to_read : (uint8_t)oh->NumberOfRvaAndSizes;

    for ( i = 0; i < nr_of_rva_to_read; i++ )
    {
        if ( i < NUMBER_OF_RVA_AND_SIZES ) printf("   %-18s%s | ", ImageDirectoryEntryNames[i], fillOffset(dir_offset, offset, 0));
        else printf("   %18u%s ", i, fillOffset(dir_offset, offset, 0));
        printf("%#14x", oh->DataDirectory[i].VirtualAddress);
        printf(" | %#8x\n", oh->DataDirectory[i].Size);

        dir_offset += size_of_data_entry;
    }
}

void PE_printImageSectionHeader(PEImageSectionHeader* sh,
                                uint16_t idx,
                                uint16_t size,
                                PECoffFileHeader* ch,
                                size_t offset,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s,
                                PStringTable st)
{
    char characteristics_bin[33];
    char* name;
    PE_getRealName(sh->Name, &name, ch, start_file_offset, file_size, fp, block_s, st);

    printf("%u / %u\n", (idx+1u), size);
//	printf(" - short name: %c%c%c%c%c%c%c%c\n", sh->Name[0], sh->Name[1], sh->Name[2], sh->Name[3], sh->Name[4], sh->Name[5], sh->Name[6], sh->Name[7]);
    printf(" - Name%s: %s\n", fillOffset(PESectionHeaderOffsets.Name, offset, 0), name);
//	printf(" - name%s: %.*s\n", IMAGE_SIZEOF_SHORT_NAME, &(sh->Name));
    printf(" - Misc.VirtualSize%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.VirtualSize, offset, 0), sh->Misc.VirtualSize, sh->Misc.VirtualSize);
    printf(" - VirtualAddress%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.VirtualAddress, offset, 0), sh->VirtualAddress, sh->VirtualAddress);
    printf(" - SizeOfRawData%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.SizeOfRawData, offset, 0), sh->SizeOfRawData, sh->SizeOfRawData);
    printf(" - PointerToRawData%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.PointerToRawData, offset, 0), sh->PointerToRawData, sh->PointerToRawData);
    printf(" - PointerToRelocations%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.PointerToRelocations, offset, 0), sh->PointerToRelocations, sh->PointerToRelocations);
    printf(" - PointerToLinenumbers%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.PointerToLinenumbers, offset, 0), sh->PointerToLinenumbers, sh->PointerToLinenumbers);
    printf(" - NumberOfRelocations%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.NumberOfRelocations, offset, 0), sh->NumberOfRelocations, sh->NumberOfRelocations);
    printf(" - NumberOfLinenumbers%s: 0x%X (%u)\n", fillOffset(PESectionHeaderOffsets.NumberOfLinenumbers, offset, 0), sh->NumberOfLinenumbers, sh->NumberOfLinenumbers);
    uint32ToBin(sh->Characteristics, characteristics_bin);
    printf(" - Characteristics%s: 0x%X (b%s)\n", fillOffset(PESectionHeaderOffsets.Characteristics, offset, 0), sh->Characteristics, characteristics_bin);
    if ( sh->Characteristics != 0 ) printf(" -");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE, "CODE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_EXECUTE, "EXECUTE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_READ, "READ");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_WRITE, "WRITE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA, "INITIALIZED_DATA");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA, "UNINITIALIZED_DATA");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_LNK_INFO, "INFO");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_LNK_REMOVE, "REMOVE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_LNK_COMDAT, "COMDAT");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_GPREL, "GPREL");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_PURGEABLE, "MEM_PURGEABLE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_16BIT, "MEM_16BIT");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_LOCKED, "MEM_LOCKED");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_PRELOAD, "MEM_PRELOAD");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_LNK_NRELOC_OVFL, "NRELOC_OVFL");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_DISCARDABLE, "MEM_DISCARDABLE");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_NOT_CACHED, "MEM_NOT_CACHED");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_NOT_PAGED, "MEM_NOT_PAGED");
    printFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_SHARED, "MEM_SHARED");
    if ( sh->Characteristics != 0 ) printf("\n");

    free(name);
}

void PE_printImageImportTableHeader(PEImageImportDescriptor* impd)
{
    if ( isMemZero(impd, sizeof(PEImageImportDescriptor)) )
        printf("No Image Import Table\n");
    else
        printf("Image Import Table:\n");
}

void PE_printImageImportDescriptor(PEImageImportDescriptor* impd, size_t offset, const char* impd_name)
{
    char date[32];
    if (impd->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(impd->TimeDateStamp, date, sizeof(date));
    else
        strcpy(date, "-1 (check bound import)");
    date[31] = 0;

    printf(" -%s %s (0x%x)\n", fillOffset(PEImageImportDescriptorOffsets.Name, offset, 0), impd_name, impd->Name);
    printf("   - OriginalFirstThunk%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.Union, offset, 0), impd->OriginalFirstThunk);
    printf("   - TimeDateStamp%s: %s (0x%x)\n", fillOffset(PEImageImportDescriptorOffsets.TimeDateStamp, offset, 0), date, impd->TimeDateStamp);
    printf("   - ForwarderChain%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.ForwarderChain, offset, 0), impd->ForwarderChain);
    printf("   - FirstThunk%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.FirstThunk, offset, 0), impd->FirstThunk);
}

void PE_printHintFunctionHeader(int bound)
{
    const char* col0_l = (bound) ? "Address" : "Ordinal";
    printf("   - %s | Function\n", col0_l);
    printf("     --------+-----------\n");
}

void PE_printImageThunkData(PEImageThunkData64* td, PEImageImportByName* ibn, size_t td_offset, size_t ibn_offset, uint8_t bitness)
{
    uint64_t flag = (bitness == 32) ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;

    if ( td->Ordinal & flag )
        printf("      0x%04x%s\n", (uint16_t)(td->Ordinal - flag), fillOffset(PEImageThunkData64Offsets.u1, td_offset, 0));
    else
        printf("      0x%04x%s | %s%s\n",
                ibn->Hint, fillOffset(PEImageImportByNameOffsets.Hint, ibn_offset, 0), 
                ibn->Name, fillOffset(PEImageImportByNameOffsets.Name, ibn_offset, 0));
}

void PE_printImageExportDirectoryInfo(PE_IMAGE_EXPORT_DIRECTORY* ied)
{
    char date[32];
    date[0] = 0;
    if (ied->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(ied->TimeDateStamp, date, sizeof(date));

    printf("IMAGE_EXPORT_DIRECTORY:\n");
    printf(" - Characteristics: 0x%x\n", ied->Characteristics);
    printf(" - TimeDateStamp: %s (0x%x)\n", date, ied->TimeDateStamp);
    printf(" - MajorVersion: %u\n", ied->MajorVersion);
    printf(" - MinorVersion: %u\n", ied->MinorVersion);
    printf(" - Name: 0x%x\n", ied->Name);
    printf(" - Base: 0x%x\n", ied->Base);
    printf(" - NumberOfFunctions: 0x%x (%u)\n", ied->NumberOfFunctions, ied->NumberOfFunctions);
    printf(" - NumberOfNames: 0x%x (%u)\n", ied->NumberOfNames, ied->NumberOfNames);
    printf(" - AddressOfFunctions: 0x%x\n", ied->AddressOfFunctions);
    printf(" - AddressOfNames: 0x%x\n", ied->AddressOfNames);
    printf(" - AddressOfNameOrdinals: 0x%x\n", ied->AddressOfNameOrdinals);
    printf("\n");
}

void PE_printImageExportDirectoryHeader()
{
    printf(" - List of exported functions:\n");
}

void PE_printImageExportDirectoryEntry(size_t i, 
                                       PE_IMAGE_EXPORT_DIRECTORY *ied,
                                       const char* name, 
                                       size_t name_max, 
                                       uint16_t name_ordinal, 
                                       uint8_t* bytes, 
                                       size_t bytes_max, 
                                       uint32_t rva, 
                                       size_t fo, 
                                       int is_forwarded)
{
    size_t j;
    size_t nr_of_bytes = 0x10;
    if ( nr_of_bytes > bytes_max )
        nr_of_bytes = bytes_max;

    printf("   [%zu/%u] \n", (i+1), ied->NumberOfFunctions);
    if ( name[0] != 0 )
        printf("   - name: %s\n", name);
    else
        printf("   - name: %s\n", "(none)");
    printf("   - ordinal: 0x%x (%u)\n", name_ordinal+ied->Base, name_ordinal+ied->Base);
    if ( is_forwarded )
    {
        printf("   - forwarded:\n");
        printf("     %s\n", bytes);
    }
    else
    {
        printf("   - function (rva: 0x%x, fo: 0x%zx):\n     ", rva, fo);
        for ( j = 0; j < nr_of_bytes; j++ )
            printf("%02x ", bytes[j]);
        printf("...\n");
    }
}

void PE_printImageLoadConfigDirectory(PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
                                      size_t offset, 
                                      int bitness,
                                      PLoadConfigTableOffsets to,
                                      size_t file_size,
                                      FILE* fp,
                                      uint8_t* block_s)
{
    struct PE_IMAGE_LOAD_CONFIG_DIRECTORY_OFFSETS offsets = (bitness == 32) ?
                                                            PeImageLoadConfigDirectoryOffsets32 :
                                                            PeImageLoadConfigDirectoryOffsets64;

    char date[32];
    date[0] = 0;
    if (lcd->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(lcd->TimeDateStamp, date, sizeof(date));

    const char* f_pre = "   - ";
    const char f_post = '\n';

    printf("IMAGE_DIRECTORY_LOAD_CONFIG:\n");
    printf(" - Size: 0x%x\n", lcd->Size);
    printf(" - TimeDateStamp%s: %s (0x%x)\n", fillOffset(offsets.Size, offset, 0), date, lcd->TimeDateStamp);
    printf(" - MajorVersion%s: %u\n", fillOffset(offsets.MajorVersion, offset, 0), lcd->MajorVersion);
    printf(" - MinorVersion%s: %u\n", fillOffset(offsets.MinorVersion, offset, 0), lcd->MinorVersion);
    printf(" - GlobalFlagsClear%s: 0x%x\n", fillOffset(offsets.GlobalFlagsClear, offset, 0), lcd->GlobalFlagsClear);
    printf(" - GlobalFlagsSet%s: 0x%x\n", fillOffset(offsets.GlobalFlagsSet, offset, 0), lcd->GlobalFlagsSet);
    printf(" - CriticalSectionDefaultTimeout%s: 0x%x\n", fillOffset(offsets.CriticalSectionDefaultTimeout, offset, 0), lcd->CriticalSectionDefaultTimeout);
    printf(" - DeCommitFreeBlockThreshold%s: 0x%"PRIx64"\n", fillOffset(offsets.DeCommitFreeBlockThreshold, offset, 0), lcd->DeCommitFreeBlockThreshold);
    printf(" - DeCommitTotalFreeThreshold%s: 0x%"PRIx64"\n", fillOffset(offsets.DeCommitTotalFreeThreshold, offset, 0), lcd->DeCommitTotalFreeThreshold);
    printf(" - LockPrefixTable%s: 0x%"PRIx64"\n", fillOffset(offsets.LockPrefixTable, offset, 0), lcd->LockPrefixTable);
    printf(" - MaximumAllocationSize%s: 0x%"PRIx64"\n", fillOffset(offsets.MaximumAllocationSize, offset, 0), lcd->MaximumAllocationSize);
    printf(" - VirtualMemoryThreshold%s: 0x%"PRIx64"\n", fillOffset(offsets.VirtualMemoryThreshold, offset, 0), lcd->VirtualMemoryThreshold);
    printf(" - ProcessAffinityMask%s: 0x%"PRIx64"\n", fillOffset(offsets.ProcessAffinityMask, offset, 0), lcd->ProcessAffinityMask);
    printf(" - ProcessHeapFlags%s: 0x%x\n", fillOffset(offsets.ProcessHeapFlags, offset, 0), lcd->ProcessHeapFlags);
    printf(" - CSDVersion%s: 0x%u\n", fillOffset(offsets.CSDVersion, offset, 0), lcd->CSDVersion);
    printf(" - DependentLoadFlags%s: 0x%u\n", fillOffset(offsets.DependentLoadFlags, offset, 0), lcd->DependentLoadFlags);
    printf(" - EditList%s: 0x%"PRIx64"\n", fillOffset(offsets.EditList, offset, 0), lcd->EditList);
    printf(" - SecurityCookie%s: 0x%"PRIx64"\n", fillOffset(offsets.SecurityCookie, offset, 0), lcd->SecurityCookie);
    printf(" - SEHandlerTable%s: 0x%"PRIx64"\n", fillOffset(offsets.SEHandlerTable, offset, 0), lcd->SEHandlerTable);
    printf(" - SEHandlerCount%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.SEHandlerCount, offset, 0), lcd->SEHandlerCount, lcd->SEHandlerCount);
    PE_printSizedRVAArray(lcd->SEHandlerCount, to->seh, file_size, fp, block_s);

    printf(" - GuardCFCheckFunctionPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardCFCheckFunctionPointer, offset, 0), lcd->GuardCFCheckFunctionPointer);
    printf(" - GuardCFDispatchFunctionPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardCFDispatchFunctionPointer, offset, 0), lcd->GuardCFDispatchFunctionPointer);
    printf(" - GuardCFFunctionTable%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardCFFunctionTable, offset, 0), lcd->GuardCFFunctionTable);
    printf(" - GuardCFFunctionCount%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.GuardCFFunctionCount, offset, 0), lcd->GuardCFFunctionCount, lcd->GuardCFFunctionCount);
    PE_printSizedRVAArray(lcd->GuardCFFunctionCount, to->fun, file_size, fp, block_s);

    printf(" - GuardFlags%s: 0x%x\n", fillOffset(offsets.GuardFlags, offset, 0), lcd->GuardFlags);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_INSTRUMENTED, "PE_IMAGE_GUARD_CF_INSTRUMENTED", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CFW_INSTRUMENTED, "PE_IMAGE_GUARD_CFW_INSTRUMENTED", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, "PE_IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_SECURITY_COOKIE_UNUSED, "PE_IMAGE_GUARD_SECURITY_COOKIE_UNUSED", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, "PE_IMAGE_GUARD_PROTECT_DELAYLOAD_IAT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION, "PE_IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT, "PE_IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION, "PE_IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT, "PE_IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_RF_INSTRUMENTED, "PE_IMAGE_GUARD_RF_INSTRUMENTED", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_RF_ENABLE, "PE_IMAGE_GUARD_RF_ENABLE", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_RF_STRICT, "PE_IMAGE_GUARD_RF_STRICT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_RETPOLINE_PRESENT, "PE_IMAGE_GUARD_RETPOLINE_PRESENT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, "PE_IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK, "PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK", f_pre, f_post);
    printFlag32F(lcd->GuardFlags, PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT, "PE_IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT", f_pre, f_post);
    printf(" - CodeIntegrity\n");
    printf("   - Flags%s: 0x%u\n", fillOffset(offsets.CodeIntegrity+PeImageLoadConfigCodeIntegrityOffsets.Flags, offset, 0), lcd->CodeIntegrity.Flags);
    printf("   - Catalog%s: 0x%u\n", fillOffset(offsets.CodeIntegrity+ PeImageLoadConfigCodeIntegrityOffsets.Catalog, offset, 0), lcd->CodeIntegrity.Catalog);
    printf("   - CatalogOffset%s: 0x%x\n", fillOffset(offsets.CodeIntegrity+PeImageLoadConfigCodeIntegrityOffsets.CatalogOffset, offset, 0), lcd->CodeIntegrity.CatalogOffset);
    printf("   - Reserved%s: 0x%x\n", fillOffset(offsets.CodeIntegrity+ PeImageLoadConfigCodeIntegrityOffsets.Reserved, offset, 0), lcd->CodeIntegrity.Reserved);
    printf(" - GuardAddressTakenIatEntryTable%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardAddressTakenIatEntryTable, offset, 0), lcd->GuardAddressTakenIatEntryTable);
    printf(" - GuardAddressTakenIatEntryCount%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.GuardAddressTakenIatEntryCount, offset, 0), lcd->GuardAddressTakenIatEntryCount, lcd->GuardAddressTakenIatEntryCount);
    PE_printSizedRVAArray(lcd->GuardAddressTakenIatEntryCount, to->iat, file_size, fp, block_s);

    printf(" - GuardLongJumpTargetTable%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardLongJumpTargetTable, offset, 0), lcd->GuardLongJumpTargetTable);
    printf(" - GuardLongJumpTargetCount%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.GuardLongJumpTargetCount, offset, 0), lcd->GuardLongJumpTargetCount, lcd->GuardLongJumpTargetCount);
    PE_printSizedRVAArray(lcd->GuardLongJumpTargetCount, to->jmp, file_size, fp, block_s);

    printf(" - DynamicValueRelocTable%s: 0x%"PRIx64"\n", fillOffset(offsets.DynamicValueRelocTable, offset, 0), lcd->DynamicValueRelocTable);
    printf(" - CHPEMetadataPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.CHPEMetadataPointer, offset, 0), lcd->CHPEMetadataPointer);
    printf(" - GuardRFFailureRoutine%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardRFFailureRoutine, offset, 0), lcd->GuardRFFailureRoutine);
    printf(" - GuardRFFailureRoutineFunctionPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardRFFailureRoutineFunctionPointer, offset, 0), lcd->GuardRFFailureRoutineFunctionPointer);
    printf(" - DynamicValueRelocTableOffset%s: 0x%x\n", fillOffset(offsets.DynamicValueRelocTableOffset, offset, 0), lcd->DynamicValueRelocTableOffset);
    printf(" - DynamicValueRelocTableSection%s: 0x%u\n", fillOffset(offsets.DynamicValueRelocTableSection, offset, 0), lcd->DynamicValueRelocTableSection);
    printf(" - Reserved2%s: 0x%u\n", fillOffset(offsets.Reserved2, offset, 0), lcd->Reserved2);
    printf(" - GuardRFVerifyStackPointerFunctionPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardRFVerifyStackPointerFunctionPointer, offset, 0), lcd->GuardRFVerifyStackPointerFunctionPointer);
    printf(" - HotPatchTableOffset%s: 0x%x\n", fillOffset(offsets.HotPatchTableOffset, offset, 0), lcd->HotPatchTableOffset);
    printf(" - Reserved3%s: 0x%x\n", fillOffset(offsets.Reserved3, offset, 0), lcd->Reserved3);
    printf(" - EnclaveConfigurationPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.EnclaveConfigurationPointer, offset, 0), lcd->EnclaveConfigurationPointer);
    printf(" - VolatileMetadataPointer%s: 0x%"PRIx64"\n", fillOffset(offsets.VolatileMetadataPointer, offset, 0), lcd->VolatileMetadataPointer);
    printf(" - GuardEHContinuationTable%s: 0x%"PRIx64"\n", fillOffset(offsets.GuardEHContinuationTable, offset, 0), lcd->GuardEHContinuationTable);
    printf(" - GuardEHContinuationCount%s: 0x%"PRIx64" (%"PRIu64")\n", fillOffset(offsets.GuardEHContinuationCount, offset, 0), lcd->GuardEHContinuationCount, lcd->GuardEHContinuationCount);
    PE_printSizedRVAArray(lcd->GuardEHContinuationCount, to->ehc, file_size, fp, block_s);
    printf("\n");
}

void PE_printSizedRVAArray(uint64_t count, 
                           size_t offset, 
                           size_t file_size,
                           FILE* fp,
                           uint8_t* block_s)
{
    size_t bytes_read;
    uint64_t i, j;
    uint8_t ptr_size = 4;
    uint32_t ptr;

    if ( count > 0 && offset < file_size )
    {
        bytes_read = readFile(fp, (size_t)offset, BLOCKSIZE_SMALL, block_s);
        if ( bytes_read < ptr_size )
        {
            header_error("ERROR: read less than expected!\n")
            return;
        }
        
        for ( i = 0, j=0; i < count; i++, j+=ptr_size)
        {
            if ( j > bytes_read - ptr_size )
            {
                offset += bytes_read;
                if ( offset > file_size - ptr_size )
                    break;

                bytes_read = readFile(fp, (size_t)offset, BLOCKSIZE_SMALL, block_s);
                if ( bytes_read < ptr_size )
                {
                    header_error("ERROR: read less than expected!\n")
                    break;
                }
                j = 0;
            }

            ptr = *((uint32_t*)&block_s[j]);

            printf("     %08X\n", ptr);
        }
    }
}

void PE_printAttributeCertificateTable(PeAttributeCertificateTable* t, uint8_t n, size_t offset)
{
    uint8_t i;
    PeAttributeCertificateTable* entry;

    printf("Attribute Certificate Table (%u):\n", n);
    for ( i = 0; i < n; i++ )
    {
        entry = &t[i];

        printf(" - %u/%u\n", i+1u, n);
        printf("   - length%s: 0x%x\n", fillOffset(PeAttributeCertificateTableOffsets.dwLength, offset, 0), entry->dwLength);
        printf("   - revision%s: 0x%x\n", fillOffset(PeAttributeCertificateTableOffsets.wRevision, offset, 0), entry->wRevision);
        printf("   - certificateType%s: %s (0x%x)\n", fillOffset(PeAttributeCertificateTableOffsets.wCertificateType, offset, 0), PE_getCertificateTypeString(entry->wCertificateType), entry->wCertificateType);
        printf("   - certificate (offset)%s: %p\n", fillOffset(PeAttributeCertificateTableOffsets.bCertificate, offset, 0), (void*)entry->bCertificate);

        offset += entry->dwLength;
    }
}

const char* PE_getCertificateTypeString(uint16_t type)
{
    switch ( type)
    {
        case WIN_CERT_TYPE_X509:
            return "X.509 Certificate (Not Supported)";
        case WIN_CERT_TYPE_PKCS_SIGNED_DATA:
            return "PKCS#7 SignedData structure";
        case WIN_CERT_TYPE_RESERVED_1:
            return "(Reserved)";
        case WIN_CERT_TYPE_TS_STACK_SIGNED:
            return "Terminal Server Protocol Stack Certificate signing (Not Supported)";
        default:
            return "None";
    }
}

//#define WIN_CERT_TYPE_X509 (0x0001) // bCertificate contains an X.509 Certificate. Not Supported
//#define WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002) // bCertificate contains a PKCS#7 SignedData structure
//#define WIN_CERT_TYPE_RESERVED_1 (0x0003) //  Reserved
//#define WIN_CERT_TYPE_TS_STACK_SIGNED (0x0004) // Terminal Server Protocol Stack Certificate signing. Not Supported

void fillSpaces(char* buf, size_t n, uint16_t level)
{
//	memset(&spaces, 0, n);
    if ( n == 0 || buf == NULL )
        return;
    size_t min = (n-1 < level*2u) ? n-1 : level*2u;
    memset(buf, ' ', min);
    buf[min] = 0;
//	size_t i;
//	spaces[0] = ' ';
//	for ( i = 0; i < n && i < level; i++ )
//	{
//		buf[i*2+1] = ' ';
//		buf[i*2+2] = ' ';
//	}
}

//void fillDashes(size_t n, uint16_t level, char* spaces)
//{
//	memset(&spaces, 0, n);
//	size_t i;
//	size_t max_i = n > 1;
//	spaces[0] = ' ';
//	for ( i = 0; i < max_i && i < level; i++ )
//	{
//		spaces[i*2+1] = '-';
//		spaces[i*2+2] = ' ';
//	}
//}



void PE_printImageResourceDirectory(const PE_IMAGE_RESOURCE_DIRECTORY* rd, size_t offset, uint16_t level)
{
    char spaces[MAX_SPACES];
    fillSpaces(spaces, MAX_SPACES, level);

    char date[32];
    date[0] = 0;
    if (rd->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(rd->TimeDateStamp, date, sizeof(date));

    printf("%sResource Directory%s:\n", spaces, fillOffset(0, offset, 0));
    printf("%s- Characteristics: 0x%x\n", spaces, rd->Characteristics);
    printf("%s- TimeDateStamp: %s (0x%x)\n", spaces, date, rd->TimeDateStamp);
    printf("%s- MajorVersion: %u\n", spaces, rd->MajorVersion);
    printf("%s- MinorVersion: %u\n", spaces, rd->MinorVersion);
    printf("%s- NumberOfNamedEntries: 0x%x\n", spaces, rd->NumberOfNamedEntries);
    printf("%s- NumberOfIdEntries: 0x%x\n", spaces, rd->NumberOfIdEntries);
}

void PE_printImageResourceDirectoryEntryHeader(int type, uint16_t n, uint16_t level)
{
    char spaces[MAX_SPACES];
    fillSpaces(spaces, MAX_SPACES, level);
    
    if ( type == 0 )
        printf("%s- Named Entries (%u):\n", spaces, n);
    else if ( type == 1 )
        printf("%s- ID Entries (%u):\n", spaces, n);
}

void PE_printImageResourceDirectoryEntry(
    const PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
    size_t table_fo,
    size_t offset,
    uint16_t level,
    uint16_t id,
    uint16_t n,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
)
{
    size_t name_offset = 0;
    size_t bytes_read = 0;
    size_t i = 0;
    uint8_t* ptr = NULL;
    PE_IMAGE_RESOURCE_DIR_STRING_U_PTR name;
    const struct Pe_Image_Resource_Dir_String_U_Offsets *name_offsets = &PeImageResourceDirStringUOffsets;

    char spaces[MAX_SPACES];
    fillSpaces(spaces, MAX_SPACES, level);
    
    printf("%s  %u/%u%s:\n", spaces, (id+1u), n, fillOffset(0, offset, 0));
    
    if ( re->NAME_UNION.NAME_STRUCT.NameIsString )
    {
        name_offset = table_fo + re->NAME_UNION.NAME_STRUCT.NameOffset;
        if ( !checkFileSpace(name_offset, start_file_offset, 4, file_size) )
        {
            header_error("ERROR: Resource name offset beyond file bounds!\n");
            return;
        }

        name_offset = name_offset + start_file_offset;
        bytes_read = readFile(fp, (size_t)name_offset, BLOCKSIZE_SMALL, block_s);
        if ( bytes_read <= 4 )
            return;

        ptr = block_s;
        name.Length = GetIntXValueAtOffset(uint16_t, ptr, name_offsets->Length);
        name.NameString = ((uint16_t*) &ptr[name_offsets->NameString]);
        if ( name.Length > (uint16_t)bytes_read - 4 ) // minus length - L'0'
            name.Length = (uint16_t)bytes_read-4;
        ptr[bytes_read-2] = 0;
        ptr[bytes_read-1] = 0;

        if ( !checkFileSpace(name_offset, start_file_offset, 2+name_offsets->Length, file_size))
        {
            header_error("ERROR: Resource name beyond file bounds!\n");
            return;
        }

        // wchar on linux is uint32_t
        // TODO: convert windows wchar(uint16_t) to utf8 to print cross os without expecting it to be ascii
        // hack: considering it ascii
        printf("%s  - Name (%u): ", spaces, name.Length);
        for ( i = 0; i < name.Length; i++ )
            printf("%c", name.NameString[i]);
        printf("\n");
    }
    // id entries have ids
    else
    {
        printf("%s  - Id: 0x%x\n", spaces, re->NAME_UNION.Id);
    }
    printf("%s  - OffsetToData: 0x%x\n", spaces, re->OFFSET_UNION.OffsetToData);
    printf("%s    - OffsetToData.OffsetToDirectory: 0x%x\n", spaces, re->OFFSET_UNION.DATA_STRUCT.OffsetToDirectory);
    printf("%s    - OffsetToData.NameIsDirectory: 0x%x\n", spaces, re->OFFSET_UNION.DATA_STRUCT.DataIsDirectory);
}

void PE_printImageResourceDataEntry(
    const PE_IMAGE_RESOURCE_DATA_ENTRY* de, 
    uint32_t fotd, 
    size_t offset, 
    uint16_t level
)
{
    char spaces[MAX_SPACES];
    fillSpaces(spaces, MAX_SPACES, level);
    
    printf("%s  - ResourceDataEntry%s:\n", spaces, fillOffset(0, offset, 0));
    //printf("%s    - OffsetToData rva: 0x%x, fo: 0x%x\n", spaces, de->OffsetToData, fotd);
    //printf("%s    - OffsetToData: 0x%x (rva), 0x%x (fo)\n", spaces, de->OffsetToData, fotd);
    printf("%s    - OffsetToData\n", spaces);
    printf("%s        rva: 0x%x\n", spaces, de->OffsetToData);
    printf("%s         fo: 0x%x\n", spaces, fotd);
    printf("%s    - Size: 0x%x\n", spaces, de->Size);
    printf("%s    - CodePage: 0x%x\n", spaces, de->CodePage);
    printf("%s    - Reserved: 0x%x\n", spaces, de->Reserved);
}





void PE_printImageTLSTableHeader()
{
    printf("TLS Table:\n");
}

void PE_printTLSEntry(PE_IMAGE_TLS_DIRECTORY64* tls, 
                      uint32_t i, 
                      uint8_t bitness, 
                      size_t start_file_offset,
                      size_t s_offset,
                      size_t e_offset,
                      size_t cb_offset,
                      size_t file_size,
                      FILE* fp,
                      uint8_t* block_s)
{
    struct PE_IMAGE_TLS_DIRECTORY_OFFSETS offsets = (bitness == 32)
        ? PeImageTlsDirectoryOfsets32
        : PeImageTlsDirectoryOfsets64;

    size_t bi;
    size_t size;
    uint8_t ptr_size = (bitness == 32) ? 4 : 8;
    size_t cb;
    int loop;

    printf(" - TLS %u:\n", i);
    printf("   - StartAddressOfRawData%s: 0x%"PRIx64"\n", fillOffset(offsets.StartAddressOfRawData, 0, start_file_offset), tls->StartAddressOfRawData);
    printf("   - EndAddressOfRawData%s: 0x%"PRIx64"\n", fillOffset(offsets.EndAddressOfRawData, 0, start_file_offset), tls->EndAddressOfRawData);
    if (s_offset < e_offset && e_offset < file_size)
    {
        size = e_offset - s_offset;
        if ( size > BLOCKSIZE_SMALL )
            size = BLOCKSIZE_SMALL;
        size = readFile(fp, s_offset, size, block_s);
        if (size != 0)
        {
            printf("       ");
            for ( bi = 0; bi < size; bi++ )
                printf("%02x|", block_s[bi]);
            printf("\n");
        }
    }
    printf("   - AddressOfIndex%s: 0x%"PRIx64"\n", fillOffset(offsets.AddressOfIndex, 0, start_file_offset), tls->AddressOfIndex);
    printf("   - AddressOfCallBacks%s: 0x%"PRIx64"\n", fillOffset(offsets.AddressOfCallBacks, 0, start_file_offset), tls->AddressOfCallBacks);
    if (cb_offset < file_size - ptr_size)
    {
        loop = 1;
        while (loop)
        {
            if (cb_offset > file_size - ptr_size)
                break;

            size = readFile(fp, cb_offset, BLOCKSIZE_SMALL, block_s);
            if (size == 0)
                break;

            for ( bi = 0; bi < size; bi+=ptr_size )
            {
                if ( bitness == 32 )
                    cb = *((uint32_t*)&block_s[bi]);
                else
                    cb = *((size_t*)&block_s[bi]);
                printf("       %0.*zx\n", (ptr_size*2), cb);
                
                if ( cb == 0 )
                {
                    loop = 0;
                    break;
                }
            }

            cb_offset += BLOCKSIZE_SMALL;
        }
    }
    printf("   - SizeOfZeroFill%s: 0x%x\n", fillOffset(offsets.SizeOfZeroFill, 0, start_file_offset), tls->SizeOfZeroFill);
    printf("   - Characteristics%s: 0x%08x:\n", fillOffset(offsets.Characteristics, 0, start_file_offset), tls->DUMMYUNIONNAME.Characteristics);
    printf("     - Reserved0%s: 0x%x\n", fillOffset(offsets.Characteristics, 0, start_file_offset), tls->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Reserved0);
    printf("     - Alignment%s: %s (0x%x)\n", fillOffset(offsets.Characteristics, 0, start_file_offset), PE_getImageSecAlignmentString(tls->DUMMYUNIONNAME.Characteristics), tls->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Alignment);
    printf("     - Reserved1%s: 0x%x\n", fillOffset(offsets.Characteristics, 0, start_file_offset), tls->DUMMYUNIONNAME.DUMMYSTRUCTNAME.Reserved1);
}

#define PE_IMAGE_SCN_ALIGN_MASK (0x00F00000)
const char* PE_getImageSecAlignmentString(uint32_t ch)
{
    uint32_t a = ch & PE_IMAGE_SCN_ALIGN_MASK;

    switch ( a )
    {
        case 0x00100000:
            return "IMAGE_SCN_ALIGN_1BYTES";
        case 0x00200000:
            return "IMAGE_SCN_ALIGN_2BYTES";
        case 0x00300000:
            return "IMAGE_SCN_ALIGN_4BYTES";
        case 0x00400000:
            return "IMAGE_SCN_ALIGN_8BYTES";
        case 0x00500000:
            return "IMAGE_SCN_ALIGN_16BYTES";
        case 0x00600000:
            return "IMAGE_SCN_ALIGN_32BYTES";
        case 0x00700000:
            return "IMAGE_SCN_ALIGN_64BYTES";
        case 0x00800000:
            return "IMAGE_SCN_ALIGN_128BYTES";
        case 0x00900000:
            return "IMAGE_SCN_ALIGN_256BYTES";
        case 0x00a00000:
            return "IMAGE_SCN_ALIGN_512BYTES";
        case 0x00b00000:
            return "IMAGE_SCN_ALIGN_1024BYTES";
        case 0x00c00000:
            return "IMAGE_SCN_ALIGN_2048BYTES";
        case 0x00d00000:
            return "IMAGE_SCN_ALIGN_4096BYTES";
        case 0x00e00000:
            return "IMAGE_SCN_ALIGN_8192BYTES";
        default:
            return "NONE";
    }
}




void PE_printImageBaseRelocationTable()
{
    printf("Base Relocation Table:\n");
}

void PE_printImageBaseRelocationBlockHeader(PE_BASE_RELOCATION_BLOCK* b, uint32_t i, size_t start_file_offset)
{
    printf(" - Block %u:\n", i);
    printf("   - Virtual Address%s: 0x%x:\n", fillOffset(PeBaseRelocationBlockOffsets.VirtualAddress, 0, start_file_offset), b->VirtualAddress);
    printf("   - SizeOfBlock%s: 0x%x:\n", fillOffset(PeBaseRelocationBlockOffsets.SizeOfBlock, 0, start_file_offset), b->SizeOfBlock);
}

const char* PeBaseRelocationTypeStrings[] = {
    "IMAGE_REL_BASED_ABSOLUTE",
    "IMAGE_REL_BASED_HIGH",
    "IMAGE_REL_BASED_LOW",
    "IMAGE_REL_BASED_HIGHLOW",
    "IMAGE_REL_BASED_HIGHADJ",
    "IMAGE_REL_BASED_MIPS_JMPADDR | IMAGE_REL_BASED_ARM_MOV32 | IMAGE_REL_BASED_RISCV_HIGH20",
    "IMAGE_REL_BASED_RESERVED",
    "IMAGE_REL_BASED_THUMB_MOV32 | IMAGE_REL_BASED_RISCV_LOW12I",
    "IMAGE_REL_BASED_RISCV_LOW12S",
    "IMAGE_REL_BASED_MIPS_JMPADDR16",
    "IMAGE_REL_BASED_DIR64",
};
#define PeBaseRelocationTypeStrings_SIZE (sizeof(PeBaseRelocationTypeStrings)/sizeof(char*))

void PE_printImageBaseRelocationBlockEntry(PE_BASE_RELOCATION_ENTRY* e)
{
    uint16_t type = e->Data >> 12;
    uint16_t offset = e->Data & 0x0FFF;
    const char* type_str = (type < PeBaseRelocationTypeStrings_SIZE) ? PeBaseRelocationTypeStrings[type] : "NONE";

    printf("     - 0x%04x | %s (%u)\n", offset, type_str, type);
}




void PE_printDebugTableHeader()
{
    printf("Debug Table:\n");
}

const char* Pe_getDebugTypeString(uint32_t type)
{
    switch ( type )
    {
        case PE_IMAGE_DEBUG_TYPE_UNKNOWN: return "UNKNOWN";
        case PE_IMAGE_DEBUG_TYPE_COFF: return "COFF";
        case PE_IMAGE_DEBUG_TYPE_CODEVIEW: return "CODEVIEW";
        case PE_IMAGE_DEBUG_TYPE_FPO: return "FPO";
        case PE_IMAGE_DEBUG_TYPE_MISC: return "MISC";
        case PE_IMAGE_DEBUG_TYPE_EXCEPTION: return "EXCEPTION";
        case PE_IMAGE_DEBUG_TYPE_FIXUP: return "FIXUP";
        case PE_IMAGE_DEBUG_TYPE_OMAP_TO_SRC: return "OMAP_TO_SRC";
        case PE_IMAGE_DEBUG_TYPE_OMAP_FROM_SRC: return "OMAP_FROM_SRC";
        case PE_IMAGE_DEBUG_TYPE_BORLAND: return "BORLAND";
        case PE_IMAGE_DEBUG_TYPE_RESERVED10: return "RESERVED10";
        case PE_IMAGE_DEBUG_TYPE_CLSID: return "CLSID";
        case PE_IMAGE_DEBUG_TYPE_VC_FEATURE: return "VC_FEATURE";
        case PE_IMAGE_DEBUG_TYPE_POGO: return "POGO";
        case PE_IMAGE_DEBUG_TYPE_ILTCG: return "ILTCG";
        case PE_IMAGE_DEBUG_TYPE_MPX: return "_MPX";
        case PE_IMAGE_DEBUG_TYPE_REPRO: return "REPRO";
        case PE_IMAGE_DEBUG_TYPE_EMBEDED_PDB: return "EMBEDED_PDB";
        case PE_IMAGE_DEBUG_TYPE_PDB_CHECK_SUM: return "PDB_CHECK_SUM";
        case PE_IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS: return "EX_DLLCHARACTERISTICS";
        case PE_IMAGE_DEBUG_TYPE_R2R_PERF_MAP: return "R2R_PERF_MAP";
        default: return "UNKNOWN";
    };
}

void PE_printDebugTableEntry(PE_DEBUG_TABLE_ENTRY* e, uint32_t i, uint32_t nr_of_entries, size_t file_offset)
{
    printf(" - Entry %u / %u:\n", i, nr_of_entries);
    printf("   - Characteristics%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.Characteristics, 0, file_offset), e->Characteristics);
    printf("   - TimeDateStamp%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.TimeDateStamp, 0, file_offset), e->TimeDateStamp);
    printf("   - MajorVersion%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.MajorVersion, 0, file_offset), e->MajorVersion);
    printf("   - MinorVersion%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.MinorVersion, 0, file_offset), e->MinorVersion);
    printf("   - Type%s: %s (0x%x)\n", fillOffset(PeImageDebugTableEntryOffsets.Type, 0, file_offset), Pe_getDebugTypeString(e->Type), e->Type);
    printf("   - SizeOfData%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.SizeOfData, 0, file_offset), e->SizeOfData);
    printf("   - AddressOfRawData%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.AddressOfRawData, 0, file_offset), e->AddressOfRawData);
    printf("   - PointerToRawData%s: 0x%x\n", fillOffset(PeImageDebugTableEntryOffsets.PointerToRawData, 0, file_offset), e->PointerToRawData);
}

int ByteArrayToGUID(uint8_t* ba, int32_t ba_size, char* guid, int32_t guid_size)
{
    if ( ba_size != GUID_BIN_SIZE )
        return -1;
    if ( guid_size < GUID_STR_BUFFER_SIZE )
        return -2;
    
    int32_t i;
    int32_t j;

    for ( i = 3, j = 0; i >= 0; i--, j+=2 )
        sprintf(&guid[j], "%02x", ba[i]);

    guid[8] = '-';

    for ( i = 5, j = 9; i >= 4; i--, j+=2 )
        sprintf(&guid[j], "%02x", ba[i]);


    guid[13] = '-';

    for ( i = 7, j = 14; i >= 6; i--, j+=2 )
        sprintf(&guid[j], "%02x", ba[i]);

    guid[18] = '-';

    for ( i = 8, j = 19; i < 10; i++, j+=2 )
        sprintf(&guid[j], "%02x", ba[i]);

    guid[23] = '-';

    for ( i = 10, j = 24; i < ba_size; i++, j+=2 )
        sprintf(&guid[j], "%02x", ba[i]);
    
    guid[guid_size-1] = 0;

    return 0;
}
void PE_printCodeViewDbgH(PPE_CODEVIEW_DBG_H entry, size_t start_file_offset, uint8_t* block_s)
{
    size_t i;
    char guid_str[GUID_STR_BUFFER_SIZE];
    ByteArrayToGUID(entry->Guid, GUID_BIN_SIZE, guid_str, GUID_STR_BUFFER_SIZE);

    printf("     - CodeView:\n");
    printf("       - Signature%s: %c%c%c%c (0x%x)\n", 
        fillOffset(PeCodeViewDbgHOffsets.Signature, 0, start_file_offset), 
        entry->SignatureA[0], entry->SignatureA[1], entry->SignatureA[2], entry->SignatureA[3], 
        entry->Signature);
    printf("       - Guid%s: ", fillOffset(PeCodeViewDbgHOffsets.Guid, 0, start_file_offset));
    printf("{%s} (", guid_str);
    printf("%02x", entry->Guid[0]);
    for ( i = 1; i < GUID_BIN_SIZE; i++ )
        printf(" %02x", entry->Guid[i]);
    printf(")\n");
    printf("       - Age%s: 0x%x\n", fillOffset(PeCodeViewDbgHOffsets.Age, 0, start_file_offset), entry->Age);
    printf("       - Path%s: %s\n", fillOffset(PeCodeViewDbgHOffsets.Path, 0, start_file_offset), entry->PathPtr);
}



void PE_printImageDelayImportTableHeader(PeImageDelayLoadDescriptor* impd)
{
    if ( isMemZero(impd, sizeof(PeImageDelayLoadDescriptor)) )
        printf("No Delay Image Import Table\n");
    else
        printf("Delay Image Import Table:\n");
}

void PE_printImageDelayImportDescriptor(PeImageDelayLoadDescriptor* did, size_t offset, const char* dll_name)
{
    char ts[32];
    ts[0] = 0;
    if (did->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(did->TimeDateStamp, ts, sizeof(ts));

    printf(" -%s %s (0x%x)\n", fillOffset(PeImageDelayLoadDescriptorOffsets.DllNameRVA, offset, 0), dll_name, did->DllNameRVA);
    printf("   - Attributes%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.Attributes, offset, 0), did->Attributes.AllAttributes);
    printf("   - ModuleHandle%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.ModuleHandleRVA, offset, 0), did->ModuleHandleRVA);
    printf("   - ImportAddressTable%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.ImportAddressTableRVA, offset, 0), did->ImportAddressTableRVA);
    printf("   - ImportNameTable%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.ImportNameTableRVA, offset, 0), did->ImportNameTableRVA);
    printf("   - BoundImportAddressTable%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.BoundImportAddressTableRVA, offset, 0), did->BoundImportAddressTableRVA);
    printf("   - UnloadInformationTable%s: 0x%x\n", fillOffset(PeImageDelayLoadDescriptorOffsets.UnloadInformationTableRVA, offset, 0), did->UnloadInformationTableRVA);
    printf("   - TimeDateStamp%s: %s (0x%x)\n", fillOffset(PeImageDelayLoadDescriptorOffsets.TimeDateStamp, offset, 0), ts, did->TimeDateStamp);
}



void PE_printImageBoundImportTableHeader(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid)
{
    if ( isMemZero(bid, sizeof(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR)) )
        printf("No Bound Import Table\n");
    else
        printf("Bound Image Import Table:\n");
}

void PE_printImageBoundImportDescriptor(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid, size_t offset, const char* dll_name)
{
    char ts[32];
    ts[0] = 0;
    if (bid->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(bid->TimeDateStamp, ts, sizeof(ts));

    printf(" -%s %s (0x%x)\n", fillOffset(PeImageBoundDescriptorOffsets.OffsetModuleName, offset, 0), dll_name, bid->OffsetModuleName);
    printf("   - TimeDateStamp%s: %s (0x%x)\n", fillOffset(PeImageBoundDescriptorOffsets.TimeDateStamp, offset, 0), ts, bid->TimeDateStamp);
    printf("   - NumberOfModuleForwarderRefs%s: 0x%x\n", fillOffset(PeImageBoundDescriptorOffsets.NumberOfModuleForwarderRefs, offset, 0), bid->NumberOfModuleForwarderRefs);
}

void PE_printImageBoundForwarderRef(PE_IMAGE_BOUND_FORWARDER_REF* bfr, size_t offset, const char* dll_name, uint16_t i, uint16_t n)
{
    char ts[32];
    ts[0] = 0;
    if (bfr->TimeDateStamp != (uint32_t)-1)
        formatTimeStampD(bfr->TimeDateStamp, ts, sizeof(ts));

    printf("   - [%u/%u]%s %s (0x%x)\n", i, n, fillOffset(PeImageBoundForwarderRefOffsets.OffsetModuleName, offset, 0), dll_name, bfr->OffsetModuleName);
    printf("     - TimeDateStamp%s: %s (0x%x)\n", fillOffset(PeImageBoundForwarderRefOffsets.TimeDateStamp, offset, 0), ts, bfr->TimeDateStamp);
    printf("     - Reserved%s: 0x%x\n", fillOffset(PeImageBoundForwarderRefOffsets.Reserved, offset, 0), bfr->Reserved);
}

#endif
