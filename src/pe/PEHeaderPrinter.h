#ifndef HEADER_PARSER_PE_HEADER_PRINTER_H
#define HEADER_PARSER_PE_HEADER_PRINTER_H

#include <stdio.h>
#include <stdint.h>

#include "../Globals.h"
#include "../utils/Converter.h"
#include "../utils/Helper.h"
#include "PEHeader.h"
#include "PEHeaderOffsets.h"
#include "PEOptionalHeaderSignature.h"
#include "PEHeaderSectionNameResolution.h"
#include "PEMachineTypes.h"
#include "PEWindowsSubsystem.h"
#include "PECharacteristics.h"

void PE_printImageDosHeader(PEImageDosHeader* image_dos_header, uint64_t start_file_offset);
void PE_printCoffFileHeader(PECoffFileHeader* ch, uint64_t offset, uint64_t start_file_offset);
//char* PE_getMachineName(PeMachineTypes type);
void PE_printOptionalHeader(PE64OptHeader* oh, uint64_t offset, uint64_t start_file_offset, uint8_t bitness);
void PE_printDataDirectory(PE64OptHeader* oh, uint64_t offset, uint8_t bitness);
void PE_printImageSectionHeader(PEImageSectionHeader* sh,
                                uint16_t idx,
                                uint16_t size,
                                PECoffFileHeader* ch,
                                uint64_t offset,
                                uint64_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s,
                                PStringTable st);
const char* PE_getSubsystemName(enum PEWinudowsSubsystem type);

void PE_printImageImportTableHeader(PEImageImportDescriptor* impd);
void PE_printImageImportDescriptor(PEImageImportDescriptor* impd, 
                                   uint64_t offset, 
                                   const char* impd_name);
void PE_printHintFunctionHeader();
void PE_printImageThunkData(PEImageThunkData64* td, PEImageImportByName* ibn, uint64_t td_offset, uint64_t ibn_offset, uint8_t bitness);

void PE_printImageExportDirectoryInfo(PE_IMAGE_EXPORT_DIRECTORY* ied);
void PE_printImageExportDirectoryHeader();
void PE_printImageExportDirectoryEntry(size_t i, uint32_t n_fun, const char* name, int name_max, uint16_t name_ordinal, unsigned char* bytes, size_t bytes_max, uint32_t rva, uint64_t fo);

void PE_printAttributeCertificateTable(PeAttributeCertificateTable* t, uint8_t n, uint64_t offset);
const char* PE_getCertificateTypeString(uint16_t type);
void PE_printImageResourceDirectoryEntryHeader(int type, uint16_t n, uint16_t level);
void PE_printImageResourceDirectoryEntry(const PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                         uint64_t table_fo,
                                         uint64_t offset,
                                         uint16_t level,
                                         uint16_t id,
                                         uint16_t n,
                                         uint64_t start_file_offset,
                                         size_t file_size,
                                         FILE* fp,
                                         unsigned char* block_s);

void PE_printImageBaseRelocationTable();
void PE_printImageBaseRelocationBlockHeader(PE_BASE_RELOCATION_BLOCK* b, 
                                            uint32_t i,
                                            uint64_t start_file_offset);
void PE_printImageBaseRelocationBlockEntry(PE_BASE_RELOCATION_ENTRY* e);

void PE_printImageDelayImportTableHeader(PeImageDelayImportDescriptor* did);
void PE_printImageDelayImportDescriptor(PeImageDelayImportDescriptor* did,
                                        uint64_t offset, 
                                        const char* dll_name);


#define MAX_SPACES (512)
void fillSpaces(char* buf, size_t n, uint16_t level);
//#define MAX_DASHES (512)
//void fillDashes(char* buf, size_t n, uint16_t level);



const char* ImageDirectoryEntryNames[] = {
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "CERTIFICATE",
    "BASE_RELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR_RUNTIME_HEADER",
    "RESERVED",
};



void PE_printImageDosHeader(PEImageDosHeader* image_dos_header, uint64_t start_file_offset)
{
    printf("PE Image Dos Header:\n");
    printf(" - signature%s: %c|%c\n", fillOffset(PEImageDosHeaderOffsets.signature, 0, start_file_offset), image_dos_header->signature[0], image_dos_header->signature[1]);
    printf(" - lastsize%s: %u\n", fillOffset(PEImageDosHeaderOffsets.lastsize, 0, start_file_offset), image_dos_header->lastsize);
    printf(" - nblocks%s: %u\n", fillOffset(PEImageDosHeaderOffsets.nblocks, 0, start_file_offset), image_dos_header->nblocks);
    printf(" - nreloc%s: %u\n", fillOffset(PEImageDosHeaderOffsets.nreloc, 0, start_file_offset), image_dos_header->nreloc);
    printf(" - hdrsize%s: %u\n", fillOffset(PEImageDosHeaderOffsets.hdrsize, 0, start_file_offset), image_dos_header->hdrsize);
    printf(" - minalloc%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.minalloc, 0, start_file_offset), image_dos_header->minalloc);
    printf(" - maxalloc%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.maxalloc, 0, start_file_offset), image_dos_header->maxalloc);
    printf(" - ss: 0x%x\n", image_dos_header->ss);
    printf(" - sp: 0x%x\n", image_dos_header->sp);
    printf(" - checksum%s: %u\n", fillOffset(PEImageDosHeaderOffsets.checksum, 0, start_file_offset), image_dos_header->checksum);
    printf(" - ip: 0x%x\n", image_dos_header->ip);
    printf(" - cs: 0x%x\n", image_dos_header->cs);
    printf(" - relocpos%s: 0x%x\n", fillOffset(PEImageDosHeaderOffsets.relocpos, 0, start_file_offset), image_dos_header->relocpos);
    printf(" - noverlay%s: %u\n", fillOffset(PEImageDosHeaderOffsets.noverlay, 0, start_file_offset), image_dos_header->noverlay);
//	printf(" - reserved1: %04x|%04x|%04x|%04x\n", image_dos_header->reserved1[0], image_dos_header->reserved1[1], image_dos_header->reserved1[2], image_dos_header->reserved1[3]);
    printf(" - oem_id%s: %u\n", fillOffset(PEImageDosHeaderOffsets.oem_id, 0, start_file_offset), image_dos_header->oem_id);
    printf(" - oem_info%s: %u\n", fillOffset(PEImageDosHeaderOffsets.oem_info, 0, start_file_offset), image_dos_header->oem_info);
//	printf(" - reserved2: %04x|%04x|%04x|%04x%04x|%04x|%04x|%04x%04x|%04x\n", image_dos_header->reserved2[0], image_dos_header->reserved2[1], image_dos_header->reserved2[2], image_dos_header->reserved2[3], image_dos_header->reserved2[4], image_dos_header->reserved2[5], image_dos_header->reserved2[6], image_dos_header->reserved2[7], image_dos_header->reserved2[8], image_dos_header->reserved2[9]);
    printf(" - e_lfanew%s: 0x%x (%u)\n", fillOffset(PEImageDosHeaderOffsets.e_lfanew, 0, start_file_offset), image_dos_header->e_lfanew, image_dos_header->e_lfanew);
    printf("\n");
}

void PE_printCoffFileHeader(PECoffFileHeader* ch, uint64_t offset, uint64_t start_file_offset)
{
    const char* dll_c_pre = "   - ";
    const char dll_c_post = '\n';
    ArchitectureMapEntry* arch = getArchitecture(ch->Machine, pe_arch_id_mapper, pe_arch_id_mapper_size);
    char ch_bin[17];
    char date[32];
    formatTimeStampD(ch->TimeDateStamp, date, sizeof(date));

    printf("Coff File Header:\n");
    printf(" - Machine%s: %s (0x%X)\n", fillOffset(PECoffFileHeaderOffsets.Machine, offset, start_file_offset), arch->arch.name, ch->Machine);
//	printf(" - Machine%s: %s (0x%X)\n", fillOffset(PECoffFileHeaderOffsets.Machine, offset), PE_getMachineName(ch->Machine), ch->Machine);
    printf(" - NumberOfSections%s: %u\n", fillOffset(PECoffFileHeaderOffsets.NumberOfSections, offset, start_file_offset), ch->NumberOfSections);
    printf(" - TimeDateStamp%s: %s (%u)\n", fillOffset(PECoffFileHeaderOffsets.TimeDateStamp, offset, start_file_offset), date, ch->TimeDateStamp);
    printf(" - PointerToSymbolTable%s: 0x%X (%u)\n", fillOffset(PECoffFileHeaderOffsets.PointerToSymbolTable, offset,
                                                                0), ch->PointerToSymbolTable, ch->PointerToSymbolTable);
    printf(" - NumberOfSymbols%s: %u\n", fillOffset(PECoffFileHeaderOffsets.NumberOfSymbols, offset, start_file_offset), ch->NumberOfSymbols);
    printf(" - SizeOfOptionalHeader%s: %u\n", fillOffset(PECoffFileHeaderOffsets.SizeOfOptionalHeader, offset, start_file_offset), ch->SizeOfOptionalHeader);
    uint16ToBin(ch->Characteristics, ch_bin);
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

void PE_printOptionalHeader(PE64OptHeader* oh, uint64_t offset, uint64_t start_file_offset, uint8_t bitness)
{
    PEOptionalHeaderOffsets offsets = (bitness == 32) ? PEOptional32HeaderOffsets : PEOptional64HeaderOffsets;
    const char* magic_string;
    const char* dll_c_pre = "   - ";
    const char dll_c_post = '\n';

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
    printf(" - MajorLinkerVersion%s: %u\n", fillOffset(offsets.MajorLinkerVersion, offset, start_file_offset), oh->MajorLinkerVersion);
    printf(" - MinorLinkerVersion%s: %u\n", fillOffset(offsets.MinorLinkerVersion, offset, start_file_offset), oh->MinorLinkerVersion);
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
    printf(" - Subsystem%s: %s (%u)\n", fillOffset(offsets.Subsystem, offset, start_file_offset), PE_getSubsystemName((enum PEWinudowsSubsystem)oh->Subsystem), oh->Subsystem);
    printf(" - DllCharacteristics%s: 0x%X (%u)\n", fillOffset(offsets.DllCharacteristics, offset, start_file_offset), oh->DLLCharacteristics, oh->DLLCharacteristics);
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

void PE_printDataDirectory(PE64OptHeader* oh, uint64_t offset, uint8_t bitness)
{
    PEOptionalHeaderOffsets offsets = (bitness == 32 ) ? PEOptional32HeaderOffsets : PEOptional64HeaderOffsets;
    uint64_t dir_offset = offsets.DataDirectories;
    uint8_t size_of_data_entry = sizeof(PEDataDirectory);

    printf(" - DataDirectory        | VirtualAddress |     Size\n");
    uint32_t i;
    uint8_t max_nr_of_rva_to_read = 128;
    uint8_t nr_of_rva_to_read = ( oh->NumberOfRvaAndSizes > max_nr_of_rva_to_read ) ? max_nr_of_rva_to_read : oh->NumberOfRvaAndSizes;

    for ( i = 0; i < nr_of_rva_to_read; i++ )
    {
        if ( i < NUMBER_OF_RVA_AND_SIZES ) printf("   - %-18s%s | ", ImageDirectoryEntryNames[i], fillOffset(dir_offset, offset, 0));
        else printf("   - %18u%s ", i, fillOffset(dir_offset, offset, 0));
        printf("%#14x", oh->DataDirectory[i].VirtualAddress);
        printf(" | %#8x\n", oh->DataDirectory[i].Size);

        dir_offset += size_of_data_entry;
    }
}

void
PE_printImageSectionHeader(PEImageSectionHeader* sh,
                           uint16_t idx,
                           uint16_t size,
                           PECoffFileHeader* ch,
                           uint64_t offset,
                           uint64_t start_file_offset,
                           size_t file_size,
                           FILE* fp,
                           unsigned char* block_s,
                           PStringTable st)
{
    char characteristics_bin[33];
    char* name;
    PE_getRealName(sh->Name, &name, ch, start_file_offset, file_size, fp, block_s, st);

    printf("%u / %u\n", (idx+1), size);
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
    if ( impd->Characteristics != 0 )
        printf("Image Import Table:\n");
    else
        printf("No Image Import Table\n");
}

void PE_printImageImportDescriptor(PEImageImportDescriptor* impd, uint64_t offset, const char* impd_name)
{
    printf(" -%s %s (0x%x)\n", fillOffset(PEImageImportDescriptorOffsets.Name, offset, 0), impd_name, impd->Name);
    printf("   - OriginalFirstThunk%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.Union, offset, 0), impd->OriginalFirstThunk);
    printf("   - TimeDateStamp%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.TimeDateStamp, offset, 0), impd->TimeDateStamp);
    printf("   - ForwarderChain%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.ForwarderChain, offset, 0), impd->ForwarderChain);
    printf("   - FirstThunk%s: 0x%x\n", fillOffset(PEImageImportDescriptorOffsets.FirstThunk, offset, 0), impd->FirstThunk);
}

void PE_printHintFunctionHeader()
{
        printf("   - %s | Function\n", "Ordinal");
        printf("     --------+-----------\n");
}

void PE_printImageThunkData(PEImageThunkData64* td, PEImageImportByName* ibn, uint64_t td_offset, uint64_t ibn_offset, uint8_t bitness)
{
    uint64_t flag = (bitness == 32) ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;

    if ( td->Ordinal & flag )
        printf("      0x%04x%s\n", (uint16_t)(td->Ordinal - IMAGE_ORDINAL_FLAG64), fillOffset(PEImageThunkData64Offsets.u1, td_offset, 0));
    else
        printf("      0x%04x%s | %s%s\n",
                ibn->Hint, fillOffset(PEImageImportByNameOffsets.Hint, ibn_offset, 0), 
                ibn->Name, fillOffset(PEImageImportByNameOffsets.Name, ibn_offset, 0));
}

void PE_printImageExportDirectoryInfo(PE_IMAGE_EXPORT_DIRECTORY* ied)
{
    printf("IMAGE_EXPORT_DIRECTORY:\n");
//#if defined(_WIN32)
//    printf(" - Characteristics: 0x%lx\n", ied->Characteristics);
//    printf(" - TimeDateStamp: 0x%lx\n", ied->TimeDateStamp);
//    printf(" - MajorVersion: 0x%lx\n", ied->MajorVersion);
//    printf(" - MinorVersion: 0x%lx\n", ied->MinorVersion);
//    printf(" - Name: 0x%lx\n", ied->Name);
//    printf(" - Base: 0x%lx\n", ied->Base);
//    printf(" - NumberOfFunctions: 0x%lx\n", ied->NumberOfFunctions);
//    printf(" - NumberOfNames: 0x%lx\n", ied->NumberOfNames);
//    printf(" - AddressOfFunctions: 0x%lx\n", ied->AddressOfFunctions);
//    printf(" - AddressOfNames: 0x%lx\n", ied->AddressOfNames);
//    printf(" - AddressOfNameOrdinals: 0x%lx\n", ied->AddressOfNameOrdinals);
//#else
//    printf(" - Characteristics: 0x%x\n", ied->Characteristics);
//    printf(" - TimeDateStamp: 0x%x\n", ied->TimeDateStamp);
//    printf(" - MajorVersion: 0x%x\n", ied->MajorVersion);
//    printf(" - MinorVersion: 0x%x\n", ied->MinorVersion);
//    printf(" - Name: 0x%x\n", ied->Name);
//    printf(" - Base: 0x%x\n", ied->Base);
//    printf(" - NumberOfFunctions: 0x%x\n", ied->NumberOfFunctions);
//    printf(" - NumberOfNames: 0x%x\n", ied->NumberOfNames);
//    printf(" - AddressOfFunctions: 0x%x\n", ied->AddressOfFunctions);
//    printf(" - AddressOfNames: 0x%x\n", ied->AddressOfNames);
//    printf(" - AddressOfNameOrdinals: 0x%x\n", ied->AddressOfNameOrdinals);
//#endif
    printf(" - Characteristics: 0x%"PRIx32"\n", ied->Characteristics);
    printf(" - TimeDateStamp: 0x%"PRIx32"\n", ied->TimeDateStamp);
    printf(" - MajorVersion: 0x%"PRIx32"\n", ied->MajorVersion);
    printf(" - MinorVersion: 0x%"PRIx32"\n", ied->MinorVersion);
    printf(" - Name: 0x%"PRIx32"\n", ied->Name);
    printf(" - Base: 0x%"PRIx32"\n", ied->Base);
    printf(" - NumberOfFunctions: 0x%"PRIx32"\n", ied->NumberOfFunctions);
    printf(" - NumberOfNames: 0x%"PRIx32"\n", ied->NumberOfNames);
    printf(" - AddressOfFunctions: 0x%"PRIx32"\n", ied->AddressOfFunctions);
    printf(" - AddressOfNames: 0x%"PRIx32"\n", ied->AddressOfNames);
    printf(" - AddressOfNameOrdinals: 0x%"PRIx32"\n", ied->AddressOfNameOrdinals);
    printf("\n");
}

void PE_printImageExportDirectoryHeader()
{
    printf(" - List of exported functions:\n");
}

void PE_printImageExportDirectoryEntry(size_t i, uint32_t n_fun, const char* name, int name_max, uint16_t name_ordinal, unsigned char* bytes, size_t bytes_max, uint32_t rva, uint64_t fo)
{
    size_t j;
    size_t nr_of_bytes = 0x10;
    if ( nr_of_bytes > bytes_max )
        nr_of_bytes = bytes_max;

//#if defined(_WIN32)
//    printf("   [%zu/%lu] \n", (i+1), n_fun);
//#else
//    printf("   [%zu/%u] \n", (i+1), n_fun);
//#endif
    printf("   [%zu/%"PRIu32"] \n", (i+1), n_fun);
    printf("   - name: %.*s\n", name_max, name);
    printf("   - ordinal: 0x%x\n", name_ordinal);
//#if defined(_WIN32)
//    printf("   - function (rva: 0x%lx, fo: 0x%llx):\n     ", rva, fo);
//#else
//    printf("   - function (rva: 0x%x, fo: 0x%lx):\n     ", rva, fo);
//#endif
    printf("   - function (rva: 0x%"PRIx32", fo: 0x%"PRIx64"):\n     ", rva, fo);
    for ( j = 0; j < nr_of_bytes; j++ )
        printf("%02x ", bytes[j]);
    printf("...\n");
}

void PE_printAttributeCertificateTable(PeAttributeCertificateTable* t, uint8_t n, uint64_t offset)
{
    uint8_t i;
    PeAttributeCertificateTable* entry;

    printf("Attribute Certificate Table (%u)\n", n);
    for ( i = 0; i < n; i++ )
    {
        entry = &t[i];

        printf(" - %u/%u\n", i+1, n);
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
//	memset(&dashes, 0, n);
    size_t min = (n-1 < level*2) ? n-1 : level*2;
    memset(buf, ' ', min);
    buf[min] = 0;
//	size_t i;
//	dashes[0] = ' ';
//	for ( i = 0; i < n && i < level; i++ )
//	{
//		buf[i*2+1] = ' ';
//		buf[i*2+2] = ' ';
//	}
}

//void fillDashes(size_t n, uint16_t level, char* dashes)
//{
//	memset(&dashes, 0, n);
//	size_t i;
//	size_t max_i = n > 1;
//	dashes[0] = ' ';
//	for ( i = 0; i < max_i && i < level; i++ )
//	{
//		dashes[i*2+1] = '-';
//		dashes[i*2+2] = ' ';
//	}
//}

void PE_printImageResourceDirectory(const PE_IMAGE_RESOURCE_DIRECTORY* rd, uint64_t offset, uint16_t level)
{
    char dashes[MAX_SPACES];
    fillSpaces(dashes, MAX_SPACES, level);

    printf("%sResource Directory%s:\n", dashes, fillOffset(0, offset, 0));
    printf("%s- Characteristics: 0x%x\n", dashes, rd->Characteristics);
    printf("%s- TimeDateStamp: 0x%x\n", dashes, rd->TimeDateStamp);
    printf("%s- MajorVersion: 0x%x\n", dashes, rd->MajorVersion);
    printf("%s- MinorVersion: 0x%x\n", dashes, rd->MinorVersion);
    printf("%s- NumberOfNamedEntries: 0x%x\n", dashes, rd->NumberOfNamedEntries);
    printf("%s- NumberOfIdEntries: 0x%x\n", dashes, rd->NumberOfIdEntries);
}

void PE_printImageResourceDirectoryEntryHeader(int type, uint16_t n, uint16_t level)
{
    char dashes[MAX_SPACES];
    fillSpaces(dashes, MAX_SPACES, level);
    
    if ( type == 0 )
        printf("%s- Named Entries (%u):\n", dashes, n);
    else if ( type == 1 )
        printf("%s- ID Entries (%u):\n", dashes, n);
}

void PE_printImageResourceDirectoryEntry(const PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                         uint64_t table_fo,
                                         uint64_t offset,
                                         uint16_t level,
                                         uint16_t id,
                                         uint16_t n,
                                         uint64_t start_file_offset,
                                         size_t file_size,
                                         FILE* fp,
                                         unsigned char* block_s)
{
    uint64_t name_offset = 0;
    size_t size = 0;
    size_t i = 0;
    unsigned char* ptr = NULL;
    PE_IMAGE_RESOURCE_DIR_STRING_U_PTR name;
    struct Pe_Image_Resource_Dir_String_U_Offsets name_offsets = PeImageResourceDirStringUOffsets;

    char dashes[MAX_SPACES];
    fillSpaces(dashes, MAX_SPACES, level);
    
    printf("%s  %u/%u%s:\n", dashes, (id+1), n, fillOffset(0, offset, 0));
    
    if ( re->NAME_UNION.NAME_STRUCT.NameIsString )
    {
        name_offset = table_fo + re->NAME_UNION.NAME_STRUCT.NameOffset;
        if ( !checkFileSpace(name_offset, start_file_offset, 4, file_size))
            return;

        name_offset = name_offset + start_file_offset;
//		size = readCustomBlock(file_name, name_offset, BLOCKSIZE, block_s);
        size = readFile(fp, name_offset, BLOCKSIZE, block_s);
        if ( size == 0 )
            return;

        ptr = block_s;
        name.Length = *((uint16_t*) &ptr[name_offsets.Length]);
        name.NameString = ((uint16_t*) &ptr[name_offsets.NameString]);

        if ( !checkFileSpace(name_offset, start_file_offset, 2+name_offsets.Length, file_size))
            return;

//		printf("   - Name.Length: 0x%x\n", name.Length);
        // ??? how to print utf16 on linux ???
        // hack considering it ascii
        printf("%s  - Name (%u): ", dashes, name.Length);
        for ( i = 0; i < name.Length; i++ )
            printf("%c", name.NameString[i]);
        printf("\n");
    }
        // id entries have ids
    else
    {
        printf("%s  - Id: 0x%x\n", dashes, re->NAME_UNION.Id);
    }
    printf("%s  - OffsetToData: 0x%x\n", dashes, re->OFFSET_UNION.OffsetToData);
    printf("%s    - OffsetToData.OffsetToDirectory: 0x%x\n", dashes, re->OFFSET_UNION.DATA_STRUCT.OffsetToDirectory);
    printf("%s    - OffsetToData.NameIsDirectory: 0x%x\n", dashes, re->OFFSET_UNION.DATA_STRUCT.DataIsDirectory);
}

void PE_printImageResourceDataEntry(const PE_IMAGE_RESOURCE_DATA_ENTRY* de, uint64_t offset, uint16_t level)
{
    char dashes[MAX_SPACES];
    fillSpaces(dashes, MAX_SPACES, level);
    
    printf("%s  - ResourceDataEntry%s:\n", dashes, fillOffset(0, offset, 0));
    printf("%s    - OffsetToData: 0x%x\n", dashes, de->OffsetToData);
    printf("%s    - Size: 0x%x\n", dashes, de->Size);
    printf("%s    - CodePage: 0x%x\n", dashes, de->CodePage);
    printf("%s    - Reserved: 0x%x\n", dashes, de->Reserved);
}

void PE_printImageBaseRelocationTable()
{
    printf("Base Relocation Table:\n");
}

void PE_printImageBaseRelocationBlockHeader(PE_BASE_RELOCATION_BLOCK* b, uint32_t i, uint64_t start_file_offset)
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

void PE_printImageBaseRelocationBlockEntry(PE_BASE_RELOCATION_ENTRY* e)
{
    uint16_t type = e->Data >> 12;
    uint16_t offset = e->Data & 0x0FFF;
    const char* type_str = (type <= 11) ? PeBaseRelocationTypeStrings[type] : "NONE";

    printf("     - 0x%04x | %s (%u)\n", offset, type_str, type);
}



void PE_printImageDelayImportTableHeader(PeImageDelayImportDescriptor* impd)
{
    if (impd->IAT != 0)
        printf("Delay Image Import Table:\n");
    else
        printf("No Delay Image Import Table\n");
}

void PE_printImageDelayImportDescriptor(PeImageDelayImportDescriptor* did, uint64_t offset, const char* dll_name)
{
    printf(" -%s %s (0x%x)\n", fillOffset(PeImageDelayImportDescriptorOffsets.Name, offset, 0), dll_name, did->Name);
    printf("   - Attributes%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.Attrs, offset, 0), did->Attrs);
    printf("   - mod%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.mod, offset, 0), did->mod);
    printf("   - IAT%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.IAT, offset, 0), did->IAT);
    printf("   - INT%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.INT, offset, 0), did->INT);
    printf("   - BoundIAT%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.BoundIAT, offset, 0), did->BoundIAT);
    printf("   - UnloadIAT%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.UnloadIAT, offset, 0), did->UnloadIAT);
    printf("   - TimeStamp%s: 0x%"PRIx32"\n", fillOffset(PeImageDelayImportDescriptorOffsets.TimeStamp, offset, 0), did->TimeStamp);
}

#endif
