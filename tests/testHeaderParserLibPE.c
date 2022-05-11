#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4100 4101 )
#endif

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

uint8_t info_level; // may be global.
uint8_t info_show_offsets; // may be global.

#include "../src/HeaderData.h"
#include "../src/stringPool.h"
#include "../src/utils/Converter.h"

#include "../src/headerParserLibPE.h"
#include "../src/headerParserLib.h"
#include "../src/ArchitectureInfo.h"
#include "../src/utils/Helper.h"
#include "../src/pe/PECharacteristics.h"
#include "../src/pe/PEHeaderOffsets.h"
#include "../src/pe/PEOptionalHeaderSignature.h"

#ifdef _WIN32
	#ifdef _DEBUG
		#ifdef _WIN64
			#pragma comment(lib, "..\\build\\debug\\64\\HeaderParser.lib")
		#else
			#pragma comment(lib, "..\\build\\debug\\32\\HeaderParser.lib")
		#endif
	#else
		#ifdef _WIN64
			#pragma comment(lib, "..\\build\\64\\HeaderParser.lib")
		#else
			#pragma comment(lib, "..\\build\\32\\HeaderParser.lib")
		#endif
	#endif
#endif


void runParser(const char* src, size_t offset, uint8_t force);
void printPEHeaderData(PEHeaderData* pehd, size_t offset);
void printHeaderData(HeaderData* data);
void printImageDosHeader(PEImageDosHeader* idh, size_t offset);
void printCoffFileHeader(PECoffFileHeader* cfh, size_t offset);
void printOptHeader(PE64OptHeader* oh, size_t offset, uint8_t bitness);
void printDataDirectory(PE64OptHeader* oh, size_t offset, uint8_t bitness);


int main(int argc, char** argv)
{
	int i;
	const char* src = NULL;
	uint8_t force = FORCE_NONE;
	size_t offset = 0;

	if (argc < 2)
	{
		printf("Usage: %s [-o offset] [-f] filename1 filename2 ... \n", argv[0]);
		return -1;
	}

	printf("argc: %d\n", argc);
	printf("offset: 0x%zx\n", offset);
	printf("force: %d\n", force);
	printf("\n");

	for ( i = 1; i < argc; i++ )
	{
		if ( argv[i][0] == '-' )
		{
			if ( strnlen(argv[i], 10) < 2 )
				continue;

			if ( argc <= i+1 )
				break;

			if ( argv[i][1] == 'o' )
			{
				offset = strtoul(argv[i + 1], NULL, 10);
				i++;
			}
			else if ( argv[i][1] == 'f' )
				force = FORCE_PE;

			continue;
		}

		src = argv[i];
		runParser(src, offset, force);
//		checkGuessed(src);
	}

	return 0;
}

void runParser(const char* src, size_t offset, uint8_t force)
{
	printf("=======runParser=======\n");
	printf("src: %s\n", src);
	printf("offset: 0x%zx\n", offset);
	printf("force: %u\n", force);
	printf("\n");
	PEHeaderData* pehd = getPEHeaderData(src, offset);

	if ( pehd == NULL )
	{
		printf("PEHeaderData is NULL\n");
		return;
	}

	printPEHeaderData(pehd, offset);

	freePEHeaderData(pehd);
	pehd = NULL;
}

void printPEHeaderData(PEHeaderData* pehd, size_t offset)
{
	size_t i;
	printf("\nPEHeaderData:\n");
	printHeaderData(pehd->hd);
	printImageDosHeader(pehd->image_dos_header, offset);
	printCoffFileHeader(pehd->coff_header, offset);
    printOptHeader(pehd->opt_header, offset, pehd->hd->h_bitness);
	printf("\n");
}

void printHeaderData(HeaderData* data)
{
	size_t i;
	printf("\nHeaderData:\n");
	printf("coderegions:\n");
	for ( i = 0; i < data->code_regions_size; i++ )
	{
		printf(" (%zu) %s: ( 0x%016zx - 0x%016zx )\n",
			   i+1, data->code_regions[i].name, data->code_regions[i].start, data->code_regions[i].end);
	}
	printf("headertype: %s\n", getHeaderDataHeaderType(data->headertype));
	printf("bitness: %d-bit\n", data->h_bitness);
	printf("endian: %s\n", endian_type_names[data->endian]);
	printf("CPU_arch: %s\n", getHeaderDataArchitecture(data->CPU_arch));
	printf("Machine: %s\n", data->Machine);
	printf("\n");
}

void printImageDosHeader(PEImageDosHeader* idh, size_t offset)
{
	printf("PE Image Dos Header:\n");
    printf(" - signature: %c|%c\n", idh->signature[0], idh->signature[1]);
    printf(" - lastsize: %u\n", idh->lastsize);
    printf(" - nblocks: %u\n", idh->nblocks);
    printf(" - nreloc: %u\n", idh->nreloc);
    printf(" - hdrsize: %u\n", idh->hdrsize);
    printf(" - minalloc: 0x%x\n", idh->minalloc);
    printf(" - maxalloc: 0x%x\n", idh->maxalloc);
    printf(" - ss: 0x%x\n", idh->ss);
    printf(" - sp: 0x%x\n", idh->sp);
    printf(" - checksum: %u\n", idh->checksum);
    printf(" - ip: 0x%x\n", idh->ip);
    printf(" - cs: 0x%x\n", idh->cs);
    printf(" - relocpos: 0x%x\n", idh->relocpos);
    printf(" - noverlay: %u\n", idh->noverlay);
//	printf(" - reserved1: %04x|%04x|%04x|%04x\n", idh->reserved1[0], idh->reserved1[1], idh->reserved1[2], idh->reserved1[3]);
    printf(" - oem_id: %u\n", idh->oem_id);
    printf(" - oem_info: %u\n", idh->oem_info);
//	printf(" - reserved2: %04x|%04x|%04x|%04x%04x|%04x|%04x|%04x%04x|%04x\n", idh->reserved2[0], idh->reserved2[1], idh->reserved2[2], idh->reserved2[3], idh->reserved2[4], idh->reserved2[5], idh->reserved2[6], idh->reserved2[7], idh->reserved2[8], idh->reserved2[9]);
    printf(" - e_lfanew: 0x%x (%u)\n", idh->e_lfanew, idh->e_lfanew);
    printf("\n");
}

void printCoffFileHeader(PECoffFileHeader* cfh, size_t offset)
{
	const char* dll_c_pre = "   - ";
    const char dll_c_post = '\n';
    ArchitectureMapEntry* arch = getArchitecture(cfh->Machine, pe_arch_id_mapper, pe_arch_id_mapper_size);
    char ch_bin[17];
    char date[32];
    formatTimeStampD(cfh->TimeDateStamp, date, sizeof(date));
    uint16ToBin(cfh->Characteristics, ch_bin);

    printf("Coff File Header:\n");
    printf(" - Machine: %s (0x%X)\n", arch->arch.name, cfh->Machine);
//	printf(" - Machine: %s (0x%X)\n", PE_getMachineName(cfh->Machine), cfh->Machine);
    printf(" - NumberOfSections: %u\n", cfh->NumberOfSections);
    printf(" - TimeDateStamp: %s (0x%x)\n", date, cfh->TimeDateStamp);
    printf(" - PointerToSymbolTable: 0x%X (%u)\n", cfh->PointerToSymbolTable, cfh->PointerToSymbolTable);
    printf(" - NumberOfSymbols: %u\n", cfh->NumberOfSymbols);
    printf(" - SizeOfOptionalHeader: %u\n", cfh->SizeOfOptionalHeader);
    printf(" - Characteristics: 0x%X (b%s)\n", cfh->Characteristics, ch_bin);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_RELOCS_STRIPPED,
            "IMAGE_FILE_RELOCS_STRIPPED: Relocation information was stripped from the file. The file must be loaded at its preferred base address. If the base address is not available, the loader reports an error.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_EXECUTABLE_IMAGE,
            "IMAGE_FILE_EXECUTABLE_IMAGE. The file is executable (there are no unresolved external references).", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_LINE_NUMS_STRIPPED,
            "IMAGE_FILE_LINE_NUMS_STRIPPED: COFF line numbers were stripped from the file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_LOCAL_SYMS_STRIPPED,
            "IMAGE_FILE_LOCAL_SYMS_STRIPPED: COFF symbol table entries were stripped from file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_AGGRESIVE_WS_TRIM,
            "IMAGE_FILE_AGGRESIVE_WS_TRIM: Aggressively trim the working set. This value is obsolete.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_LARGE_ADDRESS_AWARE,
            "IMAGE_FILE_LARGE_ADDRESS_AWARE: The application can handle addresses larger than 2 GB.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_BYTES_REVERSED_LO,
            "IMAGE_FILE_BYTES_REVERSED_LO: The bytes of the word are reversed. This flag is obsolete.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_32BIT_MACHINE,
            "IMAGE_FILE_32BIT_MACHINE: The computer supports 32-bit words.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_DEBUG_STRIPPED,
            "IMAGE_FILE_DEBUG_STRIPPED: Debugging information was removed and stored separately in another file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP,
            "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: If the image is on removable media, copy it to and run it from the swap file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_NET_RUN_FROM_SWAP,
            "IMAGE_FILE_NET_RUN_FROM_SWAP: If the image is on the network, copy it to and run it from the swap file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_SYSTEM,
            "IMAGE_FILE_SYSTEM: The image is a system file.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_DLL,
            "IMAGE_FILE_DLL: The image is a DLL file. While it is an executable file, it cannot be run directly.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_UP_SYSTEM_ONLY,
            "IMAGE_FILE_UP_SYSTEM_ONLY: The file should be run only on a uniprocessor computer.", dll_c_pre, dll_c_post);
    printFlag32F(cfh->Characteristics, PECoffCharacteristics.IMAGE_FILE_BYTES_REVERSED_HI,
            "IMAGE_FILE_BYTES_REVERSED_HI: The bytes of the word are reversed. This flag is obsolete.", dll_c_pre, dll_c_post);
    printf("\n");
}

void printOptHeader(PE64OptHeader* oh, size_t offset, uint8_t bitness)
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
    printf(" - Magic: %s (0x%x)\n", magic_string, oh->Magic);
    printf(" - MajorLinkerVersion: %u\n", oh->MajorLinkerVersion);
    printf(" - MinorLinkerVersion: %u\n", oh->MinorLinkerVersion);
    printf(" - SizeOfCode: 0x%X (%u)\n", oh->SizeOfCode, oh->SizeOfCode);
    printf(" - SizeOfInitializedData: 0x%X (%u)\n", oh->SizeOfInitializedData, oh->SizeOfInitializedData);
    printf(" - SizeOfUninitializedData: 0x%X (%u)\n", oh->SizeOfUninitializedData, oh->SizeOfUninitializedData);
    printf(" - AddressOfEntryPoint: 0x%X (%u)\n", oh->AddressOfEntryPoint, oh->AddressOfEntryPoint);
    printf(" - BaseOfCode: 0x%X (%u)\n", oh->BaseOfCode, oh->BaseOfCode);
    if (bitness == 32) printf(" - BaseOfData: 0x%X (%u)\n", oh->BaseOfData, oh->BaseOfData);
    printf(" - ImageBase: 0x%"PRIx64" (%"PRIu64")\n", oh->ImageBase, oh->ImageBase);
    printf(" - SectionAlignment: 0x%X (%u)\n", oh->SectionAlignment, oh->SectionAlignment);
    printf(" - FileAlignment: 0x%X (%u)\n", oh->FileAlignment, oh->FileAlignment);
    printf(" - MajorOSVersion: 0x%X (%u)\n", oh->MajorOSVersion, oh->MajorOSVersion);
    printf(" - MinorOSVersion: 0x%X (%u)\n", oh->MinorOSVersion, oh->MinorOSVersion);
    printf(" - MajorImageVersion: 0x%X (%u)\n", oh->MajorImageVersion, oh->MajorImageVersion);
    printf(" - MinorImageVersion: 0x%X (%u)\n", oh->MinorImageVersion, oh->MinorImageVersion);
    printf(" - MajorSubsystemVersion: 0x%X (%u)\n", oh->MajorSubsystemVersion, oh->MajorSubsystemVersion);
    printf(" - MinorSubsystemVersion: 0x%X (%u)\n", oh->MinorSubsystemVersion, oh->MinorSubsystemVersion);
    printf(" - Win32VersionValue: 0x%X (%u)\n", oh->Win32VersionValue, oh->Win32VersionValue);
    printf(" - SizeOfImage: 0x%X (%u)\n", oh->SizeOfImage, oh->SizeOfImage);
    printf(" - SizeOfHeaders: 0x%X (%u)\n", oh->SizeOfHeaders, oh->SizeOfHeaders);
    printf(" - Checksum: 0x%X (%u)\n", oh->Checksum, oh->Checksum);
    printf(" - Subsystem: (0x%x)\n", oh->Subsystem);
    printf(" - DllCharacteristics: 0x%X (b%s)\n", oh->DLLCharacteristics, ch_bin);
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
    printf(" - SizeOfStackReserve: 0x%"PRIx64" (%"PRIu64")\n", oh->SizeOfStackReserve, oh->SizeOfStackReserve);
    printf(" - SizeOfStackCommit: 0x%"PRIx64" (%"PRIu64")\n", oh->SizeOfStackCommit, oh->SizeOfStackCommit);
    printf(" - SizeOfHeapReserve: 0x%"PRIx64" (%"PRIu64")\n", oh->SizeOfHeapReserve, oh->SizeOfHeapReserve);
    printf(" - SizeOfHeapCommit: 0x%"PRIx64" (%"PRIu64")\n", oh->SizeOfHeapCommit, oh->SizeOfHeapCommit);
    printf(" - NumberOfRvaAndSizes:: 0x%X (%u)\n", oh->NumberOfRvaAndSizes, oh->NumberOfRvaAndSizes);
    printDataDirectory(oh, offset, bitness);
    printf("\n");
}

void printDataDirectory(PE64OptHeader* oh, size_t offset, uint8_t bitness)
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
