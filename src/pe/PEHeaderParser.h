#ifndef HEADER_PARSER_PE_HEADER_PARSER_H
#define HEADER_PARSER_PE_HEADER_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../ArchitectureInfo.h"
#include "../HeaderData.h"
#include "../Globals.h"
#include "../stringPool.h"
#include "../PEHeaderData.h"
#include "PEHeader.h"
#include "PEHeaderOffsets.h"
#include "PEOptionalHeaderSignature.h"
#include "PESectionCharacteristics.h"
#include "PESymbolTable.h"
#include "PEHeaderSectionNameResolution.h"
#include "PEImageDirectoryParser.h"
#include "PEHeaderPrinter.h"
#include "PECertificateHandler.h"



#define MAX_NR_OF_RVA_TO_READ (128)
#define MAX_CERT_TABLE_SIZE (10)



static int parsePEHeaderData(uint8_t force);
int parsePEHeader(uint8_t force, PEHeaderData* pehd);
int PEreadImageDosHeader(PEImageDosHeader* idh, uint64_t file_offset);
unsigned char PEcheckDosHeader(const PEImageDosHeader* idh);
uint8_t PEcheckPESignature(const uint32_t e_lfanew, uint64_t file_offset);
uint8_t PEreadCoffHeader(uint64_t offset, PECoffFileHeader* ch);
void PEfillHeaderDataWithCoffHeader(PECoffFileHeader* ch);
unsigned char PEcheckCoffHeader(const PECoffFileHeader* ch);
uint8_t PEreadOptionalHeader(uint64_t offset, PE64OptHeader* oh);
void PEfillHeaderDataWithOptHeader(PE64OptHeader* oh);
void PEreadSectionHeader(const uint64_t header_start, PECoffFileHeader* ch);
void PEfillSectionHeader(const unsigned char* ptr, PEImageSectionHeader* sh);
unsigned char PEcheckSectionHeader(const PEImageSectionHeader* sh, uint16_t idx, char* name);
//void PEreadSectionHeaderEntries(PECoffFileHeader* ch, unsigned char* section_block, const uint64_t header_start);
uint8_t PEisExecutableSectionHeader(const PEImageSectionHeader* sh);
CodeRegionData PEfillCodeRegion(const PEImageSectionHeader* sh, PECoffFileHeader* ch);
uint32_t PEcalculateSectionSize(const PEImageSectionHeader* sh);
uint8_t PEhasHeaderAtOffset(uint64_t offset);
void PEparseCertificates(PE64OptHeader* opt_header);
void PEcleanUp(PEHeaderData* pehd);

static int parse_svas = 0;

// The PE file header consists of a
//  - Microsoft MS-DOS stub,
//  - the PE signature,
//  - the COFF file header,
//  - and an optional header.
// A COFF object file header consists of
//  - a COFF file header
//  - and an optional header.
// In both cases, the file headers are followed immediately by section headers.
//
// HeaderData
//   .bitness is received by analysing the target machine and optional header
//   .endian defaults to 1 (le), because the determining Coff header flags (characteristics) are deprecated
//
// Each row of the section table is, in effect, a section header.
// This table immediately follows the optional header, if any.
// This positioning is required because the file header does not contain a direct pointer to the section table.
// Instead, the location of the section table is determined by calculating the location of the first byte after the headers.
// Make sure to use the size of the optional header as specified in the file header.
// 40 bytes per entry

/**
 * Wrapper to call parsePEHeader() with local extended data.
 *
 * @param force uint8_t FORCE_PE|FORCE_NONE
 * @return
 */
int parsePEHeaderData(uint8_t force)
{
	PEHeaderData pehd;
	PEImageDosHeader image_dos_header_l;
	PECoffFileHeader coff_header_l;
	PE64OptHeader opt_header_l;

	memset(&image_dos_header_l, 0, sizeof(PEImageDosHeader));
	memset(&coff_header_l, 0, sizeof(PECoffFileHeader));
	memset(&opt_header_l, 0, sizeof(PE64OptHeader));

	pehd.image_dos_header = &image_dos_header_l;
	pehd.coff_header = &coff_header_l;
	pehd.opt_header = &opt_header_l;
	pehd.hd = HD;

	parsePEHeader(force, &pehd);

	PEcleanUp(&pehd);

	return 0;
}

/**
 *
 * @param force uint8_t force option FORCE_PE|FORCE_NONE
 * @param pehd PEHeaderData* data object, containing dos-,coff-,opt-header.
 */
int parsePEHeader(uint8_t force, PEHeaderData* pehd)
{
	PEImageDosHeader* image_dos_header = NULL;
	PECoffFileHeader* coff_header = NULL;
	PE64OptHeader* opt_header = NULL;

	uint64_t optional_header_offset = 0;
	uint64_t section_header_offset = 0;

	uint8_t pe_header_type = 0;
	int s = 0;

	if ( pehd != NULL )
	{
		image_dos_header = pehd->image_dos_header;
		coff_header = pehd->coff_header;
		opt_header = pehd->opt_header;
	}
	else
	{
		printf("ERROR: PEHeaderData is NULL!\n");
		return -1;
	}

	if ( info_level_iimp || info_level_iexp || info_level_ires )
		parse_svas = 1;

	debug_info("parsePEHeader\n");

	s = PEreadImageDosHeader(image_dos_header, start_file_offset);
	if ( s != 0 )
		return 1;

	if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
		PEprintImageDosHeader(image_dos_header);

	if ( !checkBytes(MAGIC_DOS_STUB_BEGINNING, MAGIC_DOS_STUB_BEGINNING_LN, &block_large[PE_DOS_STUB_OFFSET]) )
	{
		if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
			header_info("INFO: No DOS stub found.\n");
	}

	if ( !PEcheckDosHeader(image_dos_header) )
	{
		header_error("ERROR: DOS header is invalid!\n");

		if ( image_dos_header->e_lfanew == 0 )
			{header_error(" - e_lfanew is 0\n");}
		else
			{header_error(" - e_lfanew (%u) > file_size (%u)", image_dos_header->e_lfanew, file_size); }

		header_error("\n");
		return 2;
	}

	pe_header_type = PEcheckPESignature(image_dos_header->e_lfanew, start_file_offset);
	if ( pe_header_type != 1 && !force )
	{
		debug_info("No valid PE00 section signature found!\n");
		if ( pe_header_type == 2 )
			HD->headertype = HEADER_TYPE_NE;
		else if ( pe_header_type == 3 )
			HD->headertype = HEADER_TYPE_LE;
		else if ( pe_header_type == 4 )
			HD->headertype = HEADER_TYPE_LX;
		else
			HD->headertype = HEADER_TYPE_MS_DOS;

		return 3;
	}

	HD->headertype = HEADER_TYPE_PE;
	HD->endian = ENDIAN_LITTLE;

	s = PEreadCoffHeader((uint64_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE, coff_header);
	if ( s != 0 ) return 4;

	if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
		PEprintCoffFileHeader(coff_header, (uint64_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE);
	PEfillHeaderDataWithCoffHeader(coff_header);
	if ( !PEcheckCoffHeader(coff_header) )
		return 5;

	optional_header_offset = (uint64_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE + PE_COFF_FILE_HEADER_SIZE;
	debug_info(" - optional_header_offset: #%lx (%lu)\n", optional_header_offset, optional_header_offset);
	s = PEreadOptionalHeader(optional_header_offset, opt_header);
	if ( s != 0 ) return 6;

	if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
		PEprintOptionalHeader(opt_header, optional_header_offset);

	PEfillHeaderDataWithOptHeader(opt_header);

	section_header_offset = (uint64_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE + PE_COFF_FILE_HEADER_SIZE + coff_header->SizeOfOptionalHeader;
	debug_info(" - section_header_offset: #%llx (%llu)\n", section_header_offset, section_header_offset);
	PEreadSectionHeader(section_header_offset, coff_header);

	if ( info_level_iimp == 1  )
		PEparseImageImportTable(opt_header, coff_header->NumberOfSections);

	if ( info_level_iexp == 1  )
		PEparseImageExportTable(opt_header, coff_header->NumberOfSections);

	if ( info_level_ires == 1  )
		PEparseImageResourceTable(opt_header, coff_header->NumberOfSections);

	if ( info_level_icrt == 1  )
		PEparseCertificates(opt_header);

	return 0;
}

void PEcleanUp(PEHeaderData* pehd)
{
	if ( string_table != NULL )
	{
		free(string_table);
		string_table = NULL;
	}

	if ( pehd && pehd->opt_header->NumberOfRvaAndSizes > 0 )
		free(pehd->opt_header->DataDirectory);
	free(svas);
	svas = NULL;
}

int PEreadImageDosHeader(PEImageDosHeader* idh, uint64_t file_offset)
{
//	uint16_t *ss, *sp; // 2 byte value
//	uint16_t *ip, *cs; // 2 byte value
	unsigned char *ptr;

	debug_info("readImageDosHeader()\n");
	debug_info(" - file_offset: %lX\n", file_offset);

	if ( !checkFileSpace(0, file_offset, sizeof(PEImageDosHeader), "PE Image Dos Header") )
		return 1;

	ptr = &block_large[0];

	idh->signature[0] = ptr[PEImageDosHeaderOffsets.signature];
	idh->signature[1] = ptr[PEImageDosHeaderOffsets.signature+1];
	idh->lastsize = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.lastsize]);
	idh->nblocks = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.nblocks]);
	idh->nreloc = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.nreloc]);
	idh->hdrsize = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.hdrsize]);
	idh->minalloc = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.minalloc]);
	idh->maxalloc = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.maxalloc]);
	idh->checksum = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.checksum]);
	idh->relocpos = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.relocpos]);
	idh->noverlay = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.noverlay]);
	idh->oem_id = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.oem_id]);
	idh->oem_info = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.oem_info]);
//	idh->ss = (uint16_t*) &ptr[PEImageDosHeaderOffsets.ss];
//	idh->sp = (uint16_t*) &ptr[PEImageDosHeaderOffsets.sp];
//	idh->ip = (uint16_t*) &ptr[PEImageDosHeaderOffsets.ip];
//	idh->cs = (uint16_t*) &ptr[PEImageDosHeaderOffsets.cs];
	idh->e_lfanew = *((uint32_t*) &ptr[PEImageDosHeaderOffsets.e_lfanew]);

	debug_info(" - magic_bytes: %c%c\n",idh->signature[0],idh->signature[1]);
	debug_info(" - e_lfanew: %X\n", idh->e_lfanew);

	return 0;
}

unsigned char PEcheckDosHeader(const PEImageDosHeader *idh)
{
	debug_info("checkDosHeader()\n");
	return idh->e_lfanew != 0 && idh->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE < file_size;
}

/**
 * This signature shows that
 * a) this file is a legitimate PE file,
 * b) this is a NE, LE, LX file
 *
 * @param e_lfanew
 * @return
 */
uint8_t PEcheckPESignature(const uint32_t e_lfanew, uint64_t file_offset)
{
	unsigned char *ptr;
	unsigned char is_pe = 0;
	unsigned char is_ne = 0;
	unsigned char is_le = 0;
	unsigned char is_lx = 0;
	uint32_t size;

	if ( !checkFileSpace(e_lfanew, file_offset, SIZE_OF_MAGIC_PE_SIGNATURE , "e_lfanew+SIZE_OF_MAGIC_PE_SIGNATURE") )
		return 0;

	if ( e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE > BLOCKSIZE_LARGE )
	{
		abs_file_offset = file_offset + e_lfanew;
		size = readBlock(file_name, abs_file_offset);
		if ( !size )
		{
			header_error("Read PE Signature block failed.\n");
			return 0;
		}
		ptr = block_standard;
	}
	else
	{
		ptr = &block_large[e_lfanew];
	}

	if ( checkBytes(MAGIC_PE_SIGNATURE, SIZE_OF_MAGIC_PE_SIGNATURE, ptr) )
		is_pe = 1;

	if ( checkBytes(MAGIC_NE_SIGNATURE, SIZE_OF_MAGIC_NE_SIGNATURE, ptr) )
		is_ne = 1;

	if ( checkBytes(MAGIC_LE_SIGNATURE, SIZE_OF_MAGIC_LE_SIGNATURE, ptr) )
		is_le = 1;

	if ( checkBytes(MAGIC_LX_SIGNATURE, SIZE_OF_MAGIC_LX_SIGNATURE, ptr) )
		is_lx = 1;
	
	debug_info("checkPESignature()\n");
	debug_info(" - pe_signature: %2X %2X %2X %2X\n", ptr[0], ptr[1], ptr[2], ptr[3]);
	debug_info(" - is_pe: %d\n", is_pe);
	debug_info(" - is_ne: %d\n", is_ne);

	if ( is_pe == 1 ) return 1;
	if ( is_ne == 1 ) return 2;
	if ( is_le == 1 ) return 3;
	if ( is_lx == 1 ) return 4;
	return 0;
}

uint8_t PEreadCoffHeader(uint64_t offset, PECoffFileHeader* ch)
{
	debug_info("readCoffHeader()\n");
	unsigned char *ptr;
//	uint32_t size;

	if ( !checkFileSpace(offset, start_file_offset, sizeof(PECoffFileHeader), "Coff File Header") )
		return 1;

	abs_file_offset = start_file_offset;
	if ( !checkLargeBlockSpace(&offset, &abs_file_offset, sizeof(PECoffFileHeader), "Coff File Header") )
		return 1;

	ptr = &block_large[offset];

	ch->Machine = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.Machine]);
	ch->NumberOfSections = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.NumberOfSections]);
	ch->TimeDateStamp = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.TimeDateStamp]);
	ch->PointerToSymbolTable = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.PointerToSymbolTable]);
	ch->NumberOfSymbols = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.NumberOfSymbols]);
	ch->SizeOfOptionalHeader = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.SizeOfOptionalHeader]);
	ch->Characteristics = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.Characteristics]);

	return 0;
}

void PEfillHeaderDataWithCoffHeader(PECoffFileHeader* ch)
{
	ArchitectureMapEntry* arch = getArchitecture(ch->Machine, pe_arch_id_mapper, pe_arch_id_mapper_size);
	HD->CPU_arch = arch->arch_id;
	HD->Machine = arch->arch.name;
	HD->bitness = arch->bitness;
}

unsigned char PEcheckCoffHeader(const PECoffFileHeader *ch)
{
	debug_info("checkCoffHeader()\n");
	unsigned char valid = 1;
//	char errors[ERRORS_BUFFER_SIZE] = {0};
//	uint16_t offset = 0;

//	if ( ch->NumberOfSections < 1 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - The NumberOfSections is %u.\n", ch->NumberOfSections);
//		offset += strlen(errors);
//		valid = 0;
//	}
//	if ( ch->SizeOfOptionalHeader == 0 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - The SizeOfOptionalHeader is %u.\n", ch->SizeOfOptionalHeader);
//		offset += strlen(errors);
//		valid = 0;
//	}
//	if ( strncmp(PEgetMachineName(ch->Machine), "None", 4) == 0 )
	if ( HD->CPU_arch == 0 )
	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - Unknown Machine 0x%x.\n", ch->Machine);
		header_info("INFO: Unknown Machine 0x%x.\n", ch->Machine);
//		offset += strlen(errors);
//		valid = 0;
	}

//	if ( !valid && strlen(errors) )
//	{
//		header_error("ERROR: Coff header is invalid!\n");
//		printf("%s\n", errors);
//	}

	return valid;
}

/**
 * Read the optional header.
 * Just the magic is filled right now, to provide a fallback for bitness determination.
 *
 * @param offset
 * @param oh
 */
uint8_t PEreadOptionalHeader(uint64_t offset, PE64OptHeader* oh)
{
	PEOptionalHeaderOffsets offsets = PEOptional64HeaderOffsets;
	unsigned char *ptr;
	uint32_t size;
	uint32_t i;
	uint8_t size_of_data_entry = sizeof(PEDataDirectory);
	uint64_t data_entry_offset;
	uint8_t nr_of_rva_to_read;
	debug_info("readPEOptionalHeader()\n");

	if ( !checkFileSpace(offset, start_file_offset, sizeof(oh->Magic), "oh->Magic") )
		return 1;

	abs_file_offset = offset + start_file_offset;
	// read new large block, to ease up offsetting
	size = readLargeBlock(file_name, abs_file_offset);
	if ( size == 0 )
		return 2;

	offset = 0;
	ptr = &block_large[offset];

	oh->Magic = *((uint16_t*) &ptr[offsets.Magic]);
	if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
		offsets = PEOptional32HeaderOffsets;

	if ( !checkFileSpace(offset, abs_file_offset, sizeof(offsets), "Optional Header Offsets") )
		return 1;

	// redundant because a new large block has been read just yet.
//	if ( !checkLargeBlockSpace(&offset, &abs_file_offset, sizeof(offsets), "Optional Header Offsets") )
//		return 1;
//	ptr = &block_large[offset];

	if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
	{
		oh->ImageBase = *((uint32_t*) &ptr[offsets.ImageBase]);
		oh->BaseOfData = *((uint32_t*) &ptr[offsets.BaseOfData]);
		oh->SizeOfStackReserve = *((uint32_t*) &ptr[offsets.SizeOfStackReserve]);
		oh->SizeOfStackCommit = *((uint32_t*) &ptr[offsets.SizeOfStackCommit]);
		oh->SizeOfHeapReserve = *((uint32_t*) &ptr[offsets.SizeOfHeapReserve]);
		oh->SizeOfHeapCommit = *((uint32_t*) &ptr[offsets.SizeOfHeapCommit]);
	}
	else
	{
		oh->ImageBase = *((uint64_t*) &ptr[offsets.ImageBase]);
		oh->SizeOfStackReserve = *((uint64_t*) &ptr[offsets.SizeOfStackReserve]);
		oh->SizeOfStackCommit = *((uint64_t*) &ptr[offsets.SizeOfStackCommit]);
		oh->SizeOfHeapReserve = *((uint64_t*) &ptr[offsets.SizeOfHeapReserve]);
		oh->SizeOfHeapCommit = *((uint64_t*) &ptr[offsets.SizeOfHeapCommit]);
	}
	oh->MajorLinkerVersion = *((uint8_t*) &ptr[offsets.MajorLinkerVersion]);
	oh->MinorLinkerVersion = *((uint8_t*) &ptr[offsets.MinorLinkerVersion]);
	oh->SizeOfCode = *((uint32_t*) &ptr[offsets.SizeOfCode]);
	oh->SizeOfInitializedData = *((uint32_t*) &ptr[offsets.SizeOfInitializedData]);
	oh->SizeOfUninitializedData = *((uint32_t*) &ptr[offsets.SizeOfUninitializedData]);
	oh->AddressOfEntryPoint = *((uint32_t*) &ptr[offsets.AddressOfEntryPoint]);
	oh->BaseOfCode = *((uint32_t*) &ptr[offsets.BaseOfCode]);
	oh->SectionAlignment = *((uint32_t*) &ptr[offsets.SectionAlignment]);
	oh->FileAlignment = *((uint32_t*) &ptr[offsets.FileAlignment]);
	oh->MajorOSVersion = *((uint16_t*) &ptr[offsets.MajorOperatingSystemVersion]);
	oh->MinorOSVersion = *((uint16_t*) &ptr[offsets.MinorOperatingSystemVersion]);
	oh->MajorImageVersion = *((uint16_t*) &ptr[offsets.MajorImageVersion]);
	oh->MinorImageVersion = *((uint16_t*) &ptr[offsets.MinorImageVersion]);
	oh->MajorSubsystemVersion = *((uint16_t*) &ptr[offsets.MajorSubsystemVersion]);
	oh->MinorSubsystemVersion = *((uint16_t*) &ptr[offsets.MinorSubsystemVersion]);
	oh->Win32VersionValue = *((uint32_t*) &ptr[offsets.Win32VersionValue]);
	oh->SizeOfImage = *((uint32_t*) &ptr[offsets.SizeOfImage]);
	oh->SizeOfHeaders = *((uint32_t*) &ptr[offsets.SizeOfHeaders]);
	oh->Checksum = *((uint32_t*) &ptr[offsets.CheckSum]);
	oh->Subsystem = *((uint16_t*) &ptr[offsets.Subsystem]);
	oh->DLLCharacteristics = *((uint16_t*) &ptr[offsets.DllCharacteristics]);
	oh->LoaderFlags = *((uint32_t*) &ptr[offsets.LoaderFlags]);
	oh->NumberOfRvaAndSizes = *((uint32_t*) &ptr[offsets.NumberOfRvaAndSizes]);

	data_entry_offset = offsets.DataDirectories;

	debug_info(" - NumberOfRvaAndSizes: %u\n", oh->NumberOfRvaAndSizes);

	if ( oh->NumberOfRvaAndSizes == 0 )
		return 0;

	nr_of_rva_to_read = oh->NumberOfRvaAndSizes;
	if ( oh->NumberOfRvaAndSizes > NUMBER_OF_RVA_AND_SIZES )
	{
		header_info("INFO: unusual value of NumberOfRvaAndSizes: %u\n", oh->NumberOfRvaAndSizes);
		nr_of_rva_to_read = (oh->NumberOfRvaAndSizes > MAX_NR_OF_RVA_TO_READ) ? MAX_NR_OF_RVA_TO_READ : oh->NumberOfRvaAndSizes;
	}

	oh->DataDirectory = (PEDataDirectory*) malloc(sizeof(PEDataDirectory) * nr_of_rva_to_read);
	if ( !oh->DataDirectory )
	{
		header_info("INFO: allocation of DataDirectory with %u entries failed!\n", nr_of_rva_to_read);
		header_info("INFO: Fallback to standard size of %u!\n", NUMBER_OF_RVA_AND_SIZES);

		oh->NumberOfRvaAndSizes = NUMBER_OF_RVA_AND_SIZES;
		oh->DataDirectory = (PEDataDirectory*) malloc(sizeof(PEDataDirectory) * oh->NumberOfRvaAndSizes);

		if ( !oh->DataDirectory )
		{
			header_error("ERROR: allocation of DataDirectory with %u entries failed!\n", oh->NumberOfRvaAndSizes);
			oh->NumberOfRvaAndSizes = 0;
			return 1;
		}
		nr_of_rva_to_read = NUMBER_OF_RVA_AND_SIZES;
	}

	for ( i = 0; i < nr_of_rva_to_read; i++ )
	{
		if ( !checkFileSpace(data_entry_offset, abs_file_offset, size_of_data_entry, "size_of_data_entry") )
			break;

		if ( !checkLargeBlockSpace(&data_entry_offset, &abs_file_offset, size_of_data_entry, "size_of_data_entry") )
			break;

		ptr = &block_large[0];

		oh->DataDirectory[i].VirtualAddress = *((uint32_t*) &ptr[data_entry_offset]);
		oh->DataDirectory[i].Size = *((uint32_t*) &ptr[data_entry_offset + 4]);

		data_entry_offset += size_of_data_entry;
//		abs_file_offset += size_of_data_entry;

		debug_info("DataDirectory[%u].VirtualAddress: 0x%x (%u)\n",
				i, oh->DataDirectory[i].VirtualAddress, oh->DataDirectory[i].VirtualAddress);
		debug_info("DataDirectory[%u].Size: 0x%x (%u)\n", i, oh->DataDirectory[i].Size, oh->DataDirectory[i].Size);
	}

	return 0;
}

void PEfillHeaderDataWithOptHeader(PE64OptHeader* oh)
{
	if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
		HD->bitness = 32;
	else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR64_MAGIC )
		HD->bitness = 64;
	else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_ROM_OPTIONAL_HDR_MAGIC )
		header_info("INFO: ROM file.\n");
	else
		header_info("INFO: Unknown PeOptionalHeaderSignature (Magic) of %u.\n", oh->Magic);

	if ( oh->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME_HEADER &&
		oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_CLR_RUNTIME_HEADER].VirtualAddress != 0 )
	{
		HD->CPU_arch = ARCH_DOT_NET;
		// TODO: check imports for mscoree.dll as well
		// check PEB.ldr[target.exe].flags : COR Image (0x200000) This module is a .NET application.
	}
}

/**
 * Read the section table.
 *
 * @param header_start
 * @param ch
 * @param finame
 */
void PEreadSectionHeader(const uint64_t header_start, PECoffFileHeader* ch)
{
	unsigned char *ptr = NULL;
	uint64_t offset;
	PEImageSectionHeader s_header;
	CodeRegionData code_region_data;
	uint16_t nr_of_sections = ch->NumberOfSections;
	uint16_t i = 0;
	uint32_t size;

	if ( parse_svas == 1 )
		svas = (SVAS*) calloc(nr_of_sections, sizeof(SVAS));
	
	// read new large block to ease up offsetting
	if ( !checkFileSpace(header_start, start_file_offset, PE_SECTION_HEADER_SIZE, "PE_SECTION_HEADER_SIZE") )
		return;

	abs_file_offset = header_start + start_file_offset;
	size = readLargeBlock(file_name, abs_file_offset);
	if ( size == 0 )
		return;
	offset = 0;

	if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
		printf("Section Header:\n");

	for ( i = 0; i < nr_of_sections; i++ )
	{
		debug_info(" - %u / %u\n", (i+1), nr_of_sections);

		if ( !checkFileSpace(offset, abs_file_offset, PE_SECTION_HEADER_SIZE, "PE_SECTION_HEADER_SIZE") )
			return;

		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, PE_SECTION_HEADER_SIZE, "PE_SECTION_HEADER_SIZE") )
			break;

		ptr = &block_large[offset];

		PEfillSectionHeader(ptr, &s_header);

		if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
			PEprintImageSectionHeader(&s_header, i, nr_of_sections, ch, abs_file_offset+offset);

		if ( !PEcheckSectionHeader(&s_header, i, s_header.Name) )
		{
//			offset += PE_SECTION_HEADER_SIZE;
//			continue;
		}
		if ( PEisExecutableSectionHeader(&s_header) )
		{
			code_region_data = PEfillCodeRegion(&s_header, ch);
			addCodeRegionDataToHeaderData(&code_region_data, HD);
		}

		if ( parse_svas )
		{
			svas[i].PointerToRawData = s_header.PointerToRawData;
			svas[i].SizeOfRawData = s_header.SizeOfRawData;
			svas[i].VirtualAddress = s_header.VirtualAddress;
			svas[i].VirtualSize = s_header.Misc.VirtualSize;
		}

		offset += PE_SECTION_HEADER_SIZE;
	}
	if ( LIB_MODE == 0 && info_level >= INFO_LEVEL_FULL )
		printf("\n");
}

void PEfillSectionHeader(const unsigned char* ptr, PEImageSectionHeader* sh)
{
	strncpy(sh->Name, (const char*)&ptr[PESectionHeaderOffsets.Name], IMAGE_SIZEOF_SHORT_NAME);
	sh->Misc.VirtualSize = *((uint32_t*) &ptr[PESectionHeaderOffsets.VirtualSize]);
	sh->VirtualAddress = *((uint32_t*) &ptr[PESectionHeaderOffsets.VirtualAddress]);
	sh->SizeOfRawData = *((uint32_t*) &ptr[PESectionHeaderOffsets.SizeOfRawData]);
	sh->PointerToRawData = *((uint32_t*) &ptr[PESectionHeaderOffsets.PointerToRawData]);
	sh->PointerToRelocations = *((uint32_t*) &ptr[PESectionHeaderOffsets.PointerToRelocations]);
	sh->PointerToLinenumbers = *((uint32_t*) &ptr[PESectionHeaderOffsets.PointerToLinenumbers]);
	sh->NumberOfRelocations = *((uint16_t*) &ptr[PESectionHeaderOffsets.NumberOfRelocations]);
	sh->NumberOfLinenumbers = *((uint16_t*) &ptr[PESectionHeaderOffsets.NumberOfLinenumbers]);
	sh->Characteristics = *((uint32_t*) &ptr[PESectionHeaderOffsets.Characteristics]);
}

unsigned char PEcheckSectionHeader(const PEImageSectionHeader* sh, uint16_t idx, char* name)
{
	debug_info("PEcheckSectionHeader()\n");
	unsigned char valid = 1;
	char errors[ERRORS_BUFFER_SIZE] = {0};
	uint16_t offset = 0;
	uint32_t section_size = PEcalculateSectionSize(sh);

	if ( !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA
										  & PESectionCharacteristics.IMAGE_SCN_MEM_READ
		   								  & PESectionCharacteristics.IMAGE_SCN_MEM_WRITE) )
	{
		debug_info("!(U & R & W): \n");
		if ( sh->PointerToRawData == 0 )
		{
			snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - PointerToRawData is 0\n");
			offset += (uint16_t)strlen(errors);
			valid = 0;
		}
		if ( start_file_offset + section_size == 0 )
		{
			snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - section_size is 0\n");
			offset += (uint16_t)strlen(errors);
			valid = 0;
		}
		if ( start_file_offset + section_size > file_size )
		{
			snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - section_size (%u) is > file_size (%u)\n",
					 section_size, file_size);
			offset += (uint16_t)strlen(errors);
			valid = 0;
		}
		if ( start_file_offset + sh->PointerToRawData + section_size > file_size )
		{
			snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - PointerToRawData (%u) + section_size (%u) = (%u) is > file_size (%u)\n",
					 sh->PointerToRawData,section_size,sh->PointerToRawData+section_size, file_size);
			offset += (uint16_t)strlen(errors);
			valid = 0;
		}
	}

	if ( !valid && strlen(errors) )
	{
		header_info("INFO: Section header %d (\"%s\") is invalid.\n", idx+1, name);
		header_info("%s\n", errors);
	}

	return valid;
}

uint8_t PEisExecutableSectionHeader(const PEImageSectionHeader* sh)
{
	return hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE) ||
			hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_EXECUTE);
}

CodeRegionData PEfillCodeRegion(const PEImageSectionHeader* sh, PECoffFileHeader* ch)
{
	uint64_t end_of_raw_data = 0;
	char *name = NULL;
	uint64_t size = PEcalculateSectionSize(sh);
	end_of_raw_data = sh->PointerToRawData + size;
	CodeRegionData code_region_data;

//	if ( sh->VirtualSize == 0 ) // object file
	// uninitialized data
	// add to regions or not ???
//	if ( size == 0 )
//	{
//		return (CodeRegionData) {"", 0, 0};
//	}

	PEgetRealName(sh->Name, &name, ch);

	code_region_data.start = sh->PointerToRawData;
	code_region_data.end = end_of_raw_data;
	code_region_data.name = name;

	return code_region_data;
}

/**
 * VirtualSize may be zero padded, SizeOfRawData may be rounded.
 * Objdump seems to choose the lesser one, or SizeOfRawData if VirtualSize is 0.
 * If SizeOfRawData the size is 0 => there is no code region.
 */
uint32_t PEcalculateSectionSize(const PEImageSectionHeader* sh)
{
//	if ( sh->PointerToRawData == 0 ) return 0;
	uint32_t size = sh->Misc.VirtualSize;

	if ( sh->SizeOfRawData == 0
		&& ( ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE)
				&& !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				)
			|| hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA)
			|| ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE
												& PESectionCharacteristics.IMAGE_SCN_MEM_READ
												& PESectionCharacteristics.IMAGE_SCN_MEM_WRITE)
				&& !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				)
//			|| ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE)
//				&& hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_READ)
//				&& hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_WRITE) )
			)
		)
		size = sh->SizeOfRawData;
	else if ( ( sh->SizeOfRawData < sh->Misc.VirtualSize && sh->SizeOfRawData > 0 )
		|| sh->Misc.VirtualSize == 0 )
		size = sh->SizeOfRawData;

//	if ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE)
//		 && !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA) )
//		size = sh->SizeOfRawData;
//	else
//		size = sh->Misc.VirtualSize;

	return size;
}

/**
 * Miscellaneous function to check for a valid PE header at an offset.
 *
 * @param offset
 * @return
 */
uint8_t PEhasHeaderAtOffset(uint64_t offset)
{
	PEImageDosHeader image_dos_header;
	int s = 0;
	uint8_t pe_header_type = 0;
	uint32_t size = readLargeBlock(file_name, offset);
	if ( size == 0 )
	{
		header_error("ERROR: PEhasHeaderAtOffset: Read large block failed.\n");
		return 0;
	}

	if ( !checkBytes(MAGIC_PE_BYTES, MAGIC_PE_BYTES_LN, block_large) )
		return 0;

	s = PEreadImageDosHeader(&image_dos_header, offset);
	if ( s != 0 ) return 0;

	if ( !checkBytes(MAGIC_DOS_STUB_BEGINNING, MAGIC_DOS_STUB_BEGINNING_LN, &block_large[PE_DOS_STUB_OFFSET]) )
		header_info("INFO: No DOS stub found.\n");

	pe_header_type = PEcheckPESignature(image_dos_header.e_lfanew, 0);
	if ( pe_header_type != 1 )
	{
//		debug_info("No valid PE00 section signature found!\n");
//		if ( pe_header_type == 2 )
//			HD->headertype = HEADER_TYPE_NE;
//		else
//			HD->headertype = HEADER_TYPE_MS_DOS;

		return 0;
	}

	return 1;
}

void PEparseCertificates(PE64OptHeader* opt_header)
{
	uint8_t table_size;
	PeAttributeCertificateTable table[MAX_CERT_TABLE_SIZE];
	const char* dir = "/tmp";

	//table_size = PEgetNumberOfCertificates(opt_header);
//	printf("has certificate: %d\n", PEhasCertificate(opt_header));
//	printf("number of certificates: %d\n", table_size);
	table_size = PEfillCertificateTable(table, MAX_CERT_TABLE_SIZE, opt_header);

	PEprintAttributeCertificateTable(table, table_size, start_file_offset+opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].VirtualAddress);

	if ( certificate_directory != NULL )
		PEwriteCertificatesToFile(table, table_size, dir);
}

#endif
