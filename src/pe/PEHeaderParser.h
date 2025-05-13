#ifndef HEADER_PARSER_PE_HEADER_PARSER_H
#define HEADER_PARSER_PE_HEADER_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

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



static int parsePEHeaderData(
    uint8_t force, 
    PHeaderData hd, 
    PGlobalParams gp, 
    PPEParams pep
);

static int parsePEHeader(uint8_t force,
                         PEHeaderData* pehd,
                         PHeaderData hd,
                         PGlobalParams gp,
                         PPEParams pep);

static int PE_readImageDosHeader(PEImageDosHeader* idh,
                                 size_t file_offset,
                                 size_t file_size,
                                 unsigned char* block_l);

static unsigned char PE_checkDosHeader(const PEImageDosHeader* idh,
                                       size_t file_size);

static uint8_t PE_checkPESignature(uint32_t e_lfanew,
                                   size_t file_offset,
                                   size_t* abs_file_offset,
                                   size_t file_size,
                                   FILE* fp,
                                   unsigned char* block_s,
                                   unsigned char* block_l);
static uint8_t PE_readCoffHeader(size_t offset,
                                 PECoffFileHeader* ch,
                                 size_t start_file_offset,
                                 size_t* abs_file_offset,
                                 size_t file_size,
                                 FILE* fp,
                                 unsigned char* block_l);
static void PE_fillHeaderDataWithCoffHeader(PECoffFileHeader* ch,
                                            PHeaderData hd);
static unsigned char PE_checkCoffHeader(const PECoffFileHeader* ch,
                                        PHeaderData hd);
static int PE_readOptionalHeader(size_t offset,
                                     PE64OptHeader* oh,
                                     size_t start_file_offset,
                                     size_t* abs_file_offset,
                                     size_t file_size,
                                     FILE* fp,
                                     unsigned char* block_l);
static void PE_fillHeaderDataWithOptHeader(PE64OptHeader* oh,
                                           PHeaderData hd);
static void PE_readSectionHeader(size_t header_start,
                                 PECoffFileHeader* ch,
                                 size_t start_file_offset,
                                 size_t* abs_file_offset,
                                 size_t file_size,
                                 uint8_t p_sec_h,
                                 FILE* fp,
                                 unsigned char* block_s,
                                 unsigned char* block_l,
                                 PStringTable st,
                                 int parse_svas,
                                 PSVAS* svas,
                                 PHeaderData hd);
static void PE_fillSectionHeader(const unsigned char* ptr, PEImageSectionHeader* sh);
static int PE_isNullSectionHeader(const PEImageSectionHeader* sh);
static int PE_checkSectionHeader(const PEImageSectionHeader* sh,
                                           uint16_t idx,
                                           const char* name,
                                           size_t start_file_offset,
                                           size_t file_size);
//void PE_readSectionHeaderEntries(PECoffFileHeader* ch, unsigned char* section_block, const size_t header_start);
static uint8_t PE_isExecutableSectionHeader(const PEImageSectionHeader* sh);
static CodeRegionData PE_fillCodeRegion(const PEImageSectionHeader* sh,
                                        PECoffFileHeader* ch,
                                        size_t start_file_offset,
                                        size_t file_size,
                                        FILE* fp,
                                        unsigned char* block_s,
                                        PStringTable st);
static uint32_t PE_calculateSectionSize(const PEImageSectionHeader* sh);
static uint8_t PE_hasHeaderAtOffset(size_t offset,
                                    size_t* abs_file_offset,
                                    size_t file_size,
                                    FILE* fp,
                                    unsigned char* block_s,
                                    unsigned char* block_l);
static void PE_parseCertificates(PE64OptHeader* opt_header,
                                 size_t start_file_offset,
                                 size_t file_size,
                                 const char* certificate_directory,
                                 FILE* fp,
                                 unsigned char* block_s);
static void PE_cleanUp(PEHeaderData* pehd);

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
int parsePEHeaderData(
    uint8_t force,
    PHeaderData hd,
    PGlobalParams gp,
    PPEParams pep
)
{
    PEHeaderData pehd;
    PEImageDosHeader image_dos_header_l;
    PECoffFileHeader coff_header_l;
    PE64OptHeader opt_header_l;

    memset(&image_dos_header_l, 0, sizeof(PEImageDosHeader));
    memset(&coff_header_l, 0, sizeof(PECoffFileHeader));
    memset(&opt_header_l, 0, sizeof(PE64OptHeader));

    memset(&pehd, 0, sizeof(PEHeaderData));

    pehd.image_dos_header = &image_dos_header_l;
    pehd.coff_header = &coff_header_l;
    pehd.opt_header = &opt_header_l;
    pehd.hd = hd;

    parsePEHeader(force, &pehd, hd, gp, pep);

    PE_cleanUp(&pehd);

    return 0;
}

/**
 *
 * @param force uint8_t force option FORCE_PE|FORCE_NONE
 * @param pehd PEHeaderData* data object, containing dos-,coff-,opt-header.
 */
int parsePEHeader(
    uint8_t force,
    PEHeaderData* pehd,
    PHeaderData hd,
    PGlobalParams gp,
    PPEParams pep
)
{
    PEImageDosHeader* image_dos_header = NULL;
    PECoffFileHeader* coff_header = NULL;
    PE64OptHeader* opt_header = NULL;

    size_t optional_header_offset = 0;
    size_t section_header_offset = 0;

    uint8_t pe_header_type = 0;
    int parse_svas = 0;
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

    if ( pep->info_level & ( INFO_LEVEL_PE_SVAS | INFO_LEVEL_PE_LIB ) )
    {
        parse_svas = 1;
    }

//    debug_info("parsePEHeader\n");

    s = PE_readImageDosHeader(image_dos_header, gp->file.start_offset, gp->file.size, gp->data.block_main);
    if ( s != 0 )
        return -2;
    
#if LIB_MODE == 0
    if ( pep->info_level & INFO_LEVEL_PE_DOS_H )
        PE_printImageDosHeader(image_dos_header, gp->file.start_offset);
#endif

    if ( !checkBytes(MAGIC_DOS_STUB_BEGINNING, MAGIC_DOS_STUB_BEGINNING_LN, &gp->data.block_main[PE_DOS_STUB_OFFSET]) )
    {
#if LIB_MODE == 0
        if ( pep->info_level & INFO_LEVEL_PE_DOS_H )
            header_info("INFO: No DOS stub found.\n");
#endif
    }

    if ( !PE_checkDosHeader(image_dos_header, gp->file.size) )
    {
        header_error("ERROR: DOS header is invalid!\n");

        if ( image_dos_header->e_lfanew == 0 )
            {header_error(" - e_lfanew is 0\n");}
        else
            {header_error(" - e_lfanew (%u) > file_size (%zu)", image_dos_header->e_lfanew, gp->file.size); }

        header_error("\n");
        return -3;
    }

    pe_header_type = PE_checkPESignature(image_dos_header->e_lfanew, gp->file.start_offset, &gp->file.abs_offset, gp->file.size,
                                      gp->file.handle, gp->data.block_sub, gp->data.block_main);
    if ( pe_header_type != 1 && !force )
    {
//        debug_info("No valid PE00 section signature found!\n");
        if ( pe_header_type == 2 )
            hd->headertype = HEADER_TYPE_NE;
        else if ( pe_header_type == 3 )
            hd->headertype = HEADER_TYPE_LE;
        else if ( pe_header_type == 4 )
            hd->headertype = HEADER_TYPE_LX;
        else
            hd->headertype = HEADER_TYPE_MS_DOS;

        return -4;
    }

    hd->headertype = HEADER_TYPE_PE;
    hd->endian = ENDIAN_LITTLE;

    s = PE_readCoffHeader((size_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE, coff_header, gp->file.start_offset,
                       &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main);
    if ( s != 0 ) return -5;
    
#if LIB_MODE == 0
    if ( pep->info_level & INFO_LEVEL_PE_COFF_H )
        PE_printCoffFileHeader(coff_header, (size_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE, gp->file.start_offset);
#endif
    PE_fillHeaderDataWithCoffHeader(coff_header, hd);
    if ( !PE_checkCoffHeader(coff_header, hd) )
        return -6;

    optional_header_offset = (size_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE + PE_COFF_FILE_HEADER_SIZE;
//    debug_info(" - optional_header_offset: #%zx (%zu)\n", optional_header_offset, optional_header_offset);
    s = PE_readOptionalHeader(optional_header_offset, opt_header, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main);
    if ( s != 0 ) return -7;
    
#if LIB_MODE == 0
    if ( pep->info_level & INFO_LEVEL_PE_OPT_H )
        PE_printOptionalHeader(opt_header, optional_header_offset, gp->file.start_offset, hd->h_bitness);
#endif

    PE_fillHeaderDataWithOptHeader(opt_header, hd);

    section_header_offset = (size_t)image_dos_header->e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE + PE_COFF_FILE_HEADER_SIZE + coff_header->SizeOfOptionalHeader;
//    debug_info(" - section_header_offset: #%zx (%zu)\n", section_header_offset, section_header_offset);
    PE_readSectionHeader(section_header_offset, coff_header, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, pep->info_level&INFO_LEVEL_PE_SEC_H,
                         gp->file.handle, gp->data.block_sub, gp->data.block_main, &pehd->st, parse_svas, &pehd->svas, hd);


    //if ( opt_header->NumberOfRvaAndSizes > 0 )
    {
        if ( pep->info_level & INFO_LEVEL_PE_IMP )
            PE_parseImageImportTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset,
                                     &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub, pep->info_level & INFO_LEVEL_PE_IMP_EX);

        if (pep->info_level & INFO_LEVEL_PE_DIMP )
            PE_parseImageDelayImportTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset,
                &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub, pep->info_level & INFO_LEVEL_PE_DIMP_EX);

        if (pep->info_level & INFO_LEVEL_PE_BIMP )
            PE_parseImageBoundImportTable(opt_header, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub);

        if ( pep->info_level & INFO_LEVEL_PE_EXP )
            PE_parseImageExportTable(opt_header, coff_header->NumberOfSections, gp->file.start_offset, gp->file.size, gp->file.handle, gp->data.block_sub, pehd->svas);

        if ( pep->info_level & INFO_LEVEL_PE_RES )
            PE_parseImageResourceTable(opt_header, coff_header->NumberOfSections, gp->file.start_offset, gp->file.size, gp->file.handle, gp->data.block_sub, pehd->svas);

        if ( pep->info_level & INFO_LEVEL_PE_DBG )
            PE_parseImageDebugTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub, pep->info_level & INFO_LEVEL_PE_DBG_EX);

        //if ( pep->info_level & INFO_LEVEL_PE_EXC )
            //PE_parseImageExceptionTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub);

        if (pep->info_level & INFO_LEVEL_PE_REL )
            PE_parseImageBaseRelocationTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub);

        if ( pep->info_level & INFO_LEVEL_PE_CRT )
            PE_parseCertificates(opt_header, gp->file.start_offset, gp->file.size, pep->certificate_directory, gp->file.handle, gp->data.block_sub);

        if (pep->info_level & INFO_LEVEL_PE_TLS )
            PE_parseImageTLSTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset, &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_sub);
    
        if (pep->info_level & INFO_LEVEL_PE_LCFG )
            PE_parseImageLoadConfigTable(opt_header, coff_header->NumberOfSections, pehd->svas, hd->h_bitness, gp->file.start_offset,
                                          &gp->file.abs_offset, gp->file.size, gp->file.handle, gp->data.block_sub);
    }
    //else
    //{
    //    debug_info("opt header size is 0!\n");
    //}
    return 0;
}

void PE_cleanUp(PEHeaderData* pehd)
{
    if ( pehd == NULL )
        return;

    if ( pehd->st.strings != NULL )
    {
        free(pehd->st.strings);
        pehd->st.strings = NULL;
    }

    if ( pehd->opt_header->NumberOfRvaAndSizes > 0 )
    {
        free(pehd->opt_header->DataDirectory);
        pehd->opt_header->DataDirectory = NULL;
    }

    if ( pehd->svas != NULL )
    {
        free(pehd->svas);
        pehd->svas = NULL;
    }
}

int PE_readImageDosHeader(PEImageDosHeader* idh,
                          size_t file_offset,
                          size_t file_size,
                          unsigned char* block_l)
{
//	uint16_t *ss, *sp; // 2 byte value
//	uint16_t *ip, *cs; // 2 byte value
    unsigned char *ptr;

//    debug_info("readImageDosHeader()\n");
//    debug_info(" - file_offset: %zx\n", file_offset);

    if ( !checkFileSpace(0, file_offset, sizeof(PEImageDosHeader), file_size) )
        return -1;

    ptr = &block_l[0];

    idh->signature[0] = (char)ptr[PEImageDosHeaderOffsets.signature];
    idh->signature[1] = (char)ptr[PEImageDosHeaderOffsets.signature+1];
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
    idh->ss = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.ss]);
    idh->sp = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.sp]);
    idh->ip = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.ip]);
    idh->cs = *((uint16_t*) &ptr[PEImageDosHeaderOffsets.cs]);
    idh->e_lfanew = *((uint32_t*) &ptr[PEImageDosHeaderOffsets.e_lfanew]);

//    debug_info(" - magic_bytes: %c%c\n",idh->signature[0],idh->signature[1]);
//    debug_info(" - e_lfanew: %X\n", idh->e_lfanew);

    return 0;
}

unsigned char PE_checkDosHeader(const PEImageDosHeader *idh,
                                size_t file_size)
{
//    debug_info("checkDosHeader()\n");
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
uint8_t PE_checkPESignature(const uint32_t e_lfanew,
                            size_t file_offset,
                            size_t* abs_file_offset,
                            size_t file_size,
                            FILE* fp,
                            unsigned char* block_s,
                            unsigned char* block_l)
{
    unsigned char *ptr;
    unsigned char is_pe = 0;
    unsigned char is_ne = 0;
    unsigned char is_le = 0;
    unsigned char is_lx = 0;
    size_t size;

    if ( !checkFileSpace(e_lfanew, file_offset, SIZE_OF_MAGIC_PE_SIGNATURE , file_size) )
        return 0;

    if ( e_lfanew + SIZE_OF_MAGIC_PE_SIGNATURE > BLOCKSIZE_LARGE )
    {
        *abs_file_offset = file_offset + e_lfanew;
        size = readFile(fp, *abs_file_offset, BLOCKSIZE_SMALL, block_s);
        if ( !size )
        {
            header_error("Read PE Signature block failed.\n");
            return 0;
        }
        ptr = block_s;
    }
    else
    {
        ptr = &block_l[e_lfanew];
    }

    if ( checkBytes(MAGIC_PE_SIGNATURE, SIZE_OF_MAGIC_PE_SIGNATURE, ptr) )
        is_pe = 1;

    if ( checkBytes(MAGIC_NE_SIGNATURE, SIZE_OF_MAGIC_NE_SIGNATURE, ptr) )
        is_ne = 1;

    if ( checkBytes(MAGIC_LE_SIGNATURE, SIZE_OF_MAGIC_LE_SIGNATURE, ptr) )
        is_le = 1;

    if ( checkBytes(MAGIC_LX_SIGNATURE, SIZE_OF_MAGIC_LX_SIGNATURE, ptr) )
        is_lx = 1;
    
//    debug_info("checkPESignature()\n");
//    debug_info(" - pe_signature: %2X %2X %2X %2X\n", ptr[0], ptr[1], ptr[2], ptr[3]);
//    debug_info(" - is_pe: %d\n", is_pe);
//    debug_info(" - is_ne: %d\n", is_ne);

    if ( is_pe == 1 ) return 1;
    if ( is_ne == 1 ) return 2;
    if ( is_le == 1 ) return 3;
    if ( is_lx == 1 ) return 4;
    return 0;
}

uint8_t PE_readCoffHeader(size_t offset,
                          PECoffFileHeader* ch,
                          size_t start_file_offset,
                          size_t* abs_file_offset,
                          size_t file_size,
                          FILE* fp,
                          unsigned char* block_l)
{
//    debug_info("readCoffHeader()\n");
    unsigned char *ptr;

    if ( !checkFileSpace(offset, start_file_offset, sizeof(PECoffFileHeader), file_size) )
        return 1;

    *abs_file_offset = start_file_offset;
    if ( !checkLargeBlockSpace(&offset, abs_file_offset, sizeof(PECoffFileHeader), block_l, fp) )
        return 1;

    ptr = &block_l[offset];

    ch->Machine = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.Machine]);
    ch->NumberOfSections = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.NumberOfSections]);
    ch->TimeDateStamp = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.TimeDateStamp]);
    ch->PointerToSymbolTable = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.PointerToSymbolTable]);
    ch->NumberOfSymbols = *((uint32_t*) &ptr[PECoffFileHeaderOffsets.NumberOfSymbols]);
    ch->SizeOfOptionalHeader = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.SizeOfOptionalHeader]);
    ch->Characteristics = *((uint16_t*) &ptr[PECoffFileHeaderOffsets.Characteristics]);

    return 0;
}

void PE_fillHeaderDataWithCoffHeader(PECoffFileHeader* ch,
                                     PHeaderData hd)
{
    ArchitectureMapEntry* arch = getArchitecture(ch->Machine, pe_arch_id_mapper, pe_arch_id_mapper_size);
    hd->CPU_arch = arch->arch_id;
    hd->Machine = arch->arch.name;
    hd->i_bitness = arch->bitness;
}

unsigned char PE_checkCoffHeader(const PECoffFileHeader *ch,
                                 PHeaderData hd)
{
//    debug_info("checkCoffHeader()\n");
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
    if ( hd->CPU_arch == 0 )
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
int PE_readOptionalHeader(size_t offset,
                              PE64OptHeader* oh,
                              size_t start_file_offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_l)
{
    struct _PE_Optional_Header_Offsets offsets = PEOptional64HeaderOffsets;
    unsigned char *ptr;
    size_t size;
    uint32_t i;
    uint8_t size_of_data_entry = sizeof(PEDataDirectory);
    size_t data_entry_offset;
    uint8_t nr_of_rva_to_read;
//    debug_info("readPEOptionalHeader()\n");

    if ( !checkFileSpace(offset, start_file_offset, sizeof(oh->Magic), file_size) )
        return 1;

    *abs_file_offset = offset + start_file_offset;
    // read new large block, to ease up offsetting
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return 2;

    offset = 0;
    ptr = &block_l[offset];

    oh->Magic = *((uint16_t*) &ptr[offsets.Magic]);
    if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
        offsets = PEOptional32HeaderOffsets;

    if ( !checkFileSpace(offset, *abs_file_offset, sizeof(PE64OptHeader), file_size) )
    {
        header_error("ERROR: PE Optional Header beyond file size!\n");
        return 1;
    }

    if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
    {
        oh->ImageBase = GetIntXValueAtOffset(uint32_t, ptr, offsets.ImageBase);
        oh->BaseOfData = GetIntXValueAtOffset(uint32_t, ptr, offsets.BaseOfData);
        oh->SizeOfStackReserve = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfStackReserve);
        oh->SizeOfStackCommit = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfStackCommit);
        oh->SizeOfHeapReserve = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfHeapReserve);
        oh->SizeOfHeapCommit = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfHeapCommit);
    }
    else
    {
        oh->ImageBase = GetIntXValueAtOffset(uint64_t, ptr, offsets.ImageBase);
        oh->SizeOfStackReserve = GetIntXValueAtOffset(uint64_t, ptr, offsets.SizeOfStackReserve);
        oh->SizeOfStackCommit = GetIntXValueAtOffset(uint64_t, ptr, offsets.SizeOfStackCommit);
        oh->SizeOfHeapReserve = GetIntXValueAtOffset(uint64_t, ptr, offsets.SizeOfHeapReserve);
        oh->SizeOfHeapCommit = GetIntXValueAtOffset(uint64_t, ptr, offsets.SizeOfHeapCommit);
    }
    oh->MajorLinkerVersion = GetIntXValueAtOffset(uint8_t, ptr, offsets.MajorLinkerVersion);
    oh->MinorLinkerVersion = GetIntXValueAtOffset(uint8_t, ptr, offsets.MinorLinkerVersion);
    oh->SizeOfCode = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfCode);
    oh->SizeOfInitializedData = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfInitializedData);
    oh->SizeOfUninitializedData = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfUninitializedData);
    oh->AddressOfEntryPoint = GetIntXValueAtOffset(uint32_t, ptr, offsets.AddressOfEntryPoint);
    oh->BaseOfCode = GetIntXValueAtOffset(uint32_t, ptr, offsets.BaseOfCode);
    oh->SectionAlignment = GetIntXValueAtOffset(uint32_t, ptr, offsets.SectionAlignment);
    oh->FileAlignment = GetIntXValueAtOffset(uint32_t, ptr, offsets.FileAlignment);
    oh->MajorOSVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorOperatingSystemVersion);
    oh->MinorOSVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorOperatingSystemVersion);
    oh->MajorImageVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorImageVersion);
    oh->MinorImageVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorImageVersion);
    oh->MajorSubsystemVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorSubsystemVersion);
    oh->MinorSubsystemVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorSubsystemVersion);
    oh->Win32VersionValue = GetIntXValueAtOffset(uint32_t, ptr, offsets.Win32VersionValue);
    oh->SizeOfImage = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfImage);
    oh->SizeOfHeaders = GetIntXValueAtOffset(uint32_t, ptr, offsets.SizeOfHeaders);
    oh->Checksum = GetIntXValueAtOffset(uint32_t, ptr, offsets.CheckSum);
    oh->Subsystem = GetIntXValueAtOffset(uint16_t, ptr, offsets.Subsystem);
    oh->DLLCharacteristics = GetIntXValueAtOffset(uint16_t, ptr, offsets.DllCharacteristics);
    oh->LoaderFlags = GetIntXValueAtOffset(uint32_t, ptr, offsets.LoaderFlags);
    oh->NumberOfRvaAndSizes = GetIntXValueAtOffset(uint32_t, ptr, offsets.NumberOfRvaAndSizes);

    data_entry_offset = offsets.DataDirectories;

//    debug_info(" - NumberOfRvaAndSizes: %u\n", oh->NumberOfRvaAndSizes);

    if ( oh->NumberOfRvaAndSizes == 0 )
        return 0;

    nr_of_rva_to_read = (oh->NumberOfRvaAndSizes > MAX_NR_OF_RVA_TO_READ) ? MAX_NR_OF_RVA_TO_READ : (uint8_t)oh->NumberOfRvaAndSizes;
    if ( oh->NumberOfRvaAndSizes != NUMBER_OF_RVA_AND_SIZES )
    {
        header_info("INFO: unusual value of NumberOfRvaAndSizes: %u\n", oh->NumberOfRvaAndSizes);
    }

    if ( nr_of_rva_to_read > 0 )
    {
        oh->DataDirectory = (PEDataDirectory*) malloc(sizeof(PEDataDirectory) * nr_of_rva_to_read);
        if ( !oh->DataDirectory )
        {
            header_info("INFO: allocation of DataDirectory with %u entries failed!\n", nr_of_rva_to_read);

            if ( nr_of_rva_to_read > NUMBER_OF_RVA_AND_SIZES )
            {
                header_info("INFO: Fallback to standard size of %u!\n", (uint32_t)NUMBER_OF_RVA_AND_SIZES);

                oh->NumberOfRvaAndSizes = NUMBER_OF_RVA_AND_SIZES;
                oh->DataDirectory = (PEDataDirectory*) malloc(sizeof(PEDataDirectory) * oh->NumberOfRvaAndSizes);

                if ( !oh->DataDirectory )
                {
                    header_error("ERROR: allocation of DataDirectory with %u entries failed!\n", oh->NumberOfRvaAndSizes);
                    oh->NumberOfRvaAndSizes = 0;
                    return -1;
                }
                nr_of_rva_to_read = NUMBER_OF_RVA_AND_SIZES;
            }
            else
            {
                oh->NumberOfRvaAndSizes = 0;
                return -1;
            }
        }

        for ( i = 0; i < nr_of_rva_to_read; i++ )
        {
            if ( !checkFileSpace(data_entry_offset, *abs_file_offset, size_of_data_entry, file_size) )
                break;

            if ( !checkLargeBlockSpace(&data_entry_offset, abs_file_offset, size_of_data_entry, block_l, fp) )
                break;

            ptr = &block_l[0];

            oh->DataDirectory[i].VirtualAddress = *((uint32_t*) &ptr[data_entry_offset]);
            oh->DataDirectory[i].Size = *((uint32_t*) &ptr[data_entry_offset + 4]);

            data_entry_offset += size_of_data_entry;
        }
    }

    return 0;
}

void PE_fillHeaderDataWithOptHeader(PE64OptHeader* oh,
                                    PHeaderData hd)
{
    if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR32_MAGIC )
        hd->h_bitness = 32;
    else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_NT_OPTIONAL_HDR64_MAGIC )
        hd->h_bitness = 64;
    else if ( oh->Magic == PeOptionalHeaderSignature.IMAGE_ROM_OPTIONAL_HDR_MAGIC )
    {
        header_info("INFO: ROM file.\n");
    }
    else
    {
        header_info("INFO: Unknown PeOptionalHeaderSignature (Magic) of %u.\n", oh->Magic);
    }

    if ( oh->NumberOfRvaAndSizes > IMG_DIR_ENTRY_CLR_RUNTIME_HEADER &&
        oh->DataDirectory[IMG_DIR_ENTRY_CLR_RUNTIME_HEADER].VirtualAddress != 0 )
    {
        hd->CPU_arch = ARCH_DOT_NET;
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
void PE_readSectionHeader(size_t header_start,
                          PECoffFileHeader* ch,
                          size_t start_file_offset,
                          size_t* abs_file_offset,
                          size_t file_size,
                          uint8_t p_sec_h,
                          FILE* fp,
                          unsigned char* block_s,
                          unsigned char* block_l,
                          PStringTable st,
                          int parse_svas,
                          PSVAS* svas,
                          PHeaderData hd)
{
    unsigned char *ptr = NULL;
    size_t offset;
    PEImageSectionHeader s_header;
    CodeRegionData code_region_data;
    uint16_t nr_of_sections = ch->NumberOfSections;
    uint16_t i = 0;
    size_t size;

    if ( parse_svas == 1 )
    {
        errno = 0;
        *svas = (PSVAS) calloc(nr_of_sections, sizeof(SVAS));
        if ( *svas == NULL )
        {
            header_error("ERROR (0x%x): Alloc failed!\n", errno);
            return;
        }
    }
    // read new large block to ease up offsetting
    if ( !checkFileSpace(header_start, start_file_offset, PE_SECTION_HEADER_SIZE, file_size) )
        return;

    *abs_file_offset = header_start + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
#if LIB_MODE == 0
    if ( p_sec_h )
        printf("Section Header:\n");
#endif

    for ( i = 0; i < nr_of_sections; i++ )
    {
//        debug_info(" - %u / %u\n", (i+1), nr_of_sections);

        if ( !checkFileSpace(offset, *abs_file_offset, PE_SECTION_HEADER_SIZE, file_size) )
            return;

        if ( !checkLargeBlockSpace(&offset, abs_file_offset, PE_SECTION_HEADER_SIZE, block_l, fp) )
            break;

        ptr = &block_l[offset];

        PE_fillSectionHeader(ptr, &s_header);
        
#if LIB_MODE == 0
        if ( p_sec_h )
            PE_printImageSectionHeader(&s_header, i, nr_of_sections, ch, *abs_file_offset+offset, start_file_offset, file_size, fp, block_s, st);
#endif

        if ( PE_isNullSectionHeader(&s_header) )
        {
            break;
        }
        if ( !PE_checkSectionHeader(&s_header, i, s_header.Name, start_file_offset, file_size) )
        {
//			offset += PE_SECTION_HEADER_SIZE;
//			continue;
        }
        if ( PE_isExecutableSectionHeader(&s_header) )
        {
            code_region_data = PE_fillCodeRegion(&s_header, ch, start_file_offset, file_size, fp, block_s, st);
            addCodeRegionDataToHeaderData(&code_region_data, hd);
        }

        if ( parse_svas )
        {
            (*svas)[i].PointerToRawData = s_header.PointerToRawData;
            (*svas)[i].SizeOfRawData = s_header.SizeOfRawData;
            (*svas)[i].VirtualAddress = s_header.VirtualAddress;
            (*svas)[i].VirtualSize = s_header.Misc.VirtualSize;
        }

        offset += PE_SECTION_HEADER_SIZE;
    }
#if LIB_MODE == 0
    if ( p_sec_h )
        printf("\n");
#endif
}

void PE_fillSectionHeader(const unsigned char* ptr,
                          PEImageSectionHeader* sh)
{
    // may not be zero terminated
    memcpy(sh->Name, (const char*)&ptr[PESectionHeaderOffsets.Name], IMG_SIZEOF_SHORT_NAME);
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

int PE_isNullSectionHeader(const PEImageSectionHeader* sh)
{
    return sh->Name[0] == 0 &&
           sh->Misc.VirtualSize == 0 &&
           sh->VirtualAddress == 0 &&
           sh->SizeOfRawData == 0 &&
           sh->PointerToRawData == 0 &&
           sh->PointerToRelocations == 0 &&
           sh->PointerToLinenumbers == 0 &&
           sh->NumberOfRelocations == 0 &&
           sh->NumberOfLinenumbers == 0 &&
           sh->Characteristics == 0;
}

int PE_checkSectionHeader(const PEImageSectionHeader* sh,
                                    uint16_t idx,
                                    const char* name,
                                    size_t start_file_offset,
                                    size_t file_size)
{
//    debug_info("PE_checkSectionHeader()\n");
    uint32_t error_code = 0;
    uint32_t section_size = PE_calculateSectionSize(sh);

    if ( !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA
                                          & PESectionCharacteristics.IMAGE_SCN_MEM_READ
                                          & PESectionCharacteristics.IMAGE_SCN_MEM_WRITE) )
    {
//        debug_info("!(U & R & W): \n");
        if ( sh->PointerToRawData == 0 )
        {
            error_code |= 0x1;
        }
        if ( start_file_offset + section_size == 0 )
        {
            error_code |= 0x2;
        }
        if ( start_file_offset + section_size > file_size )
        {
            error_code |= 0x4;
        }
        if ( start_file_offset + sh->PointerToRawData + section_size > file_size )
        {
            error_code |= 0x8;
        }
    }

    if ( error_code )
    {
        header_info("INFO: Section header %d (\"%s\") is invalid.\n", idx+1, name);
        if ( error_code & 0x1 )
            header_info(" - PointerToRawData is 0\n");
        if ( error_code & 0x2 )
            header_info(" - section_size is 0\n");
        if ( error_code & 0x4 )
            header_info(" - section_size (%u) is > file_size (%zu)\n", section_size, file_size);
        if ( error_code & 0x8 )
            header_info(" - PointerToRawData (%u) + section_size (%u) = (%u) is > file_size (%zu)\n",
                     sh->PointerToRawData,section_size,sh->PointerToRawData+section_size, file_size);
    }

    return error_code == 0;
}

uint8_t PE_isExecutableSectionHeader(const PEImageSectionHeader* sh)
{
    return hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE) ||
            hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_MEM_EXECUTE);
}

CodeRegionData PE_fillCodeRegion(const PEImageSectionHeader* sh,
                                 PECoffFileHeader* ch,
                                 size_t start_file_offset,
                                 size_t file_size,
                                 FILE* fp,
                                 unsigned char* block_s,
                                 PStringTable st)
{
    size_t end_of_raw_data = 0;
    char *name = NULL;
    size_t size = PE_calculateSectionSize(sh);
    end_of_raw_data = sh->PointerToRawData + size;
    CodeRegionData code_region_data;

//	if ( sh->VirtualSize == 0 ) // object file
    // uninitialized data
    // add to regions or not ???
//	if ( size == 0 )
//	{
//		return (CodeRegionData) {"", 0, 0};
//	}

    PE_getRealName(sh->Name, &name, ch, start_file_offset, file_size, fp, block_s, st);

    code_region_data.start = sh->PointerToRawData;
    code_region_data.end = end_of_raw_data;
    code_region_data.name = name;

    return code_region_data; // return value
}

/**
 * VirtualSize may be zero padded, SizeOfRawData may be rounded.
 * Objdump seems to choose the lesser one, or SizeOfRawData if VirtualSize is 0.
 * If SizeOfRawData the size is 0 => there is no code region.
 * TODO: clean up
 */
uint32_t PE_calculateSectionSize(const PEImageSectionHeader* sh)
{
//	if ( sh->PointerToRawData == 0 ) return 0;
    uint32_t size = sh->Misc.VirtualSize;

    if ( sh->SizeOfRawData == 0
        && ( ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE)
                && !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA)
                )
            || hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_INITIALIZED_DATA)
            //|| ( hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_CODE
            //                                    & PESectionCharacteristics.IMAGE_SCN_MEM_READ
            //                                    & PESectionCharacteristics.IMAGE_SCN_MEM_WRITE)
            //     &&
            //     !hasFlag32(sh->Characteristics, PESectionCharacteristics.IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            //   )
            )
        )
    {
        size = sh->SizeOfRawData;
    }
    else if ( ( sh->SizeOfRawData < sh->Misc.VirtualSize && sh->SizeOfRawData > 0 )
               || sh->Misc.VirtualSize == 0 
            )
    {
        size = sh->SizeOfRawData;
    }
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
uint8_t PE_hasHeaderAtOffset(size_t offset,
                             size_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             unsigned char* block_s,
                             unsigned char* block_l)
{
    PEImageDosHeader image_dos_header;
    int s = 0;
    uint8_t pe_header_type = 0;
//	uint32_t size = readCustomBlock(file_name, offset, BLOCKSIZE_LARGE, block_l);
    size_t size = readFile(fp, offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
    {
        header_error("ERROR: PE_hasHeaderAtOffset: Read large block failed.\n");
        return 0;
    }

    if ( !checkBytes(MAGIC_PE_BYTES, MAGIC_PE_BYTES_LN, block_l) )
        return 0;

    s = PE_readImageDosHeader(&image_dos_header, offset, file_size, block_l);
    if ( s != 0 ) return 0;

    if ( !checkBytes(MAGIC_DOS_STUB_BEGINNING, MAGIC_DOS_STUB_BEGINNING_LN, &block_l[PE_DOS_STUB_OFFSET]) )
        header_info("INFO: No DOS stub found.\n");

    pe_header_type = PE_checkPESignature(image_dos_header.e_lfanew, 0, abs_file_offset, file_size, fp, block_s, block_l);
    if ( pe_header_type != 1 )
    {
//		debug_info("No valid PE00 section signature found!\n");
//		if ( pe_header_type == 2 )
//			hd->headertype = HEADER_TYPE_NE;
//		else
//			hd->headertype = HEADER_TYPE_MS_DOS;

        return 0;
    }

    return 1;
}

void PE_parseCertificates(PE64OptHeader* oh,
                          size_t start_file_offset,
                          size_t file_size,
                          const char* certificate_directory,
                          FILE* fp,
                          unsigned char* block_s)
{
    uint8_t table_size;
    PeAttributeCertificateTable table[MAX_CERT_TABLE_SIZE];

    if ( oh->NumberOfRvaAndSizes <= IMG_DIR_ENTRY_CERTIFICATE )
    {
        header_error("ERROR: Data Directory too small for CERTIFICATE entry!\n");
        return;
    }

    //table_size = PEgetNumberOfCertificates(opt_header);
//	printf("has certificate: %d\n", PEhasCertificate(opt_header));
//	printf("number of certificates: %d\n", table_size);
    table_size = PE_fillCertificateTable(oh, start_file_offset, file_size, fp, block_s, table, MAX_CERT_TABLE_SIZE);

    PE_printAttributeCertificateTable(table, table_size, start_file_offset+oh->DataDirectory[IMG_DIR_ENTRY_CERTIFICATE].VirtualAddress);

    if ( certificate_directory != NULL )
        PE_writeCertificatesToFile(table, table_size, certificate_directory, file_size, fp, block_s);
}

#endif
