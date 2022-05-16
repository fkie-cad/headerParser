#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "utils/Helper.h"
#include "utils/blockio.h"

#include "HeaderData.h"
#include "headerDataHandler.h"
#include "ArchitectureInfo.h"
#include "stringPool.h"
#include "Globals.h"

#include "art/ArtHeaderParser.h"
#include "dex/DexHeaderParser.h"
#include "elf/ElfHeaderParser.h"
#include "jar/JarHeaderParser.h"
#include "java/JavaClassHeaderParser.h"
#include "macho/MachOHeaderParser.h"
#include "msi/MsiHeaderParser.h"
#include "pe/PEHeaderParser.h"
#include "zip/ZipHeaderParser.h"

static void parseHeader(
    uint8_t force,
    PHeaderData hd,
    PGlobalParams gp,
    PPEParams pep,
    PElfParams elfp,
    PDexParams dexp
);

int isART(unsigned char* block);
int isELF(unsigned char* block);
int isPE(unsigned char* block);
int isDEX(unsigned char* block);
int isMachO(unsigned char* block);
int isMSI(unsigned char* block);
//int isPEArchive(unsigned char* block);
int isJavaClass(unsigned char* block);
int isZipArchive(unsigned char* block);



void parseHeader(uint8_t force, PHeaderData hd, PGlobalParams gp, PPEParams pep, PElfParams elfp, PDexParams dexp)
{
    info_level = gp->info_level;
    info_show_offsets = gp->info_show_offsets;

    if ( gp->file.abs_offset + MIN_FILE_SIZE > gp->file.size )
    {
        header_error("ERROR: filesize (0x%zx) is too small for a start offset of 0x%zx!\n",
                     gp->file.size, gp->file.abs_offset);
        hd->headertype = HEADER_TYPE_NONE;
    }
    else if ( force == FORCE_PE )
    {
        parsePEHeaderData(FORCE_PE, hd, gp, pep);
    }
    else if ( isELF(gp->data.block_main) )
    {
        parseELFHeader(hd, gp, elfp);
    }
    else if ( isPE(gp->data.block_main) )
    {
        parsePEHeaderData(FORCE_NONE, hd, gp, pep);
    }
    else if ( isDEX(gp->data.block_main) )
    {
        parseDexHeader(hd, gp, dexp);
    }
    else if ( isMachO(gp->data.block_main) )
    {
        parseMachOHeader(hd, gp);
    }
    else if ( isMSI(gp->data.block_main) )
    {
        parseMSIHeader(hd, gp, pep);
    }
//	else if ( isPEArchive(gp->data.block_main))
//	{
//		header_info("INFO: Archive\n");
//	}
    else if ( isJavaClass(gp->data.block_main) )
    {
        parseJavaClassHeader(hd, gp);
    }
    else if ( isZipArchive(gp->data.block_main) )
    {
        parseZip(hd, gp);
    }
    else if ( isART(gp->data.block_main) )
    {
        parseArtHeader(hd, gp);
    }
    else
    {
        hd->headertype = HEADER_TYPE_NONE;
    }
}

int isART(unsigned char* block)
{
    return checkBytes(MAGIC_ART_BYTES, MAGIC_ART_BYTES_LN, block);
}

int isELF(unsigned char* block)
{
    return checkBytes(MAGIC_ELF_BYTES, MAGIC_ELF_BYTES_LN, block);
}

int isPE(unsigned char* block)
{
    return checkBytes(MAGIC_PE_BYTES, MAGIC_PE_BYTES_LN, block);
}

int isDEX(unsigned char* block)
{
    return checkBytes(MAGIC_DEX_BYTES, MAGIC_DEX_BYTES_LN, block);
}

int isMachO(unsigned char* block)
{
    return checkBytes(MAGIC_MACH_O_BYTES_32, MAGIC_MACH_O_BYTES_LN, block)
            || checkBytes(MAGIC_MACH_O_BYTES_64, MAGIC_MACH_O_BYTES_LN, block)
            || checkBytes(MAGIC_MACH_O_BYTES_32_RV, MAGIC_MACH_O_BYTES_LN, block)
            || checkBytes(MAGIC_MACH_O_BYTES_64_RV, MAGIC_MACH_O_BYTES_LN, block);
}

int isMSI(unsigned char* block)
{
    return checkBytes(MAGIC_MSI_BYTES, MAGIC_MSI_BYTES_LN, block);
}

//int isPEArchive(unsigned char* block)
//{
//	return checkBytes(MAGIC_PE_ARCHIV_BYTES, MAGIC_PE_ARCHIV_BYTES_LN, block);
//}

int isJavaClass(unsigned char* block)
{
    return checkBytes(MAGIC_JAVA_CLASS_BYTES, MAGIC_JAVA_CLASS_BYTES_LN, block);
}

int isZipArchive(unsigned char* block)
{
    return checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, block);
}

HP_API
const char* getHeaderDataArchitecture(uint16_t id)
{
    if ( id >= ARCHITECTURE_NAMES_SIZE )
        id = 0;

    return architecture_names[id];
}

HP_API
const char* getHeaderDataHeaderType(uint8_t id)
{
    if ( id >= HEADER_TYPES_SIZE )
        id = 0;

    return header_type_names[id];
}

HP_API
const char* getHeaderDataEndianType(uint8_t id)
{
    if ( id >= ENDIAN_NAMES_SIZE )
        id = 0;

    return endian_type_names[id];
}

//int initGlobalParams(GlobalParams* gp)
//{
//    memset(gp, 0, sizeof(GlobalParams));
//    gp->data.block_main = (uint8_t*)malloc(BLOCKSIZE_LARGE);
//    if ( !gp->data.block_main )
//        return -1;
//    gp->data.block_sub = (uint8_t*)malloc(BLOCKSIZE_SMALL);
//    if ( !gp->data.block_sub )
//        return -1;
//}
//
//int freeGlobalParams(GlobalParams* gp)
//{
//    if ( gp->data.block_main )
//        free(gp->data.block_main);
//
//    if ( !gp->data.block_sub )
//        free(gp->data.block_sub);
//
//    if ( !gp->block_dyn )
//        free(gp->block_dyn);
//
//    memset(gp, 0, sizeof(GlobalParams));
//}
