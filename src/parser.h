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

static void parseHeader(uint8_t force, PHeaderData hd, PGlobalParams gp, PPEParams pep, PElfParams elfp);

int isART(unsigned char* block);
int isELF(unsigned char* block);
int isPE(unsigned char* block);
int isDEX(unsigned char* block);
int isMachO(unsigned char* block);
int isMSI(unsigned char* block);
//int isPEArchive(unsigned char* block);
int isJavaClass(unsigned char* block);
int isZipArchive(unsigned char* block);

void parseHeader(uint8_t force, PHeaderData hd, PGlobalParams gp, PPEParams pep, PElfParams elfp)
{
    info_level = gp->info_level;
    info_show_offsets = gp->info_show_offsets;

    if ( gp->abs_file_offset + MIN_FILE_SIZE > gp->file_size )
    {
        header_error("ERROR: filesize (0x%zx) is too small for a start offset of 0x%zx!\n",
                     gp->file_size, gp->abs_file_offset);
        hd->headertype = HEADER_TYPE_NONE;
    }
    else if ( force == FORCE_PE )
    {
        parsePEHeaderData(FORCE_PE, hd, gp, pep);
    }
    else if ( isELF(gp->block_large) )
    {
        parseELFHeader(hd, gp, elfp);
    }
    else if ( isPE(gp->block_large) )
    {
        parsePEHeaderData(FORCE_NONE, hd, gp, pep);
    }
    else if ( isDEX(gp->block_large) )
    {
        parseDexHeader(hd, gp);
    }
    else if ( isMachO(gp->block_large) )
    {
        parseMachOHeader(hd, gp);
    }
    else if ( isMSI(gp->block_large) )
    {
        parseMSIHeader(hd, gp, pep);
    }
//	else if ( isPEArchive(gp->block_large))
//	{
//		header_info("INFO: Archive\n");
//	}
    else if ( isJavaClass(gp->block_large) )
    {
        parseJavaClassHeader(hd, gp);
    }
    else if ( isZipArchive(gp->block_large) )
    {
        parseZip(hd, gp);
    }
    else if ( isART(gp->block_large) )
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