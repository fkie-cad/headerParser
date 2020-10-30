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

static void parseHeader(uint8_t force, PHeaderData hd, PGlobalParams gp, PPEParams pep);

uint8_t isART(unsigned char* block);
uint8_t isELF(unsigned char* block);
uint8_t isPE(unsigned char* block);
uint8_t isDEX(unsigned char* block);
uint8_t isMachO(unsigned char* block);
uint8_t isMSI(unsigned char* block);
//uint8_t isPEArchive(unsigned char* block);
uint8_t isJavaClass(unsigned char* block);
uint8_t isZipArchive(unsigned char* block);

void parseHeader(uint8_t force, PHeaderData hd, PGlobalParams gp, PPEParams pep)
{
    info_level = gp->info_level;

	if ( gp->abs_file_offset + MIN_FILE_SIZE > gp->file_size )
	{
#if defined(_WIN32)
		header_error("ERROR: file (%zu) is too small for a start offset of %llu!\n",
					 gp->file_size, gp->abs_file_offset);
#else
		header_error("ERROR: file (%zu) is too small for a start offset of %lu!\n",
					 gp->file_size, gp->abs_file_offset);
#endif
		hd->headertype = HEADER_TYPE_NONE;
	}
	else if ( force == FORCE_PE )
	{
		parsePEHeaderData(FORCE_PE, hd, gp, pep);
	}
	else if ( isELF(gp->block_large) )
	{
		parseELFHeader(hd, gp);
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

uint8_t isART(unsigned char* block)
{
	return checkBytes(MAGIC_ART_BYTES, MAGIC_ART_BYTES_LN, block);
}

uint8_t isELF(unsigned char* block)
{
	return checkBytes(MAGIC_ELF_BYTES, MAGIC_ELF_BYTES_LN, block);
}

uint8_t isPE(unsigned char* block)
{
	return checkBytes(MAGIC_PE_BYTES, MAGIC_PE_BYTES_LN, block);
}

uint8_t isDEX(unsigned char* block)
{
	return checkBytes(MAGIC_DEX_BYTES, MAGIC_DEX_BYTES_LN, block);
}

uint8_t isMachO(unsigned char* block)
{
	return checkBytes(MAGIC_MACH_O_BYTES_32, MAGIC_MACH_O_BYTES_LN, block)
			|| checkBytes(MAGIC_MACH_O_BYTES_64, MAGIC_MACH_O_BYTES_LN, block)
			|| checkBytes(MAGIC_MACH_O_BYTES_32_RV, MAGIC_MACH_O_BYTES_LN, block)
			|| checkBytes(MAGIC_MACH_O_BYTES_64_RV, MAGIC_MACH_O_BYTES_LN, block);
}

uint8_t isMSI(unsigned char* block)
{
	return checkBytes(MAGIC_MSI_BYTES, MAGIC_MSI_BYTES_LN, block);
}

//uint8_t isPEArchive(unsigned char* block)
//{
//	return checkBytes(MAGIC_PE_ARCHIV_BYTES, MAGIC_PE_ARCHIV_BYTES_LN, block);
//}

uint8_t isJavaClass(unsigned char* block)
{
	return checkBytes(MAGIC_JAVA_CLASS_BYTES, MAGIC_JAVA_CLASS_BYTES_LN, block);
}

uint8_t isZipArchive(unsigned char* block)
{
	return checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, block);
}
