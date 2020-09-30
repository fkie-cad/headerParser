#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "utils/Helper.h"
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

static void parseHeader(uint8_t force);

uint8_t isART();
uint8_t isELF();
uint8_t isPE();
uint8_t isDEX();
uint8_t isMachO();
uint8_t isMSI();
//uint8_t isPEArchive();
uint8_t isJavaClass();
uint8_t isZipArchive();

void parseHeader(uint8_t force)
{
	if ( abs_file_offset + MIN_FILE_SIZE > file_size )
	{
		header_error("ERROR: file (%u) is too small for a start offset of %zu!\n",
				file_size, abs_file_offset);

		HD->headertype = HEADER_TYPE_NONE;
	}
	else if ( force == FORCE_PE )
	{
		parsePEHeaderData(FORCE_PE);
	}
	else if ( isELF() )
	{
		parseELFHeader();
	}
	else if ( isPE() )
	{
		parsePEHeaderData(FORCE_NONE);
	}
	else if ( isDEX() )
	{
		parseDexHeader();
	}
	else if ( isMachO() )
	{
		parseMachOHeader();
	}
	else if ( isMSI() )
	{
		parseMSIHeader();
	}
//	else if ( isPEArchive())
//	{
//		header_info("INFO: Archive\n");
//	}
	else if ( isJavaClass() )
	{
		parseJavaClassHeader();
	}
	else if ( isZipArchive() )
	{
		parseZip();
	}
	else if ( isART() )
	{
		parseArtHeader();
	}
	else
	{
		HD->headertype = HEADER_TYPE_NONE;
	}
}

uint8_t isART()
{
	return checkBytes(MAGIC_ART_BYTES, MAGIC_ART_BYTES_LN, block_large);
}

uint8_t isELF()
{
	return checkBytes(MAGIC_ELF_BYTES, MAGIC_ELF_BYTES_LN, block_large);
}

uint8_t isPE()
{
	return checkBytes(MAGIC_PE_BYTES, MAGIC_PE_BYTES_LN, block_large);
}

uint8_t isDEX()
{
	return checkBytes(MAGIC_DEX_BYTES, MAGIC_DEX_BYTES_LN, block_large);
}

uint8_t isMachO()
{
	return checkBytes(MAGIC_MACH_O_BYTES_32, MAGIC_MACH_O_BYTES_LN, block_large)
			|| checkBytes(MAGIC_MACH_O_BYTES_64, MAGIC_MACH_O_BYTES_LN, block_large)
			|| checkBytes(MAGIC_MACH_O_BYTES_32_RV, MAGIC_MACH_O_BYTES_LN, block_large)
			|| checkBytes(MAGIC_MACH_O_BYTES_64_RV, MAGIC_MACH_O_BYTES_LN, block_large);
}

uint8_t isMSI()
{
	return checkBytes(MAGIC_MSI_BYTES, MAGIC_MSI_BYTES_LN, block_large);
}

//uint8_t isPEArchive()
//{
//	return checkBytes(MAGIC_PE_ARCHIV_BYTES, MAGIC_PE_ARCHIV_BYTES_LN, block_large);
//}

uint8_t isJavaClass()
{
	return checkBytes(MAGIC_JAVA_CLASS_BYTES, MAGIC_JAVA_CLASS_BYTES_LN, block_large);
}

uint8_t isZipArchive()
{
	return checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, block_large);
}
