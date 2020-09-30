#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "headerParserLib.h"
#include "headerParserLibPE.h"
#include "headerDataHandler.h"

#include "Globals.h"
#include "utils/Helper.h"
#include "utils/common_fileio.h"
#include "utils/blockio.h"
#include "parser.h"

static int sanitizeArgs();
static int getBasicInfoA(const char* file, uint64_t start, uint8_t force, HeaderData* hd);
static int getPEHeaderDataA(const char* file, uint64_t start, PEHeaderData* pehd);
static PEHeaderData* getInitializedPEHeaderData();

// gcc -fPIC -shared -Ofast -o libheaderparser.so headerParserLib.c headerParserLib.h HeaderData.h HeaderData.c -Wall


HeaderData* getBasicHeaderParserInfo(const char* file, uint64_t start, uint8_t force)
{
	HeaderData* hd = (HeaderData*) malloc(sizeof(HeaderData));
	if ( hd == NULL )
		return NULL;
	
	if ( getBasicInfoA(file, start, force, hd) != 0 )
	{
		freeHeaderData(hd);
		return NULL;
	}
	
	return hd;
}

int getBasicInfoA(const char* file, uint64_t start, uint8_t force, HeaderData* hd)
{
	uint32_t n = 0;
	info_level = INFO_LEVEL_BASIC;
	abs_file_offset = start;
	start_file_offset = start;
	file_size = 0;

	memset(block_large, 0, BLOCKSIZE_LARGE);
	memset(block_standard, 0, BLOCKSIZE);
	memset(file_name, 0, PATH_MAX);

	HD = hd;

	initHeaderData(HD, DEFAULT_CODE_REGION_CAPACITY);
	expandFilePath(file, file_name);

	debug_info("abs_file_offset: %lu\n", abs_file_offset);
	debug_info("start_file_offset: %lu\n", start_file_offset);
	debug_info("file_name: %s\n", file_name);

	file_size = getSize(file_name);
	if ( file_size == 0 )
		return -1;

	if ( sanitizeArgs() != 0 )
		return 0;

	n = readLargeBlock(file_name, abs_file_offset);
	if ( !n )
		return -3;

	parseHeader(force);

	return 0;
}

PEHeaderData* getPEHeaderData(const char* file, uint64_t start)
{
	PEHeaderData* pehd = getInitializedPEHeaderData();
	if ( !pehd )
		return NULL;

	if ( getPEHeaderDataA(file, start, pehd) != 0 )
	{
		freePEHeaderData(pehd);
		return NULL;
	}

	return pehd;
}

PEHeaderData* getInitializedPEHeaderData()
{
	PEHeaderData* pehd = NULL;

	pehd = (PEHeaderData*) calloc(1, sizeof(PEHeaderData));
	if ( pehd == NULL )
		return NULL;

	pehd->image_dos_header = (PEImageDosHeader*) calloc(1, sizeof(PEImageDosHeader));
	pehd->coff_header = (PECoffFileHeader*) calloc(1, sizeof(PECoffFileHeader));
	pehd->opt_header = (PE64OptHeader*) calloc(1, sizeof(PE64OptHeader));
	if ( pehd->image_dos_header == NULL || pehd->coff_header == NULL || pehd->opt_header == NULL )
	{
		freePEHeaderData(pehd);
		return NULL;
	}

	return pehd;
}

int getPEHeaderDataA(const char* file, uint64_t start, PEHeaderData* pehd)
{
	HeaderData* hd = NULL;
	uint32_t n = 0;
	int s = 0;

	info_level = INFO_LEVEL_FULL;
	abs_file_offset = start;
	start_file_offset = start;
	file_size = 0;

	memset(block_large, 0, BLOCKSIZE_LARGE);
	memset(block_standard, 0, BLOCKSIZE);
	memset(file_name, 0, PATH_MAX);

	// is used in parsing
	hd = (HeaderData*) malloc(sizeof(HeaderData));
	if ( hd == NULL )
		return -1;
	initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);
	HD = hd;
	pehd->hd = hd;

//	initExtendedPEHeaderData(HD, DEFAULT_CODE_REGION_CAPACITY);
	expandFilePath(file, file_name);

	debug_info("abs_file_offset: %lu\n", abs_file_offset);
	debug_info("start_file_offset: %lu\n", start_file_offset);
	debug_info("file_name: %s\n", file_name);

	file_size = getSize(file_name);
	if ( file_size == 0 )
		return -2;

	if ( sanitizeArgs() != 0 )
		return 0;

	n = readLargeBlock(file_name, abs_file_offset);
	if ( !n )
		return -3;

	if ( abs_file_offset + MIN_FILE_SIZE > file_size )
	{
		header_error("ERROR: file (%u) is too small for a start offset of %lu!\n", file_size, abs_file_offset);
		return -4;
	}

	s = parsePEHeader(FORCE_PE, pehd);

	// if error or not pe sig found
	if ( s < 0 || ( s > 0 && s < 4 ) )
		return -5;

	return 0;
}

void freePEHeaderData(PEHeaderData* hd)
{
	if ( hd == NULL )
		return;

	PEcleanUp(hd);
	freeHeaderData(hd->hd);

	free(hd->image_dos_header);
	free(hd->coff_header);
	free(hd->opt_header);

	free(hd);
}

int sanitizeArgs()
{
	if ( abs_file_offset + MIN_FILE_SIZE > file_size )
	{
//		header_error("ERROR: file (%u) is too small for a start offset of %lu!\n",
//			   file_size, abs_file_offset);
		return 1;
	}
	return 0;
}

HeaderData* getInitializedHeaderParserHeaderData()
{
	HeaderData* data;
	data = (HeaderData*) malloc(sizeof(HeaderData));

	if ( data == NULL )
		return NULL;

	initHeaderData(data, 1);

	return data;
}

void headerParser_freeLibHeaderData(HeaderData* data)
{
    free(data);
	freeHeaderData(HD);
	HD = NULL;
}

const char* getHeaderDataArchitecture(uint8_t id)
{
	if ( id >= ARCHITECTURE_NAMES_SIZE )
		id = 0;

	return architecture_names[id];
}

const char* getHeaderDataHeaderType(uint8_t id)
{
	if ( id >= HEADER_TYPES_SIZE )
		id = 0;

	return header_type_names[id];
}

const char* getHeaderDataEndianType(uint8_t id)
{
	if ( id >= ENDIAN_NAMES_SIZE )
		id = 0;

	return endian_type_names[id];
}
