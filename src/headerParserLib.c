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

static int sanitizeArgs(uint64_t abs_file_offset, size_t file_size);
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
	GlobalParams gp;
	memset(&gp, 0, sizeof(GlobalParams));
	PEParams pep;
	memset(&pep, 0, sizeof(PEParams));

	gp.info_level = INFO_LEVEL_BASIC;
    gp.abs_file_offset = start;
    gp.start_file_offset = start;
    gp.file_size = 0;

	memset(gp.block_large, 0, BLOCKSIZE_LARGE);
	memset(gp.block_standard, 0, BLOCKSIZE);
	memset(gp.file_name, 0, PATH_MAX);

	initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);
	expandFilePath(file, gp.file_name);

	debug_info("abs_file_offset: %lu\n", gp.abs_file_offset);
	debug_info("start_file_offset: %lu\n", gp.start_file_offset);
	debug_info("file_name: %s\n", gp.file_name);

    gp.file_size = getSize(gp.file_name);
	if ( gp.file_size == 0 )
		return -1;

	if ( sanitizeArgs(gp.abs_file_offset, gp.file_size) != 0 )
		return 0;

//	n = readLargeBlock(file_name, abs_file_offset);
	n = readCustomBlock(gp.file_name, gp.abs_file_offset, BLOCKSIZE_LARGE, gp.block_large);
	if ( !n )
		return -3;

	parseHeader(force, hd, &gp, &pep);

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
    GlobalParams gp;
    memset(&gp, 0, sizeof(GlobalParams));
    PEParams pep;
    memset(&pep, 0, sizeof(PEParams));

	gp.info_level = INFO_LEVEL_FULL;
    gp.abs_file_offset = start;
    gp.start_file_offset = start;
    gp.file_size = 0;

	memset(gp.block_large, 0, BLOCKSIZE_LARGE);
	memset(gp.block_standard, 0, BLOCKSIZE);
	memset(gp.file_name, 0, PATH_MAX);

	// is used in parsing
	hd = (HeaderData*) malloc(sizeof(HeaderData));
	if ( hd == NULL )
		return -1;
	initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);
	pehd->hd = hd;

//	initExtendedPEHeaderData(HD, DEFAULT_CODE_REGION_CAPACITY);
	expandFilePath(file, gp.file_name);

	debug_info("abs_file_offset: %lu\n", gp.abs_file_offset);
	debug_info("start_file_offset: %lu\n", gp.start_file_offset);
	debug_info("file_name: %s\n", gp.file_name);

    gp.file_size = getSize(gp.file_name);
	if ( gp.file_size == 0 )
		return -2;

	if ( sanitizeArgs(gp.abs_file_offset, gp.file_size) != 0 )
		return 0;

	n = readCustomBlock(gp.file_name, gp.abs_file_offset, BLOCKSIZE_LARGE, gp.block_large);
//	n = readLargeBlock(file_name, abs_file_offset);
	if ( !n )
		return -3;

	if ( gp.abs_file_offset + MIN_FILE_SIZE > gp.file_size )
	{
		header_error("ERROR: file (%zu) is too small for a start offset of %lu!\n", gp.file_size, gp.abs_file_offset);
		return -4;
	}

	s = parsePEHeader(FORCE_PE, pehd, hd, &gp, &pep);

	// if error or not pe sig found
	if ( s < 0 || ( s > 0 && s < 4 ) )
		return -5;

	return 0;
}

void freePEHeaderData(PEHeaderData* pehd)
{
	if ( pehd == NULL )
		return;

	PE_cleanUp(pehd);
	freeHeaderData(pehd->hd);

	free(pehd->image_dos_header);
	free(pehd->coff_header);
	free(pehd->opt_header);

	free(pehd);
}

int sanitizeArgs(uint64_t abs_file_offset, size_t file_size)
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

//void headerParser_freeLibHeaderData(HeaderData* data)
//{
//    free(data);
//	freeHeaderData(hd);
//	hd = NULL;
//}

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
