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

#include "headerParserLib.h"
#include "headerParserLibPE.h"
#include "headerDataHandler.h"

#include "errorCodes.h"
#include "Globals.h"
#include "utils/Helper.h"
#include "utils/common_fileio.h"
#include "utils/Files.h"
#include "utils/blockio.h"
#include "parser.h"

static int sanitizeArgs(size_t abs_file_offset, size_t file_size);
static int getBasicInfoA(const char* file, size_t start, uint8_t force, HeaderData* hd);
static int getPEHeaderDataA(const char* file, size_t start, PEHeaderData* pehd);
static PEHeaderData* getInitializedPEHeaderData();

// gcc -fPIC -shared -Ofast -o libheaderparser.so headerParserLib.c headerParserLib.h HeaderData.h HeaderData.c -Wall


HP_API
HeaderData* getBasicHeaderParserInfo(const char* file, size_t start, uint8_t force)
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

int getBasicInfoA(const char* file, size_t start, uint8_t force, HeaderData* hd)
{
    size_t n = 0;
    int s;
    GlobalParams gp;
    int errsv;
    PEParams pep;
    ElfParams elfp;
    DexParams dexp;
    char file_name[PATH_MAX];

    memset(&gp, 0, sizeof(GlobalParams));
    memset(&pep, 0, sizeof(PEParams));
    memset(&elfp, 0, sizeof(ElfParams));
    memset(&dexp, 0, sizeof(DexParams));

    gp.info_level = INFO_LEVEL_BASIC;
    gp.file.abs_offset = start;
    gp.file.start_offset = start;
    gp.file.size = 0;

//	memset(gp.data.block_main, 0, BLOCKSIZE_LARGE);
//	memset(gp.data.block_sub, 0, BLOCKSIZE_SMALL);
    memset(file_name, 0, PATH_MAX);

    s = initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);
    if ( s!=0 )
    {
        return -5;
    }
    s = expandFilePath(file, file_name);
    if ( s != 0 )
        return s;

    //debug_info("abs_file_offset: 0x%zx\n", gp.file.abs_offset);
    //debug_info("start_file_offset: 0x%zx\n", gp.file.start_offset);
    //debug_info("file_name: %s\n", file_name);

    errno = 0;
    gp.file.handle = fopen(file_name, "rb");
    errsv = errno;
    if ( gp.file.handle == NULL)
    {
//        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, gp.file_name);
        return -1;
    }

    gp.file.size = getSizeFP(gp.file.handle);
    if ( gp.file.size == 0 )
    {
        s = -2;
        goto exit;
    }

    if ( sanitizeArgs(gp.file.abs_offset, gp.file.size) != 0 )
    {
        // return no error, so not NULL initialized data is returned
        s = 0;
        goto exit;
    }

    n = readFile(gp.file.handle, gp.file.abs_offset, BLOCKSIZE_LARGE, gp.data.block_main);
    if ( !n )
    {
        s = -3;
        goto exit;
    }

    parseHeader(force, hd, &gp, &pep, &elfp, &dexp);

exit:
    if ( gp.file.handle != NULL )
        fclose(gp.file.handle);

    return s;
}

HP_API
PEHeaderData* getPEHeaderData(const char* file, size_t start)
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

int getPEHeaderDataA(const char* file, size_t start, PEHeaderData* pehd)
{
    HeaderData* hd = NULL;
    size_t n = 0;
    int s = 0;
    int errsv = 0;
    GlobalParams gp;
    PEParams pep;
    char file_name[PATH_MAX];

    memset(&gp, 0, sizeof(GlobalParams));
    gp.info_level = INFO_LEVEL_EXTENDED;
    gp.file.abs_offset = start;
    gp.file.start_offset = start;
    gp.file.size = 0;

    memset(&pep, 0, sizeof(PEParams));
    pep.info_level = INFO_LEVEL_PE_EXTENDED | INFO_LEVEL_PE_LIB;

//	memset(gp.data.block_main, 0, BLOCKSIZE_LARGE);
//	memset(gp.data.block_sub, 0, BLOCKSIZE_SMALL);
    memset(file_name, 0, PATH_MAX);

    // is used in parsing
    hd = (HeaderData*) malloc(sizeof(HeaderData));
    if ( hd == NULL )
        return -1;
    initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);
    pehd->hd = hd;

//	initExtendedPEHeaderData(HD, DEFAULT_CODE_REGION_CAPACITY);
    s = expandFilePath(file, file_name);
    if ( s != 0 )
        return s;

    //debug_info("abs_file_offset: 0x%lx\n", gp.file.abs_offset);
    //debug_info("start_file_offset: 0x%lx\n", gp.file.start_offset);
    //debug_info("file_name: %s\n", file_name);

    errno = 0;
    gp.file.handle = fopen(file_name, "rb");
    errsv = errno;
    if ( gp.file.handle == NULL)
    {
//        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, gp.file_name);
        return -2;
    }

    gp.file.size = getSizeFP(gp.file.handle);
    if ( gp.file.size == 0 )
    {
        s = -3;
        goto exit;
    }

    if ( sanitizeArgs(gp.file.abs_offset, gp.file.size) != 0 )
    {
        s = -4;
        goto exit;
    }

    n = readFile(gp.file.handle, gp.file.abs_offset, BLOCKSIZE_LARGE, gp.data.block_main);
    if ( !n )
    {
        s = -5;
        goto exit;
    }

    if ( gp.file.abs_offset + MIN_FILE_SIZE > gp.file.size )
    {
        header_error("ERROR: filesize (0x%zx) is too small for a start offset of 0x%zx!\n", gp.file.size, gp.file.abs_offset);
        s = -6;
        goto exit;
    }

    s = parsePEHeader(FORCE_PE, pehd, hd, &gp, &pep);

    // if error or not pe sig found
    if ( s < 0 || ( s > 0 && s < 4 ) )
    {
        s = -7;
        goto exit;
    }

exit:
    if ( gp.file.handle != NULL )
        fclose(gp.file.handle);

    return s;
}

HP_API
void freePEHeaderData(PEHeaderData* pehd)
{
    if ( pehd == NULL )
        return;

    PE_cleanUp(pehd);
    freeHeaderData(pehd->hd);

    if ( pehd->image_dos_header )
        free(pehd->image_dos_header);
    if ( pehd->coff_header )
        free(pehd->coff_header);
    if ( pehd->opt_header )
        free(pehd->opt_header);

    free(pehd);
}

int sanitizeArgs(size_t abs_file_offset, size_t file_size)
{
    if ( abs_file_offset + MIN_FILE_SIZE > file_size )
    {
//		header_error("ERROR: filesize (%u) is too small for a start offset of %lu!\n",
//			   file_size, abs_file_offset);
        return 1;
    }
    return 0;
}

HP_API
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

//HP_API
//const char* getHeaderDataArchitecture(uint16_t id)
//{
//    if ( id >= ARCHITECTURE_NAMES_SIZE )
//        id = 0;
//
//    return architecture_names[id];
//}
//
//HP_API
//const char* getHeaderDataHeaderType(uint8_t id)
//{
//    if ( id >= HEADER_TYPES_SIZE )
//        id = 0;
//
//    return header_type_names[id];
//}
//
//HP_API
//const char* getHeaderDataEndianType(uint8_t id)
//{
//    if ( id >= ENDIAN_NAMES_SIZE )
//        id = 0;
//
//    return endian_type_names[id];
//}
