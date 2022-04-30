#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4100 4101 )
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

#define VERBOSE_MODE 1

#ifndef LIB_MODE
#define LIB_MODE (0)
#endif

#include "print.h"
#include "utils/env.h"
#include "Globals.h"

#include "utils/Converter.h"
#include "utils/common_fileio.h"
#include "utils/Files.h"
#include "utils/blockio.h"
#include "utils/Helper.h"

#include "parser.h"

//#define DILLER

#define BIN_NAME "headerParser"
#define BIN_VS "1.15.0"
#define BIN_DATE "04.02.2022"

#define LIN_PARAM_IDENTIFIER ('-')
#define WIN_PARAM_IDENTIFIER ('/')
#ifdef _WIN32
#define PARAM_IDENTIFIER WIN_PARAM_IDENTIFIER
#else
#define PARAM_IDENTIFIER LIN_PARAM_IDENTIFIER
#endif


static void printUsage();
static void printHelp();
static bool isCallForHelp(const char* arg1);
static int parseArgs(int argc, char** argv, PGlobalParams gp, PPEParams pep, PElfParams elfp, uint8_t* force, char* file_name);
static void sanitizeArgs(PGlobalParams gp);
static uint8_t isArgOfType(const char* arg, char* type);
static uint8_t hasValue(char* type, int i, int end_i);
static uint8_t getInfoLevel(char* arg);
static void printHeaderData(uint8_t, PHeaderData hd, unsigned char* block);
static void printHeaderData1(PHeaderData hd);
static uint8_t getForceOption(const char* arg);



#ifdef DILLER
__declspec(dllexport)
#endif
int
#ifdef _WIN32
__cdecl
#endif
main(int argc, char** argv)
{
    size_t n = 0;
    int errsv = 0;
    char file_name[PATH_MAX];

    HeaderData* hd = NULL;
    uint8_t force = FORCE_NONE;

    GlobalParams gp;

    PEParams pep;
    ElfParams elfp;

    memset(&gp, 0, sizeof(GlobalParams));
    memset(&pep, 0, sizeof(PEParams));
    memset(&elfp, 0, sizeof(ElfParams));
    memset(file_name, 0, PATH_MAX);

    int s = 0;

    if ( argc < 2 )
    {
        printUsage();
        return 0;
    }
    

    if ( isCallForHelp(argv[1]) )
    {
        printHelp();
        return 1;
    }

    if ( parseArgs(argc, argv, &gp, &pep, &elfp, &force, file_name) != 0 )
        return 0;

    errno = 0;
    gp.fp = fopen(file_name, "rb");
    errsv = errno;
    if ( gp.fp == NULL)
    {
        printf("ERROR (0x%x): Could not open file: \"%s\"\n", errsv, file_name);
        return -1;
    }

    gp.file_size = getSizeFP(gp.fp);
    if ( gp.file_size == 0 )
    {
        printf("ERROR: File \"%s\" is zero.\n", file_name);
        s = -2;
        goto exit;
    }

    sanitizeArgs(&gp);

    DPrint("file_name: %s\n", file_name);
    DPrint("abs_file_offset: 0x%zx\n", gp.abs_file_offset);
    DPrint("abs_file_offset: 0x%zx\n", gp.abs_file_offset);
    DPrint("start_file_offset: 0x%zx\n", gp.start_file_offset);

    n = readFile(gp.fp, gp.abs_file_offset, BLOCKSIZE_LARGE, gp.block_large);
    if ( !n )
    {
        printf("Read failed.\n");
        s = 0;
        goto exit;
    }

    hd = (HeaderData*) malloc(sizeof(HeaderData));
    if ( hd == NULL )
    {
        printf("Malloc HeaderData failed.\n");
        s = -3;
        goto exit;
    }

    initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);

    parseHeader(force, hd, &gp, &pep, &elfp);
    printHeaderData(gp.info_level, hd, gp.block_large);

exit:
    freeHeaderData(hd);
    hd = NULL;
    if ( gp.fp != NULL )
        fclose(gp.fp);

    return s;
}

void printUsage()
{
#ifdef _WIN32
    char* pref = "";
#else
    char* pref = "./";
#endif
    printf("Usage: %s%s file/name [options]\n", pref, BIN_NAME);
    printf("Usage: %s%s [options] file/name\n", pref, BIN_NAME);
    printf("\nVersion: %s\n", BIN_VS);
    printf("Last changed: %s\n", BIN_DATE);
}

bool isCallForHelp(const char* arg1)
{
    return isArgOfType(arg1, "/h") || 
           isArgOfType(arg1, "/?");
}

void printHelp()
{
    printUsage();
    printf("\n"
        "Options:\n"
            " * -h Print this.\n"
            " * -s:size_t Start offset. Default = 0.\n"
            " * -i:uint8_t Level of output info. Default = 1 : minimal output. 2 : Extended output (print basic header).\n"
            " * -f:string Force a headertype to be parsed skipping magic value validity checks. Supported types are: pe.\n"
            " * -offs: show file offsets of the printed values (for -i 2 or XX only options).\n"
            " * PE only options:\n"
            "   * -dosh: Print DOS header.\n"
            "   * -coffh: Print COFF header.\n"
            "   * -opth: Print Optional header.\n"
            "   * -sech: Print Section headers.\n"
            "   * -exp: Print the Image Export Table (IMAGE_DIRECTORY_ENTRY_EXPORT).\n"
            "   * -imp: Print the Image Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT) dll names and info.\n"
            "   * -impx: Print the Image Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT) dll names, info and imported functions.\n"
            "   * -res: Print the Image Resource Table (IMAGE_DIRECTORY_ENTRY_RESOURCE).\n"
            "   * -dbg: Print the Debug Table (IMAGE_DIRECTORY_ENTRY_DEBUG).\n"
            "   * -dbgx: Print the Debug Table (IMAGE_DIRECTORY_ENTRY_DEBUG) (a bit more) extended.\n"
            //"   * -exc: Print the Exception Table (IMAGE_DIRECTORY_ENTRY_EXCEPTION).\n"
            "   * -crt: Print the Image Certificate Table (IMAGE_DIRECTORY_ENTRY_CERTIFICATE).\n"
            "   * -cod: Directory to save found certificates in (Needs -crt).\n"
            "   * -rel: Print the Image Base Relocation Table (IMAGE_DIRECTORY_ENTRY_BASE_RELOC).\n"
            "   * -tls: Print the Image TLS Table (IMAGE_DIRECTORY_ENTRY_TLS).\n"
            "   * -lcfg: Print the Image Load Config Table (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG).\n"
            "   * -bimp: Print the Image Bound Import Table (IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT).\n"
            "   * -dimp: Print the Image Delay Import Table (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) dll names and info..\n"
            "   * -dimpx: Print the Image Delay Import Table (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) dll names, info and imported functions.\n"
            " * ELF only options:\n"
            "   * -fileh: Print file header.\n"
            "   * -progh: Print program headers.\n"
            "   * -sech: Print section headers.\n"
            "   * -sym: Print symbol table (names only).\n"
            "   * -symx: Print symbol table with all info.\n"
            "   * -dym: Print dynamic symbol table (names only).\n"
            "   * -dymx: Print dynamic symbol table with all info.\n"
    );
    printf("\n");
    printf("Examples:\n");
    printf("$ ./%s path/to/a.file\n", BIN_NAME);
    printf("$ ./%s path/to/a.file -i 2\n", BIN_NAME);
    printf("$ ./%s path/to/a.file -s 0x100\n", BIN_NAME);
    printf("$ ./%s path/to/a.file -f pe\n", BIN_NAME);
}

int parseArgs(int argc, char** argv, PGlobalParams gp, PPEParams pep, PElfParams elfp, uint8_t* force, char* file_name)
{
    int start_i = 1;
    int end_i = argc;
    int i;
    int s = 0;
    char* arg = NULL;

    gp->info_level = INFO_LEVEL_BASIC;

    for ( i = start_i; i < end_i; i++ )
    {
        arg = argv[i];
        //if ( arg[0] != LIN_PARAM_IDENTIFIER &&  )
        //    break;

        if ( isArgOfType(arg, "-s") )
        {
            if ( hasValue("-s", i, end_i))
            {
                s = parseSizeT(argv[i + 1], &gp->abs_file_offset);
                if ( s != 0 )
                    gp->abs_file_offset = 0;
                gp->start_file_offset = gp->abs_file_offset;
                i++;
            }
        }
        else if ( isArgOfType(arg, "-i") )
        {
            if ( hasValue("-i", i, end_i))
            {
                gp->info_level = getInfoLevel(argv[i + 1]);
                i++;
            }
        }
        else if ( isArgOfType(arg, "-f") )
        {
            if ( hasValue("-f", i, end_i))
            {
                *force = getForceOption(argv[i + 1]);
                if ( *force == FORCE_NONE )
                {
                    header_info("INFO: Unknown force option \"%s\"\n", argv[i + 1]);
                }
                i++;
            }
        }
        else if ( isArgOfType(arg, "-offs") )
        {
            gp->info_show_offsets = 1;
        }
        else if ( isArgOfType(arg, "-dosh") )
        {
            pep->info_level |= INFO_LEVEL_PE_DOS_H;
        }
        else if ( isArgOfType(arg, "-coffh") )
        {
            pep->info_level |= INFO_LEVEL_PE_COFF_H;
        }
        else if ( isArgOfType(arg, "-opth") )
        {
            pep->info_level |= INFO_LEVEL_PE_OPT_H;
        }
        else if ( isArgOfType(arg, "-sech") )
        {
            pep->info_level |= INFO_LEVEL_PE_SEC_H;
            elfp->info_level |= INFO_LEVEL_ELF_SEC_H;
        }
        else if ( isArgOfType(arg, "-imp") )
        {
            pep->info_level |= INFO_LEVEL_PE_IMP;
        }
        else if ( isArgOfType(arg, "-impx") )
        {
            pep->info_level |= INFO_LEVEL_PE_IMP | INFO_LEVEL_PE_IMP_EX;
        }
        else if ( isArgOfType(arg, "-exp") )
        {
            pep->info_level |= INFO_LEVEL_PE_EXP;
        }
        else if ( isArgOfType(arg, "-expx") )
        {
            pep->info_level |= INFO_LEVEL_PE_EXP | INFO_LEVEL_PE_EXP_EX;
        }
        else if (isArgOfType(arg, "-res"))
        {
            pep->info_level |= INFO_LEVEL_PE_RES;
        }
        else if (isArgOfType(arg, "-dbg"))
        {
            pep->info_level |= INFO_LEVEL_PE_DBG;
        }
        else if (isArgOfType(arg, "-dbgx"))
        {
            pep->info_level |= INFO_LEVEL_PE_DBG | INFO_LEVEL_PE_DBG_EX;
        }
        //else if (isArgOfType(arg, "-exc"))
        //{
        //    pep->info_level |= INFO_LEVEL_PE_EXC;
        //}
        else if (isArgOfType(arg, "-tls"))
        {
            pep->info_level |= INFO_LEVEL_PE_TLS;
        }
        else if (isArgOfType(arg, "-rel"))
        {
            pep->info_level |= INFO_LEVEL_PE_REL;
        }
        else if ( isArgOfType(arg, "-crt") )
        {
            pep->info_level |= INFO_LEVEL_PE_CRT;
        }
        else if ( isArgOfType(arg, "-cod") )
        {
            if ( hasValue("-cod", i, end_i))
            {
                pep->certificate_directory = argv[i + 1];
                cropTrailingSlash((char*)pep->certificate_directory);
//				expandFilePath(argv[i+i], certificate_directory);
                i++;
            }
        }
        else if (isArgOfType(arg, "-dimp"))
        {
            pep->info_level |= INFO_LEVEL_PE_DIMP;
        }
        else if (isArgOfType(arg, "-dimpx"))
        {
            pep->info_level |= INFO_LEVEL_PE_DIMP | INFO_LEVEL_PE_DIMP_EX;
        }
        else if (isArgOfType(arg, "-bimp"))
        {
            pep->info_level |= INFO_LEVEL_PE_BIMP;
        }
        else if (isArgOfType(arg, "-lcfg"))
        {
            pep->info_level |= INFO_LEVEL_PE_LCFG;
        }
        else if (isArgOfType(arg, "-fileh"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_FILE_H;
        }
        else if (isArgOfType(arg, "-progh"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_PROG_H;
        }
        else if (isArgOfType(arg, "-sym"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_SYM_TAB;
        }
        else if (isArgOfType(arg, "-symx"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_SYM_TAB | INFO_LEVEL_ELF_SYM_TAB_EX;
        }
        else if (isArgOfType(arg, "-dym"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_DYN_SYM_TAB;
        }
        else if (isArgOfType(arg, "-dymx"))
        {
            elfp->info_level |= INFO_LEVEL_ELF_DYN_SYM_TAB | INFO_LEVEL_ELF_DYN_SYM_TAB_EX;
        }
        else if ( arg[0] != '-' )
        {
            expandFilePath(arg, file_name);
        }
        else
        {
            header_info("INFO: Unknown Option \"%s\"\n", arg);
        }
    }


    // maybe move to pe/elf parsing
    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
    {
        pep->info_level |= INFO_LEVEL_PE_EXTENDED;
        elfp->info_level |= INFO_LEVEL_ELF_EXTENDED;
    }
    if ( pep->info_level + elfp->info_level > 0 && gp->info_level < INFO_LEVEL_EXTENDED )
    {
        gp->info_level = INFO_LEVEL_EXTENDED;
    }

    if ( file_name[0] == 0 )
    {
        header_info("ERROR: No file set!\n");
        s = -1;
    }
    else if ( !fileExists(file_name) )
    {
        header_info("ERROR: File not found!\n");
        s = -1;
    }

    if ( pep->certificate_directory!=NULL )
    {
        if ( strnlen(pep->certificate_directory, PATH_MAX) >= PATH_MAX-10 )
        {
            header_info("ERROR: Certificate output directory path \"%.*s\" too long!\n", PATH_MAX, pep->certificate_directory);
            pep->certificate_directory = NULL;
            s = -2;
        }
        if ( !dirExists(pep->certificate_directory) )
        {
            header_info("ERROR: Certificate output directory \"%.*s\" does not exist!\n", PATH_MAX, pep->certificate_directory);
            pep->certificate_directory = NULL;
            s = -3;
        }
    }

    return s;
}

void sanitizeArgs(PGlobalParams gp)
{
    if ( gp->abs_file_offset + 16 > gp->file_size )
    {
        header_info("INFO: filesize (0x%zx) is too small for a start offset of 0x%zx!\nSetting to 0!\n",
            gp->file_size, gp->abs_file_offset);
        gp->abs_file_offset = 0;
        gp->start_file_offset = gp->abs_file_offset;
    }
}

uint8_t getForceOption(const char* arg)
{
    if ( strncmp(arg, FORCE_PE_STR, 3) == 0 )
        return FORCE_PE;

    return FORCE_NONE;
}

uint8_t isArgOfType(const char* arg, char* type)
{
    size_t i;
    size_t type_ln;
    if ( arg[0] != LIN_PARAM_IDENTIFIER && arg[0] != WIN_PARAM_IDENTIFIER )
        return 0;

    type_ln = strlen(type);

    for ( i = 1; i < type_ln; i++ )
    {
        if ( arg[i] != type[i] )
            return 0;
    }
    return arg[i] == 0;
}

uint8_t hasValue(char* type, int i, int end_i)
{
    if ( i >= end_i - 1 )
    {
        header_info("INFO: Arg \"%s\" has no value! Skipped!\n", type);
        return 0;
    }

    return 1;
}

uint8_t getInfoLevel(char* arg)
{
    uint8_t level;

    char* endptr;
    level = (uint8_t)strtol(arg, &endptr, 10);

    if ( endptr == arg )
    {
        header_info("INFO: %s could not be converted to a number: Not a number!\nSetting to 1!\n", arg);
        level = INFO_LEVEL_BASIC;
    }

    if ( level > INFO_LEVEL_EXTENDED || level == INFO_LEVEL_NONE )
        level = INFO_LEVEL_BASIC;

    return level;
}

void printHeaderData(uint8_t level, PHeaderData hd, unsigned char* block)
{
    int i = 0;

    if ( level == INFO_LEVEL_BASIC )
    {
        printHeaderData1(hd);
    }
    else if ( level >= INFO_LEVEL_EXTENDED )
    {
        if ( hd->headertype == HEADER_TYPE_NONE )
        {
            printf("unsupported header:\n");
            for ( i = 0; i < MIN_FILE_SIZE; i++ )
            {
                printf("%02x|", block[i]);
            }
            printf("\n");
            for ( i = 0; i < MIN_FILE_SIZE; i++ )
            {
                printf("%c", block[i]);
            }
            printf("\n");
        }
    }
}

void printHeaderData1(PHeaderData hd)
{
    size_t i;

    printf("\nHeaderData:\n");
    printf("coderegions:\n");
    for ( i = 0; i < hd->code_regions_size; i++ )
    {
        printf(" (%zu) %s: ( 0x%016"PRIx64" - 0x%016"PRIx64" )\n",
               i + 1, hd->code_regions[i].name, hd->code_regions[i].start, hd->code_regions[i].end);
    }
    printf("headertype: %s (%d)\n", getHeaderDataHeaderType(hd->headertype), hd->h_bitness);
    printf("bitness: %d-bit\n", hd->i_bitness);
    printf("endian: %s\n", getHeaderDataEndianType(hd->endian));
    printf("CPU_arch: %s\n", getHeaderDataArchitecture(hd->CPU_arch));
    printf("Machine: %s\n", hd->Machine);
    printf("\n");
}
