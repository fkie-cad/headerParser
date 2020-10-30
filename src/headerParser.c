#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define VERBOSE_MODE 1

#ifndef LIB_MODE
#define LIB_MODE (0)
#endif

#include "Globals.h"
#include "utils/Helper.h"
#include "utils/common_fileio.h"
#include "parser.h"

#define BINARYNAME ("headerParser")

static void printUsage();
static void printHelp();
static uint8_t parseArgs(int argc, char** argv, PGlobalParams gp, PPEParams pep, uint8_t* force);
static void sanitizeArgs(PGlobalParams gp);
static uint8_t isArgOfType(char* arg, char* type);
static uint8_t hasValue(char* type, int i, int end_i);
static uint8_t getInfoLevel(char* arg);
static void printHeaderData(uint8_t, PHeaderData hd, unsigned char* block);
static void printHeaderData1(PHeaderData hd);
static uint8_t getForceOption(const char* arg);

const char* vs = "1.9.0";
const char* last_changed = "30.10.2020";



int main(int argc, char** argv)
{
	uint32_t n = 0;

	HeaderData* hd = NULL;
	uint8_t force = FORCE_NONE;

	GlobalParams gp;
    memset(&gp, 0, sizeof(GlobalParams));

	PEParams pep;
	memset(&pep, 0, sizeof(PEParams));

	int s = 0;

	if ( argc < 2 )
	{
		printUsage();
		return 0;
	}

	if ( parseArgs(argc, argv, &gp, &pep, &force) != 0 )
		return 0;

	gp.file_size = getSize(gp.file_name);
	if ( gp.file_size == 0 )
	{
		printf("ERROR: File \"%s\" does not exist.\n", gp.file_name);
		s = 0;
		goto clean;
	}
	sanitizeArgs(&gp);

	debug_info("file_name: %s\n", gp.file_name);
	debug_info("abs_file_offset: 0x%lx\n", gp.abs_file_offset);
	debug_info("start_file_offset: 0x%lx\n", gp.start_file_offset);

//	n = readLargeBlock(gp.file_name, gp.abs_file_offset);
	n = readCustomBlock(gp.file_name, gp.abs_file_offset, BLOCKSIZE_LARGE, gp.block_large);
	if ( !n )
	{
		printf("Read failed.\n");
		s = 0;
		goto clean;
	}

	hd = (HeaderData*) malloc(sizeof(HeaderData));
	if ( hd == NULL )
	{
		printf("Malloc failed.\n");
		s = 3;
		goto clean;
	}

	initHeaderData(hd, DEFAULT_CODE_REGION_CAPACITY);

	parseHeader(force, hd, &gp, &pep);
	printHeaderData(gp.info_level, hd, gp.block_large);

	clean:
	freeHeaderData(hd);
	hd = NULL;

	return s;
}

void printUsage()
{
	printf("Usage: ./%s file/name [options]\n", BINARYNAME);
	printf("Usage: ./%s [options] file/name\n", BINARYNAME);
	printf("\nVersion: %s\n", vs);
	printf("Last changed: %s\n", last_changed);
}

void printHelp()
{
	printUsage();
	printf("\n"
			" * -h Print this.\n"
			" * -s:uint64_t Start offset. Default = 0.\n"
			" * -i:uint8_t Level of output info. Default = 1 : minimal output. 2 : Full output. 3 : Full output with offsets.\n"
			" * -f:string Force a headertype to be parsed skipping magic value validity checks. Supported types are: pe.\n"
			" * PE only options:\n"
			"   * -iimp: Print the Image Import Table (IMAGE_DIRECTORY_ENTRY_IMPORT) (Currently needs -i > 1).\n"
			"   * -iexp: Print the Image Export Table (IMAGE_DIRECTORY_ENTRY_EXPORT) (Currently needs -i > 1).\n"
			"   * -ires: Print the Image Resource Table (IMAGE_DIRECTORY_ENTRY_RESOURCE) (Currently needs -i > 1).\n"
			"   * -icrt: Print the Image Certificate Table (IMAGE_DIRECTORY_ENTRY_CERTIFICATE) (Currently needs -i > 1).\n"
			"   * -cod: Directory to save found certificates in (Needs -icrt).\n"
	);
	printf("\n");
	printf("Examples:\n");
	printf("$ ./%s path/to/a.file\n", BINARYNAME);
	printf("$ ./%s path/to/a.file -i 2\n", BINARYNAME);
	printf("$ ./%s path/to/a.file -s 0x100\n", BINARYNAME);
	printf("$ ./%s path/to/a.file -f pe\n", BINARYNAME);
}

uint8_t parseArgs(int argc, char** argv, PGlobalParams gp, PPEParams pep, uint8_t* force)
{
	int start_i = 1;
	int end_i = argc - 1;
	int i;
	int s;

	if ( isArgOfType(argv[1], "-h"))
	{
		printHelp();
		return 1;
	}

	gp->info_level = INFO_LEVEL_BASIC;

	// if first argument is the input file
	if ( argv[1][0] != '-' )
	{
		expandFilePath(argv[1], gp->file_name);
		start_i = 2;
		end_i = argc;
	}

	for ( i = start_i; i < end_i; i++ )
	{
		if ( argv[i][0] != '-' )
			break;

		if ( isArgOfType(argv[i], "-s"))
		{
			if ( hasValue("-s", i, end_i))
			{
				s = parseUint64(argv[i + 1], &gp->abs_file_offset);
				if ( !s )
					gp->abs_file_offset = 0;
				gp->start_file_offset = gp->abs_file_offset;
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-i"))
		{
			if ( hasValue("-i", i, end_i))
			{
				gp->info_level = getInfoLevel(argv[i + 1]);
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-f") )
		{
			if ( hasValue("-f", i, end_i))
			{
				*force = getForceOption(argv[i + 1]);
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-iimp") )
		{
			pep->info_level_iimp = true;
		}
		else if ( isArgOfType(argv[i], "-iexp") )
		{
            pep->info_level_iexp = true;
		}
		else if ( isArgOfType(argv[i], "-ires") )
		{
            pep->info_level_ires = true;
		}
		else if ( isArgOfType(argv[i], "-icrt") )
		{
            pep->info_level_icrt = true;
		}
		else if ( isArgOfType(argv[i], "-cod") )
		{
			if ( hasValue("-cod", i, end_i))
			{
                pep->certificate_directory = argv[i + 1];
//				expandFilePath(argv[i+i], certificate_directory);
				i++;
			}
		}
		else
		{
			header_info("INFO: Unknown arg type \"%s\"\n", argv[i]);
		}
	}

	if ( start_i == 1 )
		expandFilePath(argv[i], gp->file_name);

	if ( gp->info_level < 2 )
	{
        pep->info_level_iimp = false;
        pep->info_level_iexp = false;
        pep->info_level_ires = false;
        pep->info_level_icrt = false;
	}

	if ( pep->certificate_directory!=NULL )
    {
        if ( strnlen(pep->certificate_directory, PATH_MAX) >= PATH_MAX-10 )
        {
            header_info("ERROR: Certificate output directory path \"%.*s\" too long!\n", PATH_MAX, pep->certificate_directory);
            pep->certificate_directory = NULL;
            return -1;
        }
        if ( !dirExists(pep->certificate_directory) )
        {
            header_info("ERROR: Certificate output directory \"%.*s\" does not exist!\n", PATH_MAX, pep->certificate_directory);
            pep->certificate_directory = NULL;
            return -1;
        }
    }

	return 0;
}

void sanitizeArgs(PGlobalParams gp)
{
	if ( gp->abs_file_offset + 16 > gp->file_size )
	{
#if defined(_WIN32)
		header_info("INFO: file (%zu) is too small for a start offset of %llu!\nSetting to 0!\n",
					gp->file_size, gp->abs_file_offset);
#else
		header_info("INFO: file (%zu) is too small for a start offset of %lu!\nSetting to 0!\n",
					gp->file_size, gp->abs_file_offset);
#endif
		gp->abs_file_offset = 0;
		gp->start_file_offset = gp->abs_file_offset;
	}
}

uint8_t getForceOption(const char* arg)
{
	if ( strncmp(arg, FORCE_PE_STR, 2) == 0 )
		return FORCE_PE;

	return FORCE_NONE;
}

uint8_t isArgOfType(char* arg, char* type)
{
	size_t type_ln;

	type_ln = strlen(type);

	return strlen(arg) == type_ln && strncmp(arg, type, type_ln) == 0;
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
	level = strtol(arg, &endptr, 10);

	if ( endptr == arg )
	{
		header_info("INFO: %s could not be converted to a number: Not a number!\nSetting to 1!\n", arg);
		level = INFO_LEVEL_BASIC;
	}

	if ( level > INFO_LEVEL_FULL_WITH_OFFSETS || level == INFO_LEVEL_NONE )
		level = INFO_LEVEL_BASIC;

	return level;
}

void printHeaderData(uint8_t level, PHeaderData hd, unsigned char* block)
{
	int i = 0;

	if ( level == INFO_LEVEL_BASIC )
		printHeaderData1(hd);
	else if ( level >= INFO_LEVEL_FULL )
	{
		if ( hd->headertype == HEADER_TYPE_NONE )
		{
			printf("unsupported header:\n");
			for ( i = 0; i < 16; i++ )
			{
				printf("%02x|", block[i]);
			}
			printf("\n");
			for ( i = 0; i < 16; i++ )
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
		printf(" (%lu) %s: ( 0x%016lx - 0x%016lx )\n",
			   i + 1, hd->code_regions[i].name, hd->code_regions[i].start, hd->code_regions[i].end);
	}
	printf("headertype: %s\n", header_type_names[hd->headertype]);
	printf("bitness: %d-bit\n", hd->bitness);
	printf("endian: %s\n", endian_type_names[hd->endian]);
	printf("CPU_arch: %s\n", architecture_names[hd->CPU_arch]);
	printf("Machine: %s\n", hd->Machine);
	printf("\n");
}
