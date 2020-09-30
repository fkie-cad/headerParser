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
#include "utils/blockio.h"
#include "parser.h"

#define BINARYNAME ("headerParser")

static void printUsage();
static void printHelp();
static uint8_t parseArgs(int argc, char** argv);
static void sanitizeArgs();
static uint8_t isArgOfType(char* arg, char* type);
static uint8_t hasValue(char* type, int i, int end_i);
static uint8_t getInfoLevel(char* arg);
static void clean(void);
static void printHeaderData(uint8_t);
static void printHeaderData1();
static uint8_t getForceOption(const char* arg);

const char* vs = "1.8.3";
const char* last_changed = "30.04.2020";
uint8_t force = FORCE_NONE;



int main(int argc, char** argv)
{
	uint32_t n = 0;
	HeaderData* hd = NULL;

	atexit(clean);

	if ( argc < 2 )
	{
		printUsage();
		return 0;
	}

	if ( parseArgs(argc, argv) != 0 )
		return 0;

	file_size = getSize(file_name);
	if ( file_size == 0 )
	{
		printf("ERROR: File \"%s\" does not exist.\n", file_name);
		return 0;
	}
	sanitizeArgs();

	debug_info("file_name: %s\n", file_name);
	debug_info("abs_file_offset: 0x%lx\n", abs_file_offset);
	debug_info("start_file_offset: 0x%lx\n", start_file_offset);

	n = readLargeBlock(file_name, abs_file_offset);
	if ( !n )
	{
		printf("Read failed.\n");
		return 0;
	}

	hd = (HeaderData*) malloc(sizeof(HeaderData));
	if ( hd == NULL )
	{
		printf("Malloc failed.\n");
		return -3;
	}
	HD = hd;

	initHeaderData(HD, DEFAULT_CODE_REGION_CAPACITY);

	parseHeader(force);
	printHeaderData(info_level);

	freeHeaderData(hd);
	HD = NULL;

	return 0;
}

void clean(void)
{
	freeHeaderData(HD);
	HD = NULL;
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
	printf(
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
	printf("Example: ./%s path/to/a.file\n", BINARYNAME);
	printf("Example: ./%s path/to/a.file -i 2\n", BINARYNAME);
	printf("Example: ./%s path/to/a.file -s 0x100\n", BINARYNAME);
	printf("Example: ./%s path/to/a.file -f pe\n", BINARYNAME);
}

uint8_t parseArgs(int argc, char** argv)
{
	int start_i = 1;
	int end_i = argc - 1;
	int i;

	if ( isArgOfType(argv[1], "-h"))
	{
		printHelp();
		return 1;
	}

	info_level = INFO_LEVEL_BASIC;

	// if first argument is the input file
	if ( argv[1][0] != '-' )
	{
		expandFilePath(argv[1], file_name);
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
				abs_file_offset = parseUint64(argv[i + 1]);
				start_file_offset = abs_file_offset;
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-i"))
		{
			if ( hasValue("-i", i, end_i))
			{
				info_level = getInfoLevel(argv[i + 1]);
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-f") )
		{
			if ( hasValue("-f", i, end_i))
			{
				force = getForceOption(argv[i + 1]);
				i++;
			}
		}
		else if ( isArgOfType(argv[i], "-iimp") )
		{
			info_level_iimp = true;
		}
		else if ( isArgOfType(argv[i], "-iexp") )
		{
			info_level_iexp = true;
		}
		else if ( isArgOfType(argv[i], "-ires") )
		{
			info_level_ires = true;
		}
		else if ( isArgOfType(argv[i], "-icrt") )
		{
			info_level_icrt = true;
		}
		else if ( isArgOfType(argv[i], "-cod") )
		{
			if ( hasValue("-cod", i, end_i))
			{
				certificate_directory = argv[i + 1];
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
		expandFilePath(argv[i], file_name);

	if ( info_level < 2 )
	{
		info_level_iimp = false;
		info_level_iexp = false;
		info_level_ires = false;
		info_level_icrt = false;
	}

	if ( certificate_directory!=NULL && !dirExists(certificate_directory) )
	{
		header_info("ERROR: Certificate output directory \"%.*s\" does not exist!\n", PATH_MAX, certificate_directory);
		certificate_directory = NULL;
		return -1;
	}
	
	return 0;
}

void sanitizeArgs()
{
	if ( abs_file_offset + 16 > file_size )
	{
		header_info("INFO: file (%u) is too small for a start offset of %lu!\nSetting to 0!\n",
			   file_size, abs_file_offset);
		abs_file_offset = 0;
		start_file_offset = abs_file_offset;
	}
}

uint8_t getForceOption(const char* arg)
{
	if ( strncmp(arg, FORCE_PE_STR, 4) == 0 )
		return FORCE_PE;

	return FORCE_NONE;
}

uint8_t isArgOfType(char* arg, char* type)
{
	int type_ln;

	type_ln = strlen(type);

	return strnlen(arg, 10) == type_ln && strncmp(arg, type, type_ln) == 0;
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

	if ( level > INFO_LEVEL_FULL_WITH_OFFSETS || level == INFO_LEVEL_NONE ) level = INFO_LEVEL_BASIC;

	return level;
}

void printHeaderData(uint8_t level)
{
	int i = 0;

	if ( level == INFO_LEVEL_BASIC )
		printHeaderData1();
	else if ( level >= INFO_LEVEL_FULL )
	{
		if ( HD->headertype == HEADER_TYPE_NONE )
		{
			printf("unsupported header:\n");
			for ( i = 0; i < 16; i++ )
			{
				printf("%02x|", block_large[i]);
			}
			printf("\n");
			for ( i = 0; i < 16; i++ )
			{
				printf("%c", block_large[i]);
			}
			printf("\n");
		}
	}
}

void printHeaderData1()
{
	size_t i;

	printf("\nHeaderData:\n");
	printf("coderegions:\n");
	for ( i = 0; i < HD->code_regions_size; i++ )
	{
		printf(" (%lu) %s: ( 0x%016lx - 0x%016lx )\n",
			   i + 1, HD->code_regions[i].name, HD->code_regions[i].start, HD->code_regions[i].end);
	}
	printf("headertype: %s\n", header_type_names[HD->headertype]);
	printf("bitness: %d-bit\n", HD->bitness);
	printf("endian: %s\n", endian_type_names[HD->endian]);
	printf("CPU_arch: %s\n", architecture_names[HD->CPU_arch]);
	printf("Machine: %s\n", HD->Machine);
	printf("\n");
}
