#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#pragma warning( disable : 4100 4101 )
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../src/HeaderData.h"
#include "../src/stringPool.h"

#include "../src/headerParserLib.h"
#include "../src/utils/common_fileio.h"

#ifdef _WIN32
	#ifdef _DEBUG
		#ifdef _WIN64
			#pragma comment(lib, "..\\build\\debug\\64\\HeaderParser.lib")
		#else
			#pragma comment(lib, "..\\build\\debug\\32\\HeaderParser.lib")
		#endif
	#else
		#ifdef _WIN64
			#pragma comment(lib, "..\\build\\64\\HeaderParser.lib")
		#else
			#pragma comment(lib, "..\\build\\32\\HeaderParser.lib")
		#endif
	#endif
#endif

void runParser(const char* src, size_t offset, uint8_t force);
HeaderData* getPeGuessedHeaderData(const char* file_src);
void checkGuessed(const char* file_src);
void printHeaderData(HeaderData* data);

int main(int argc, char** argv)
{
	int i;
	const char* src = NULL;
	uint8_t force = FORCE_NONE;
	size_t offset = 0;

	if (argc < 2)
	{
		printf("Usage: %s [-o offset] [-f] filename1 filename2 ... \n", argv[0]);
		return -1;
	}

	printf("argc: %d\n", argc);
	printf("offset: 0x%zx\n", offset);
	printf("force: %u\n", force);
	printf("\n");

	for ( i = 1; i < argc; i++ )
	{
		if ( argv[i][0] == '-' )
		{
			if ( strnlen(argv[i], 10) < 2 )
				continue;

			if ( argc <= i+1 )
				break;

			if ( argv[i][1] == 'o' )
			{
				offset = strtoul(argv[i + 1], NULL, 10);
				i++;
			}
			else if ( argv[i][1] == 'f' )
				force = FORCE_PE;

			continue;
		}

		src = argv[i];
		runParser(src, offset, force);
//		checkGuessed(src);
	}
//	if ( argc > 2 )
//		offset = parseUint64(argv[2]);
//	if ( argc > 3 )
//		force = argv[3];

	return 0;
}

void runParser(const char* src, size_t offset, uint8_t force)
{
	printf("=======runParser=======\n");
	printf("src: %s\n", src);
	printf("offset: 0x%zx\n", offset);
	printf("force: %u\n", force);
	printf("\n");
	HeaderData* data = getBasicHeaderParserInfo(src, offset, force);

	if ( data == NULL )
		return;

	printHeaderData(data);

	freeHeaderData(data);
	data = NULL;
}

void checkGuessed(const char* file_src)
{
	printf("=======checkGuessed=======\n");
	printf("src: %s\n", file_src);
	printf("\n");

	HeaderData* hpd = getPeGuessedHeaderData(file_src);

	if ( hpd != NULL )
	{
		printHeaderData(hpd);
		freeHeaderData(hpd);
	}
}

HeaderData* getPeGuessedHeaderData(const char* file_src)
{
	uint8_t force = FORCE_PE;

	HeaderData* hpd = getBasicHeaderParserInfo(file_src, 0, force);

	if ( hpd == NULL )
	{
		printf("HeaderData is NULL\n");
		return NULL;
	}

	// check for supported arch is the only possible validation for a guessed hpd
	if ( hpd->headertype != HEADER_TYPE_NONE )
		return hpd;
	else
	{
		freeHeaderData(hpd);
		return NULL;
	}
}

void printHeaderData(HeaderData* data)
{
	size_t i;
	printf("\nHeaderData:\n");
	printf("coderegions:\n");
	for ( i = 0; i < data->code_regions_size; i++ )
	{
		printf(" (%zu) %s: ( 0x%016zx - 0x%016zx )\n",
			   i+1, data->code_regions[i].name, data->code_regions[i].start, data->code_regions[i].end);
	}
	printf("headertype: %s\n", getHeaderDataHeaderType(data->headertype));
	printf("bitness: %d-bit\n", data->h_bitness);
	printf("endian: %s\n", endian_type_names[data->endian]);
	printf("CPU_arch: %s\n", getHeaderDataArchitecture(data->CPU_arch));
	printf("Machine: %s\n", data->Machine);
	printf("\n");
}
