#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "../src/HeaderData.h"
#include "../src/stringPool.h"
#include "../src/utils/Converter.h"

#include "../src/headerParserLibPE.h"

int main(int argc, char** argv)
{
	uint32_t i;
	const char* src = NULL;
	uint8_t force = FORCE_NONE;
	uint64_t offset = 0;

	if (argc < 2)
	{
		printf("Usage: %s [-o offset] [-f] filename1 filename2 ... \n", argv[0]);
		return -1;
	}

	printf("argc: %d\n", argc);
	printf("offset: %lu\n", offset);
	printf("force: %d\n", force);
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
//		runParser(src, offset, force);
//		checkGuessed(src);
	}

	return 0;
}