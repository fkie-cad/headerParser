#ifndef HEADER_PARSER_HEADER_DATA_HANDLER_H
#define HEADER_PARSER_HEADER_DATA_HANDLER_H

#include <errno.h>

#include "HeaderData.h"

#ifdef __cplusplus
extern "C"{
#endif
void freeHeaderData(HeaderData* header_data);
#ifdef __cplusplus
}
#endif
void freeInnerHeaderData(HeaderData* header_data);
int initHeaderData(HeaderData* header_data, size_t code_regions_capacity);
static uint8_t resizeHeaderDataCodeRegions(HeaderData* header_data);
static void addCodeRegionDataToHeaderData(CodeRegionData* data, HeaderData* header_data);

int initHeaderData(HeaderData* header_data, size_t code_regions_capacity)
{
	header_data->code_regions_capacity = code_regions_capacity;
	header_data->code_regions = (CodeRegionData*) calloc(1, sizeof(CodeRegionData)*header_data->code_regions_capacity);
	if ( !header_data->code_regions )
		return -1;
	header_data->code_regions_size = 0;
	header_data->headertype = 0;
	header_data->bitness = 0;
	header_data->endian = 0;
	header_data->CPU_arch = 0;
	header_data->Machine = MACHINE_NONE;

	return 0;
}

void freeHeaderData(HeaderData* header_data)
{
	freeInnerHeaderData(header_data);

	free(header_data);
}

void freeInnerHeaderData(HeaderData* header_data)
{
	size_t i;

	if ( header_data == NULL )
		return;

	for ( i = 0; i < header_data->code_regions_size; i++ )
		free(header_data->code_regions[i].name);

	free(header_data->code_regions);
	header_data->code_regions = NULL;

	header_data->code_regions_capacity = 0;
	header_data->code_regions_size = 0;
}

void addCodeRegionDataToHeaderData(CodeRegionData* data, HeaderData* header_data)
{
	if ( header_data->code_regions_size >= header_data->code_regions_capacity )
	{
		if (!resizeHeaderDataCodeRegions(header_data))
			return;
	}

	header_data->code_regions[header_data->code_regions_size] = *data;
	header_data->code_regions_size++;
}

uint8_t resizeHeaderDataCodeRegions(HeaderData* header_data)
{
	header_data->code_regions_capacity *= 2;
	errno = 0;
	CodeRegionData* temp = (CodeRegionData*)realloc(header_data->code_regions, sizeof(CodeRegionData) * header_data->code_regions_capacity);
	if (!temp)
	{
		int errsv = errno;
		printf("ERROR (0x%x): Reallocating Coderegions failed!\n", errsv);
		return 0;
	}
	header_data->code_regions = temp;
	return 1;
}

#endif