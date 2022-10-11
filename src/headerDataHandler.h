#ifndef HEADER_PARSER_HEADER_DATA_HANDLER_H
#define HEADER_PARSER_HEADER_DATA_HANDLER_H

#include <errno.h>

#include "exp.h"
#include "HeaderData.h"

//#ifdef __cplusplus
//extern "C"{
//#endif
//void freeHeaderData(HeaderData* hd);
//#ifdef __cplusplus
//}
//#endif
static void freeInnerHeaderData(HeaderData* hd);
int initHeaderData(HeaderData* header_data, size_t code_regions_capacity);
static uint8_t resizeHeaderDataCodeRegions(HeaderData* header_data);
static void addCodeRegionDataToHeaderData(CodeRegionData* data, HeaderData* header_data);

int initHeaderData(HeaderData* header_data, size_t code_regions_capacity)
{
    memset(header_data, 0, sizeof(HeaderData));
    
    header_data->code_regions_capacity = code_regions_capacity;
    header_data->code_regions = (CodeRegionData*) calloc(1, sizeof(CodeRegionData)*header_data->code_regions_capacity);
    if ( !header_data->code_regions )
        return -1;
    header_data->Machine = MACHINE_NONE;

    return 0;
}

HP_API
void freeHeaderData(HeaderData* hd)
{
    if ( hd == NULL )
        return;

    freeInnerHeaderData(hd);
    free(hd);
}

void freeInnerHeaderData(HeaderData* hd)
{
    size_t i;

    if ( hd == NULL )
        return;

    for ( i = 0; i < hd->code_regions_size; i++ )
    {
        if ( hd->code_regions[i].name )
            free(hd->code_regions[i].name);
    }

    free(hd->code_regions);
    hd->code_regions = NULL;

    hd->code_regions_capacity = 0;
    hd->code_regions_size = 0;

    // java allocates machine string
    if ( hd->headertype == HEADER_TYPE_JAVA_CLASS )
        free((char*)hd->Machine);
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