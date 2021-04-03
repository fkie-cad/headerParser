#ifndef HEADER_PARSER_PE_HEADER_DATA_H
#define HEADER_PARSER_PE_HEADER_DATA_H

#include "pe/PEHeader.h"

typedef struct PEHeaderData
{
    PEImageDosHeader* image_dos_header;
    PECoffFileHeader* coff_header;
    PE64OptHeader* opt_header;
    HeaderData* hd;
    StringTable st;
    SVAS* svas;
} PEHeaderData;

#endif
