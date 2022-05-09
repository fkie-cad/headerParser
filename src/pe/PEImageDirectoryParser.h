#ifndef HEADER_PARSER_PE_IMAGE_DIRECTORY_PARSER_H
#define HEADER_PARSER_PE_IMAGE_DIRECTORY_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>




typedef struct LoadConfigTableOffsets {
    size_t seh;
    size_t fun;
    size_t iat;
    size_t jmp;
    size_t ehc;
} LoadConfigTableOffsets, *PLoadConfigTableOffsets;

#include "../utils/fifo/Fifo.h"
#include "../exp.h"
#include "PEHeaderPrinter.h"
#include "PEHeader.h"



size_t PE_getDataDirectoryEntryFileOffset(
    PEDataDirectory* data_directory,
    enum ImageDirectoryEntries entry_id,
    uint16_t nr_of_sections,
    const char* label,
    SVAS* svas
);

size_t PE_Rva2Foa(
    uint32_t va, 
    SVAS* svas, 
    uint16_t svas_size
);





#include "idp/PEImageBaseRelocationTable.h"
#include "idp/PEImageDebugTable.h"
#include "idp/PEImageExportTable.h"
#include "idp/PEImageImportTable.h"
#include "idp/PEImageDelayImportTable.h"
#include "idp/PEImageBoundImportTable.h"
#include "idp/PEImageLoadConfigTable.h"
#include "idp/PEImageRessourceTable.h"
#include "idp/PEImageTLSTable.h"




size_t PE_getDataDirectoryEntryFileOffset(PEDataDirectory* data_directory,
                                            enum ImageDirectoryEntries entry_id,
                                            uint16_t nr_of_sections,
                                            const char* label,
                                            SVAS* svas)
{
    PEDataDirectory* table = &data_directory[entry_id]; // 32 + 64
    uint32_t vaddr = table->VirtualAddress;
    uint32_t vsize = table->Size;
    size_t table_fo;

    if ( vsize == 0 || vaddr == 0 )
    {
        printf("No %s Table!\n\n", label);
        return 0;
    }
    // end get table entry

    // get table rva offset
    table_fo = PE_Rva2Foa(vaddr, svas, nr_of_sections);
    if ( table_fo == (size_t)-1 )
        return 0;

    return table_fo;
}




/**
 * Convert RVA (relative virtual address) to an in file offset.
 * Since importDirectory.RVA (==va), lives in the .section_header section,
 * importDirectory.RVA - section_header.VA gives us the offset of the import table relative to the start of the .section_header section
 *
 * @param va uint32_t the virtual address (offset)
 * @param svas SVAS* Section Virtual Addresses
 * @param svas_size uint16_t number of sections, size of svas
 * @return size_t the (absolute) file offset or 0
 */
size_t PE_Rva2Foa(uint32_t va, SVAS* svas, uint16_t svas_size)
{
    uint16_t i;
    SVAS* sh_vas = NULL;

    for (i = 0; i < svas_size; i++)
    {
        sh_vas = &svas[i];

        if ((va >= sh_vas->VirtualAddress) && (va <= sh_vas->VirtualAddress + sh_vas->SizeOfRawData))
        {
            return (size_t)va + sh_vas->PointerToRawData - sh_vas->VirtualAddress;
        }
    }
    return 0;
}

#endif
