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

HP_API
void PE_parseImageImportTable(PE64OptHeader* oh,
                              uint16_t nr_of_sections,
                              SVAS* svas,
                              uint8_t bitness,
                              size_t start_file_offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l,
                              uint8_t* block_s,
                              int extended);
void PE_fillImportDescriptor(PEImageImportDescriptor* id,
                             size_t* offset,
                             size_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             uint8_t* block_l);
int PE_fillThunkData(PEImageThunkData64* thunk_data,
                      size_t offset,
                      int bitness,
                      size_t start_file_offset,
                      size_t file_size,
                      FILE* fp);
int PE_fillImportByName(PEImageImportByName* ibn,
                         size_t offset,
                         FILE* fp,
                         uint8_t* block_s);
int PE_iterateThunkData(uint16_t nr_of_sections,
                        SVAS* svas,
                        uint8_t bitness,
                        size_t start_file_offset,
                        size_t file_size,
                        FILE* fp,
                        uint8_t* block_s,
                        size_t thunk_data_offset);

void PE_parseImageBoundImportTable(PE64OptHeader* oh,
                                   size_t start_file_offset,
                                   size_t* abs_file_offset,
                                   size_t file_size,
                                   FILE* fp,
                                   uint8_t* block_l,
                                   uint8_t* block_s);
void PE_fillBoundImportDescriptor(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid,
                                 size_t* offset,
                                 size_t* abs_file_offset,
                                 size_t file_size,
                                 FILE* fp,
                                 uint8_t* block_l);
void PE_fillBoundForwarderRef(PE_IMAGE_BOUND_FORWARDER_REF* bfr,
                              size_t* offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l);

void PE_parseImageExportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas
);
int PE_fillImageExportDirectory(
    PE_IMAGE_EXPORT_DIRECTORY* ied,
    size_t offset,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s
);

void PE_parseImageLoadConfigTable(PE64OptHeader* oh,
                                 uint16_t nr_of_sections,
                                 SVAS* svas,
                                 uint8_t bitness,
                                 size_t start_file_offset,
                                 size_t* abs_file_offset,
                                 size_t file_size,
                                 FILE* fp,
                                 uint8_t* block_s);
int PE_fillImageLoadConfigDirectory(PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
                                    uint8_t bitness,
                                    size_t offset,
                                    size_t start_file_offset,
                                    size_t file_size,
                                    FILE* fp,
                                    uint8_t* block_s);

void PE_parseImageResourceTable(PE64OptHeader* oh,
                                uint16_t nr_of_sections,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s,
                                SVAS* svas);
int PE_fillImageResourceDirectory(PE_IMAGE_RESOURCE_DIRECTORY* rd,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s);
int PE_recurseImageResourceDirectory(
    size_t offset,
    size_t table_fo,
    uint16_t nr_of_named_entries,
    uint16_t nr_of_id_entries,
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
);
int PE_parseResourceDirectoryEntry(
    uint16_t id, 
    size_t offset, 
    size_t table_fo, 
    uint16_t nr_of_entries, 
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
);
//int PE_iterateImageResourceDirectory(size_t offset,size_t table_fo,uint16_t nr_of_named_entries,uint16_t nr_of_id_entries,uint16_t level,size_t start_file_offset,size_t file_size,FILE* fp,uint8_t* block_s);
//int PE_parseResourceDirectoryEntryI(uint16_t id,size_t offset,size_t table_fo,uint16_t nr_of_entries,uint16_t level,size_t start_file_offset,size_t file_size,FILE* fp,uint8_t* block_s, PFifo fifo);
int PE_fillImageResourceDirectoryEntry(PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                       size_t offset,
                                       size_t table_fo,
                                       size_t start_file_offset,
                                       size_t file_size,
                                       FILE* fp,
                                       uint8_t* block_s);
int PE_fillImageResourceDataEntry(PE_IMAGE_RESOURCE_DATA_ENTRY* de,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s);

void PE_parseImageDelayImportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    int extended
);
void PE_fillDelayImportDescriptor(PeImageDelayLoadDescriptor* id,
                                  size_t* offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_l);

size_t PE_getDataDirectoryEntryFileOffset(PEDataDirectory* data_directory,
                                            enum ImageDirectoryEntries entry_id,
                                            uint16_t nr_of_sections,
                                            const char* label,
                                            SVAS* svas);

void PE_parseImageTLSTable(PE64OptHeader* oh,
                           uint16_t nr_of_sections,
                           SVAS* svas,
                           uint8_t bitness,
                           size_t start_file_offset,
                           size_t* abs_file_offset,
                           size_t file_size,
                           FILE* fp,
                           uint8_t* block_l,
                           uint8_t* block_s);
void PE_fillTLSEntry(PE_IMAGE_TLS_DIRECTORY64* tls,
                     size_t* offset,
                     size_t* abs_file_offset,
                     size_t file_size,
                     uint8_t bitness,
                     FILE* fp,
                     uint8_t* block_l);

int PE_parseImageBaseRelocationTable(PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s);
uint32_t PE_numberOfRelocationEntries(uint32_t SizeOfBlock);

//size_t Rva2Offset(uint32_t va, SVAS* svas, uint16_t svas_size);
size_t PE_Rva2Foa(uint32_t va, SVAS* svas, uint16_t svas_size);





/**
 * Parse ImageImportTable, i.e. DataDirectory[IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
HP_API
void PE_parseImageImportTable(PE64OptHeader* oh,
                              uint16_t nr_of_sections,
                              SVAS* svas,
                              uint8_t bitness,
                              size_t start_file_offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l,
                              uint8_t* block_s,
                              int extended)
{
    size_t size;
    size_t offset;
    size_t name_offset;
    
    size_t thunk_data_offset;
    size_t table_fo;

    char* dll_name = NULL;

    PEImageImportDescriptor id; // 32 + 64
    uint32_t vsize = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
    size_t r_size = 0;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_IMPORT, nr_of_sections, "Import", svas);
    if ( table_fo == 0 )
        return;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;

    PE_fillImportDescriptor(&id, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageImportTableHeader(&id);

    // terminated by zero filled PEImageImportDescriptor
    while ( !isMemZero(&id, sizeof(id)) && r_size < vsize)
    {
        dll_name = NULL;
        name_offset = PE_Rva2Foa(id.Name, svas, nr_of_sections);
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
            break;
        name_offset += start_file_offset;
        if ( readFile(fp, name_offset, BLOCKSIZE, block_s) )
            dll_name = (char*) block_s;
//		else
//			break;

        PE_printImageImportDescriptor(&id, *abs_file_offset+offset, dll_name);

        if ( extended )
        {
            if ( id.OriginalFirstThunk != 0)
                thunk_data_offset = PE_Rva2Foa(id.OriginalFirstThunk, svas, nr_of_sections);
            else
                thunk_data_offset = PE_Rva2Foa(id.FirstThunk, svas, nr_of_sections);

            if ( thunk_data_offset > 0 )
                thunk_data_offset += start_file_offset;

            PE_printHintFunctionHeader((id.TimeDateStamp == (uint32_t)-1));
            PE_iterateThunkData(nr_of_sections, svas, bitness, start_file_offset, file_size, fp, block_s, thunk_data_offset);
        }

        offset += PE_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_IMPORT_DESCRIPTOR_SIZE;
        PE_fillImportDescriptor(&id, &offset, abs_file_offset, file_size, fp, block_l);

        printf("\n");
    }
}

void PE_fillImportDescriptor(PEImageImportDescriptor* id,
                             size_t* offset,
                             size_t* abs_file_offset,
                             size_t file_size,
                             FILE* fp,
                             uint8_t* block_l)
{
    uint8_t *ptr = NULL;

    memset(id, 0, PE_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    id->OriginalFirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Union]);
    id->TimeDateStamp = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.TimeDateStamp]);
    id->ForwarderChain = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.ForwarderChain]);
    id->Name = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.Name]);
    id->FirstThunk = *((uint32_t*) &ptr[PEImageImportDescriptorOffsets.FirstThunk]);
}

int PE_fillThunkData(PEImageThunkData64* thunk_data,
                      size_t offset,
                      int bitness,
                      size_t start_file_offset,
                      size_t file_size,
                      FILE* fp)
{
    uint8_t block[PE_THUNK_DATA_64_SIZE];
    uint8_t data_size = ( bitness == 32 ) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;
    size_t r_size = 0;

    memset(thunk_data, 0, sizeof(PEImageThunkData64));
    
    if ( !checkFileSpace(offset, start_file_offset, data_size, file_size) )
        return -1;

    r_size = readFile(fp, offset, data_size, block);
    if ( r_size < data_size )
        return -2;

    if ( bitness == 32 )
        thunk_data->Ordinal = *((uint32_t*) &block[PEImageThunkData32Offsets.u1]);
    else
        thunk_data->Ordinal = *((uint64_t*) &block[PEImageThunkData64Offsets.u1]);

    return 0;
}

int PE_fillImportByName(PEImageImportByName* ibn,
                         size_t offset,
                         FILE* fp,
                         uint8_t* block_s)
{
    size_t r_size = 0;

    memset(ibn, 0, sizeof(PEImageImportByName));

    r_size = readFile(fp, offset, BLOCKSIZE, block_s);
    if ( !r_size )
        return -1;
    
    ibn->Hint = *((uint16_t*) &block_s[PEImageImportByNameOffsets.Hint]);
    ibn->Name = (char*) &block_s[PEImageImportByNameOffsets.Name];

    return 0;
}

/**
 * Parse ImageDelayImportTable, i.e. DataDirectory[DELAY_IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageDelayImportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    int extended
)
{
    size_t size;
    size_t offset;
    size_t name_offset;

    size_t thunk_data_offset;
    size_t table_fo;

    char* dll_name = NULL;

    PeImageDelayLoadDescriptor did; // 32 + 64
    uint32_t vsize = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
    size_t r_size = 0;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, nr_of_sections, "Delay Import", svas);
    if ( table_fo == 0 )
        return;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
#ifdef DEBUG_PRINT_INFO
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
#endif
    PE_fillDelayImportDescriptor(&did, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageDelayImportTableHeader(&did);

    // terminated by zero filled PEImageImportDescriptor
//    while ( did.ImportNameTableRVA != 0 && did.ImportAddressTableRVA != 0 )
    while ( !isMemZero(&did, sizeof(did)) && r_size < vsize )
    {
        dll_name = NULL;
        name_offset = PE_Rva2Foa(did.DllNameRVA, svas, nr_of_sections);
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
            break;
        name_offset += start_file_offset;

        if ( readFile(fp, name_offset, BLOCKSIZE, block_s) )
            dll_name = (char*)block_s;
        //		else
        //			break;

        PE_printImageDelayImportDescriptor(&did, *abs_file_offset + offset, dll_name);

        if ( extended )
        {
            if ( did.ImportNameTableRVA != 0 )
                thunk_data_offset = PE_Rva2Foa(did.ImportNameTableRVA, svas, nr_of_sections);
            else
                thunk_data_offset = PE_Rva2Foa(did.ImportAddressTableRVA, svas, nr_of_sections);

            if ( thunk_data_offset > 0 )
                thunk_data_offset += start_file_offset;

            PE_printHintFunctionHeader((did.TimeDateStamp == (uint32_t)-1));
            PE_iterateThunkData(nr_of_sections, svas, bitness, start_file_offset, file_size, fp, block_s, thunk_data_offset);
        }

        offset += PE_DELAY_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_DELAY_IMPORT_DESCRIPTOR_SIZE;
        PE_fillDelayImportDescriptor(&did, &offset, abs_file_offset, file_size, fp, block_l);

        printf("\n");
    }
}

void PE_fillDelayImportDescriptor(PeImageDelayLoadDescriptor* did,
                                  size_t* offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(did, 0, PE_DELAY_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_DELAY_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    did->Attributes.AllAttributes = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.Attributes]);
    did->DllNameRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.DllNameRVA]);
    did->ModuleHandleRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ModuleHandleRVA]);
    did->ImportAddressTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ImportAddressTableRVA]);
    did->ImportNameTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.ImportNameTableRVA]);
    did->BoundImportAddressTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.BoundImportAddressTableRVA]);
    did->UnloadInformationTableRVA = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.UnloadInformationTableRVA]);
    did->TimeDateStamp = *((uint32_t*)&ptr[PeImageDelayLoadDescriptorOffsets.TimeDateStamp]);
}

int PE_iterateThunkData(uint16_t nr_of_sections,
                        SVAS* svas,
                        uint8_t bitness,
                        size_t start_file_offset,
                        size_t file_size,
                        FILE* fp,
                        uint8_t* block_s,
                        size_t thunk_data_offset)
{
    int s;
    size_t fo = 0;
    PEImageThunkData64 thunk_data; // 32==PIMAGE_THUNK_DATA32 64:PIMAGE_THUNK_DATA64
    uint8_t thunk_data_size = (bitness == 32) ? PE_THUNK_DATA_32_SIZE : PE_THUNK_DATA_64_SIZE;
    PEImageImportByName import_by_name; // 32 + 64
    uint64_t flag = (bitness == 32) ? IMAGE_ORDINAL_FLAG32 : IMAGE_ORDINAL_FLAG64;

    while ( 1 )
    {
        s = PE_fillThunkData(&thunk_data, thunk_data_offset, bitness, start_file_offset, file_size, fp);
        if ( s != 0 )
        {
            header_error("ERROR (0x%x): PE_fillThunkData\n", s);
            return -1;
        }
        // end of data
        if ( thunk_data.Ordinal == 0 )
            break;

        if ( !(thunk_data.Ordinal & flag) )
        {
            fo = PE_Rva2Foa((uint32_t)thunk_data.AddressOfData, svas, nr_of_sections); // INT => AddressOfData, IAT => Function
            if ( fo == 0 )
                return -2;
            fo += start_file_offset;

            s = PE_fillImportByName(&import_by_name, fo, fp, block_s);
            if ( s != 0 )
            {
                header_error("ERROR (0x%x): PE_fillImportByName\n", s);
                return -3;
            }
        }

        PE_printImageThunkData(&thunk_data, &import_by_name, thunk_data_offset, fo, bitness);

        thunk_data_offset += thunk_data_size;
    }

    return 0;
}

/**
 * Parse ImageBoundImportTable, i.e. DataDirectory[BOUND_IMPORT]
 *
 */
void PE_parseImageBoundImportTable(
    PE64OptHeader* oh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
)
{
    size_t size;
    size_t table_fo;
    size_t offset;
    size_t name_offset;

    PEDataDirectory* table = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]; // 32 + 64
    uint32_t vaddr = table->VirtualAddress;
    uint32_t vsize = table->Size;
    size_t r_size = 0;

    char* dll_name = NULL;

    uint16_t ri;

    PE_IMAGE_BOUND_IMPORT_DESCRIPTOR bid; // 32 + 64
    PE_IMAGE_BOUND_FORWARDER_REF bfr; // 32 + 64

    if (vaddr == 0 || vsize == 0)
    {
        printf("No Bound Import Table!\n\n");
        return;
    }
    // not an rva, but plain fo !!
    table_fo = vaddr;
    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
#ifdef DEBUG_PRINT_INFO
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
#endif
    PE_fillBoundImportDescriptor(&bid, &offset, abs_file_offset, file_size, fp, block_l);

    PE_printImageBoundImportTableHeader(&bid);

    // terminated by zero filled PEImageBoundImportDescriptor
    while ( !isMemZero(&bid, sizeof(bid)) && r_size < vsize  )
    {
        dll_name = NULL;
        name_offset = table_fo + bid.OffsetModuleName + start_file_offset;
        if ( !checkFileSpace(0, name_offset, 1, file_size) )
            break;

        if ( readFile(fp, name_offset, BLOCKSIZE, block_s) )
            dll_name = (char*)block_s;
        //else
        //  break;

        PE_printImageBoundImportDescriptor(&bid, *abs_file_offset + offset, dll_name);

        offset += PE_BOUND_IMPORT_DESCRIPTOR_SIZE;
        r_size += PE_BOUND_IMPORT_DESCRIPTOR_SIZE;

        for ( ri = 0; ri < bid.NumberOfModuleForwarderRefs; ri++ )
        {
            PE_fillBoundForwarderRef(&bfr, &offset, abs_file_offset, file_size, fp, block_l);

            dll_name = NULL;
            name_offset = table_fo + bfr.OffsetModuleName + start_file_offset;
            if ( !checkFileSpace(0, name_offset, 1, file_size) )
                break;

            if ( readFile(fp, name_offset, BLOCKSIZE, block_s) )
                dll_name = (char*)block_s;

            PE_printImageBoundForwarderRef(&bfr, *abs_file_offset + offset, dll_name, ri+1, bid.NumberOfModuleForwarderRefs);

            offset += PE_BOUND_FORWARDER_REF_SIZE;
            r_size += PE_BOUND_FORWARDER_REF_SIZE;
        }

        printf("\n");

        PE_fillBoundImportDescriptor(&bid, &offset, abs_file_offset, file_size, fp, block_l);
    }
}

void PE_fillBoundImportDescriptor(PE_IMAGE_BOUND_IMPORT_DESCRIPTOR* bid,
                                  size_t* offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(bid, 0, PE_BOUND_IMPORT_DESCRIPTOR_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_BOUND_IMPORT_DESCRIPTOR_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    bid->TimeDateStamp = *((uint32_t*)&ptr[PeImageBoundDescriptorOffsets.TimeDateStamp]);
    bid->OffsetModuleName = *((uint16_t*)&ptr[PeImageBoundDescriptorOffsets.OffsetModuleName]);
    bid->NumberOfModuleForwarderRefs = *((uint16_t*)&ptr[PeImageBoundDescriptorOffsets.NumberOfModuleForwarderRefs]);
}

void PE_fillBoundForwarderRef(PE_IMAGE_BOUND_FORWARDER_REF* bfr,
                              size_t* offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* block_l)
{
    uint8_t* ptr = NULL;

    memset(bfr, 0, PE_BOUND_FORWARDER_REF_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, PE_BOUND_FORWARDER_REF_SIZE, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, PE_BOUND_FORWARDER_REF_SIZE, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    bfr->TimeDateStamp = *((uint32_t*)&ptr[PeImageBoundForwarderRefOffsets.TimeDateStamp]);
    bfr->OffsetModuleName = *((uint16_t*)&ptr[PeImageBoundForwarderRefOffsets.OffsetModuleName]);
    bfr->Reserved= *((uint16_t*)&ptr[PeImageBoundForwarderRefOffsets.Reserved]);
}






/**
 * Parse ImageExportTable, i.e. DataDirectory[EXPORT]
 *
 * @param oh
 * @param nr_of_sections
 * @param start_file_offset
 * @param file_size
 * @param fp
 * @param block_s
 * @param svas
 */
void PE_parseImageExportTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas
)
{
    PE_IMAGE_EXPORT_DIRECTORY ied;

    size_t table_fo;
    size_t functions_offset, names_offset, names_ordinal_offset;
    uint32_t function_rva, name_rva;
    size_t function_fo, name_fo;
    uint16_t name_ordinal;
    char name[BLOCKSIZE];
    uint32_t table_start_rva = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    uint32_t table_end_rva = table_start_rva + oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    int is_forwarded;
    size_t size, name_size, bytes_size;
    size_t i;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_EXPORT, nr_of_sections, "Export", svas);
    if ( table_fo == 0 )
        return;

    // fill PE_IMAGE_EXPORT_DIRECTORY info
    if ( PE_fillImageExportDirectory(&ied, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
        return;

    PE_printImageExportDirectoryInfo(&ied);

    // iterate functions
    // converte rvas: function, name, nameordinal
    functions_offset = PE_Rva2Foa(ied.AddressOfFunctions, svas, nr_of_sections);
    functions_offset += start_file_offset;

    names_offset = PE_Rva2Foa(ied.AddressOfNames, svas, nr_of_sections);
    names_offset += start_file_offset;

    names_ordinal_offset = PE_Rva2Foa(ied.AddressOfNameOrdinals, svas, nr_of_sections);
    names_ordinal_offset += start_file_offset;


    PE_printImageExportDirectoryHeader();

    // iterate through the blocks
    for ( i = 0; i < ied.NumberOfFunctions; i++, functions_offset+=4,names_offset+=4,names_ordinal_offset+=2 )
    {
        is_forwarded = 0;

        fseek(fp, functions_offset, SEEK_SET);
        size = fread(&function_rva, 1, 4, fp);
        if ( size != 4 )
            continue;
        
        if ( table_start_rva <= function_rva && function_rva < table_end_rva )
        {
            is_forwarded = 1;
        }

        fseek(fp, names_offset, SEEK_SET);
        size = fread(&name_rva, 1, 4, fp);
        if ( size != 4 )
            continue;

        fseek(fp, names_ordinal_offset, SEEK_SET);
        size = fread(&name_ordinal, 1, 2, fp);
        if ( size != 2 )
            continue;

        
        name_size = 0;
        name_fo = 0;
        memset(name, 0, BLOCKSIZE);
        if ( name_rva > 0 )
        {
            name_fo = PE_Rva2Foa(name_rva, svas, nr_of_sections);
            //printf("name_fo: 0x%zx\n", name_fo);
            if ( name_fo != 0 )
            {
                name_fo += start_file_offset;
                name_size = readFile(fp, name_fo, BLOCKSIZE, (uint8_t*)name);
            }
            //printf("name_size: 0x%zx\n", name_size);
            if ( name_size < 2 || name_fo == 0 )
            {
                name_size = 0;
                name[0] = 0;
            }
            else
            {
                name[name_size-1] = 0;
            }
        }
        
        bytes_size = 0;
        function_fo = 0;
        memset(block_s, 0, BLOCKSIZE);
        if ( function_rva > 0 )
        {
            function_fo = PE_Rva2Foa(function_rva, svas, nr_of_sections);
            if ( function_fo != 0 )
            {
                function_fo += start_file_offset;
                bytes_size = readFile(fp, function_fo, BLOCKSIZE, block_s);
            }
            
            if ( bytes_size == 0 || function_fo == 0)
            {
                bytes_size = 0;
                block_s[0] = 0;
            }
        }

        PE_printImageExportDirectoryEntry(i, ied.NumberOfFunctions, name, name_size, name_ordinal, block_s, bytes_size, function_rva, function_fo, is_forwarded);
    }
}

int PE_fillImageExportDirectory(PE_IMAGE_EXPORT_DIRECTORY* ied,
                                size_t offset,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct Pe_Image_Export_Directory_Offsets offsets = PeImageExportDirectoryOffsets;

    if ( !checkFileSpace(offset, start_file_offset, PE_EXPORT_DIRECTORY_SIZE, file_size))
        return 1;

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE, block_s);
    if ( size == 0 )
        return 2;
    offset = 0;

    ptr = &block_s[offset];
    memset(ied, 0, PE_EXPORT_DIRECTORY_SIZE);
    ied->Characteristics = *((uint32_t*) &ptr[offsets.Characteristics]);
    ied->TimeDateStamp = *((uint32_t*) &ptr[offsets.TimeDateStamp]);
    ied->MajorVersion = *((uint16_t*) &ptr[offsets.MajorVersion]);
    ied->MinorVersion = *((uint16_t*) &ptr[offsets.MinorVersion]);
    ied->Name = *((uint32_t*) &ptr[offsets.Name]);
    ied->Base = *((uint32_t*) &ptr[offsets.Base]);
    ied->NumberOfFunctions = *((uint32_t*) &ptr[offsets.NumberOfFunctions]);
    ied->NumberOfNames = *((uint32_t*) &ptr[offsets.NumberOfNames]);
    ied->AddressOfFunctions = *((uint32_t*) &ptr[offsets.AddressOfFunctions]);
    ied->AddressOfNames = *((uint32_t*) &ptr[offsets.AddressOfNames]);
    ied->AddressOfNameOrdinals = *((uint32_t*) &ptr[offsets.AddressOfNameOrdinals]);

    return 0;
}





void PE_parseImageTLSTable(PE64OptHeader* oh,
                           uint16_t nr_of_sections,
                           SVAS* svas,
                           uint8_t bitness,
                           size_t start_file_offset,
                           size_t* abs_file_offset,
                           size_t file_size,
                           FILE* fp,
                           uint8_t* block_l,
                           uint8_t* block_s)
{
    PE_IMAGE_TLS_DIRECTORY64 tls;

    size_t table_fo;
    size_t e_size = (bitness == 32) ? PE_IMAGE_TLS_DIRECTORY32_SIZE : PE_IMAGE_TLS_DIRECTORY64_SIZE;
    size_t r_size = 0;
    size_t size;
    size_t offset;
    uint32_t i = 0;
    size_t s_offset;
    size_t e_offset;
    size_t cb_offset;
    
    uint32_t tls_table_size = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_TLS, nr_of_sections, "TLS", svas);
    if (table_fo == 0)
        return;
#ifdef DEBUG_PRINT_INFO
    debug_info("PE_parseImageTLSTable\n");
    debug_info("table_fo: 0x%zx\n", table_fo);
#endif

    offset = table_fo;

    // read new block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, e_size, file_size) )
        return;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;
    offset = 0;
    
#ifdef DEBUG_PRINT_INFO
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
#endif

    PE_printImageTLSTableHeader();

    while ( 1 )
    {
        PE_fillTLSEntry(&tls, &offset, abs_file_offset, file_size, bitness, fp, block_l);
        
        if ( isMemZero(&tls, sizeof(tls)) )
            break;

        s_offset = (size_t)(tls.StartAddressOfRawData - oh->ImageBase);
        s_offset = PE_Rva2Foa((uint32_t)s_offset, svas, nr_of_sections);
        s_offset += start_file_offset;

        e_offset = (size_t)(tls.EndAddressOfRawData - oh->ImageBase);
        e_offset = PE_Rva2Foa((uint32_t)e_offset, svas, nr_of_sections);
        e_offset += start_file_offset;
        
        cb_offset = (size_t)(tls.AddressOfCallBacks - oh->ImageBase);
        cb_offset = PE_Rva2Foa((uint32_t)cb_offset, svas, nr_of_sections);
        cb_offset += start_file_offset;

        PE_printTLSEntry(&tls, i+1, bitness, *abs_file_offset+offset, s_offset, e_offset, cb_offset, file_size, fp, block_s);

        offset += e_size;
        r_size += e_size;
        
        if ( r_size >= tls_table_size )
            break;

        i++;
        printf("\n");
    }
}

void PE_fillTLSEntry(PE_IMAGE_TLS_DIRECTORY64* tls,
                    size_t* offset,
                    size_t* abs_file_offset,
                    size_t file_size,
                    uint8_t bitness,
                    FILE* fp,
                    uint8_t* block_l)
{
    uint8_t *ptr = NULL;
    size_t e_size = (bitness == 32) 
        ? PE_IMAGE_TLS_DIRECTORY32_SIZE 
        : PE_IMAGE_TLS_DIRECTORY64_SIZE;
    struct PE_IMAGE_TLS_DIRECTORY_OFFSETS offsets = (bitness == 32)
        ? PeImageTlsDirectoryOfsets32
        : PeImageTlsDirectoryOfsets64;

    memset(tls, 0, PE_IMAGE_TLS_DIRECTORY64_SIZE);

    if ( !checkFileSpace(*offset, *abs_file_offset, e_size, file_size) )
        return;

    if ( !checkLargeBlockSpace(offset, abs_file_offset, e_size, block_l, fp) )
        return;

    ptr = &block_l[*offset];
    if ( bitness == 32 )
    {
        tls->StartAddressOfRawData = *((uint32_t*) &ptr[offsets.StartAddressOfRawData]);
        tls->EndAddressOfRawData = *((uint32_t*) &ptr[offsets.EndAddressOfRawData]);
        tls->AddressOfIndex = *((uint32_t*) &ptr[offsets.AddressOfIndex]);
        tls->AddressOfCallBacks = *((uint32_t*) &ptr[offsets.AddressOfCallBacks]);
    }
    else
    {
        tls->StartAddressOfRawData = *((uint64_t*) &ptr[offsets.StartAddressOfRawData]);
        tls->EndAddressOfRawData = *((uint64_t*) &ptr[offsets.EndAddressOfRawData]);
        tls->AddressOfIndex = *((uint64_t*) &ptr[offsets.AddressOfIndex]);
        tls->AddressOfCallBacks = *((uint64_t*) &ptr[offsets.AddressOfCallBacks]);
    }
    tls->SizeOfZeroFill = *((uint32_t*) &ptr[offsets.SizeOfZeroFill]);
    tls->DUMMYUNIONNAME.Characteristics = *((uint32_t*) &ptr[offsets.Characteristics]);
}




/**
 * Parse ImageDelayImportTable, i.e. DataDirectory[DELAY_IMPORT]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageLoadConfigTable(PE64OptHeader* oh,
                                  uint16_t nr_of_sections,
                                  SVAS* svas,
                                  uint8_t bitness,
                                  size_t start_file_offset,
                                  size_t* abs_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    PE_IMAGE_LOAD_CONFIG_DIRECTORY64 lcd;

    size_t table_fo;

    LoadConfigTableOffsets to;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, nr_of_sections, "Load Config", svas);
    if (table_fo == 0)
        return;

    size_t e_size = (bitness == 32) ? PE_IMAGE_LOAD_CONFIG_DIRECTORY32_SIZE : PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE;
    if (oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size != e_size)
    {
        printf("LOAD_CONFIG size missmatch: expected 0x%zx but got 0x%"PRIx32"\n", e_size, oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
    }

    // fill PE_IMAGE_EXPORT_DIRECTORY info
    if (PE_fillImageLoadConfigDirectory(&lcd, bitness, table_fo, start_file_offset, file_size, fp, block_s) != 0)
        return;
    
    to.seh = (size_t)(lcd.SEHandlerTable - oh->ImageBase);
    to.seh = PE_Rva2Foa((uint32_t)to.seh, svas, nr_of_sections);
    to.seh += start_file_offset;

    to.fun = (size_t)(lcd.GuardCFFunctionTable - oh->ImageBase);
    to.fun = PE_Rva2Foa((uint32_t)to.fun, svas, nr_of_sections);
    to.fun += start_file_offset;

    to.iat = (size_t)(lcd.GuardAddressTakenIatEntryTable - oh->ImageBase);
    to.iat = PE_Rva2Foa((uint32_t)to.iat, svas, nr_of_sections);
    to.iat += start_file_offset;

    to.jmp = (size_t)(lcd.GuardLongJumpTargetTable - oh->ImageBase);
    to.jmp = PE_Rva2Foa((uint32_t)to.jmp, svas, nr_of_sections);
    to.jmp += start_file_offset;

    to.ehc = (size_t)(lcd.GuardEHContinuationTable - oh->ImageBase);
    to.ehc = PE_Rva2Foa((uint32_t)to.ehc, svas, nr_of_sections);
    to.ehc += start_file_offset;

    PE_printImageLoadConfigDirectory(&lcd, *abs_file_offset + table_fo, bitness, &to, file_size, fp, block_s);
}

int PE_fillImageLoadConfigDirectory(PE_IMAGE_LOAD_CONFIG_DIRECTORY64* lcd,
                                    uint8_t bitness,
                                    size_t offset,
                                    size_t start_file_offset,
                                    size_t file_size,
                                    FILE* fp,
                                    uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct PE_IMAGE_LOAD_CONFIG_DIRECTORY_OFFSETS offsets = (bitness==32) ? 
                                                            PeImageLoadConfigDirectoryOffsets32 : 
                                                            PeImageLoadConfigDirectoryOffsets64;
    size_t d_size = (bitness == 32) ? PE_IMAGE_LOAD_CONFIG_DIRECTORY32_SIZE : PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE;

    if (!checkFileSpace(offset, start_file_offset, d_size, file_size))
        return 1;

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE, block_s);
    if (size == 0)
        return 2;
    offset = 0;

    ptr = &block_s[offset];
    memset(lcd, 0, PE_IMAGE_LOAD_CONFIG_DIRECTORY64_SIZE);
    lcd->Size = GetIntXValueAtOffset(uint32_t, ptr, offsets.Size); //*((uint32_t*)&ptr[offsets.Size]);
    lcd->TimeDateStamp = *((uint32_t*)&ptr[offsets.TimeDateStamp]);
    lcd->MajorVersion = *((uint16_t*)&ptr[offsets.MajorVersion]);
    lcd->MinorVersion = *((uint16_t*)&ptr[offsets.MinorVersion]);
    lcd->GlobalFlagsClear = *((uint32_t*)&ptr[offsets.GlobalFlagsClear]);
    lcd->GlobalFlagsSet = *((uint32_t*)&ptr[offsets.GlobalFlagsSet]);
    lcd->CriticalSectionDefaultTimeout = *((uint32_t*)&ptr[offsets.CriticalSectionDefaultTimeout]);
    lcd->ProcessHeapFlags = *((uint32_t*)&ptr[offsets.ProcessHeapFlags]);
    lcd->CSDVersion = *((uint16_t*)&ptr[offsets.CSDVersion]);
    lcd->DependentLoadFlags = *((uint16_t*)&ptr[offsets.DependentLoadFlags]);
    lcd->GuardFlags = *((uint32_t*)&ptr[offsets.GuardFlags]);
    lcd->CodeIntegrity.Flags = *((uint16_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Flags]);
    lcd->CodeIntegrity.Catalog = *((uint16_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Catalog]);
    lcd->CodeIntegrity.CatalogOffset = *((uint32_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.CatalogOffset]);
    lcd->CodeIntegrity.Reserved = *((uint32_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Reserved]);
    lcd->DynamicValueRelocTableOffset = *((uint32_t*)&ptr[offsets.DynamicValueRelocTableOffset]);
    lcd->DynamicValueRelocTableSection = *((uint16_t*)&ptr[offsets.DynamicValueRelocTableSection]);
    lcd->Reserved2 = *((uint16_t*)&ptr[offsets.Reserved2]);
    lcd->HotPatchTableOffset = *((uint32_t*)&ptr[offsets.HotPatchTableOffset]);
    lcd->Reserved3 = *((uint32_t*)&ptr[offsets.Reserved3]);

    if (bitness == 32)
    {
        lcd->CriticalSectionDefaultTimeout = *((uint32_t*)&ptr[offsets.CriticalSectionDefaultTimeout]);
        lcd->DeCommitFreeBlockThreshold = *((uint32_t*)&ptr[offsets.DeCommitFreeBlockThreshold]);
        lcd->DeCommitTotalFreeThreshold = *((uint32_t*)&ptr[offsets.DeCommitTotalFreeThreshold]);
        lcd->LockPrefixTable = *((uint32_t*)&ptr[offsets.LockPrefixTable]);
        lcd->MaximumAllocationSize = *((uint32_t*)&ptr[offsets.MaximumAllocationSize]);
        lcd->VirtualMemoryThreshold = *((uint32_t*)&ptr[offsets.VirtualMemoryThreshold]);
        lcd->ProcessAffinityMask = *((uint32_t*)&ptr[offsets.ProcessAffinityMask]);
        lcd->EditList = *((uint32_t*)&ptr[offsets.EditList]);
        lcd->SecurityCookie = *((uint32_t*)&ptr[offsets.SecurityCookie]);
        lcd->SEHandlerTable = *((uint32_t*)&ptr[offsets.SEHandlerTable]);
        lcd->SEHandlerCount = *((uint32_t*)&ptr[offsets.SEHandlerCount]);
        lcd->GuardCFCheckFunctionPointer = *((uint32_t*)&ptr[offsets.GuardCFCheckFunctionPointer]);
        lcd->GuardCFDispatchFunctionPointer = *((uint32_t*)&ptr[offsets.GuardCFDispatchFunctionPointer]);
        lcd->GuardCFFunctionTable = *((uint32_t*)&ptr[offsets.GuardCFFunctionTable]);
        lcd->GuardCFFunctionCount = *((uint32_t*)&ptr[offsets.GuardCFFunctionCount]);
        lcd->GuardAddressTakenIatEntryTable = *((uint32_t*)&ptr[offsets.GuardAddressTakenIatEntryTable]);
        lcd->GuardAddressTakenIatEntryCount = *((uint32_t*)&ptr[offsets.GuardAddressTakenIatEntryCount]);
        lcd->GuardLongJumpTargetTable = *((uint32_t*)&ptr[offsets.GuardLongJumpTargetTable]);
        lcd->GuardLongJumpTargetCount = *((uint32_t*)&ptr[offsets.GuardLongJumpTargetCount]);
        lcd->DynamicValueRelocTable = *((uint32_t*)&ptr[offsets.DynamicValueRelocTable]);
        lcd->CHPEMetadataPointer = *((uint32_t*)&ptr[offsets.CHPEMetadataPointer]);
        lcd->GuardRFFailureRoutine = *((uint32_t*)&ptr[offsets.GuardRFFailureRoutine]);
        lcd->GuardRFFailureRoutineFunctionPointer = *((uint32_t*)&ptr[offsets.GuardRFFailureRoutineFunctionPointer]);
        lcd->GuardRFVerifyStackPointerFunctionPointer = *((uint32_t*)&ptr[offsets.GuardRFVerifyStackPointerFunctionPointer]);
        lcd->EnclaveConfigurationPointer = *((uint32_t*)&ptr[offsets.EnclaveConfigurationPointer]);
        lcd->VolatileMetadataPointer = *((uint32_t*)&ptr[offsets.VolatileMetadataPointer]);
        lcd->GuardEHContinuationTable = *((uint32_t*)&ptr[offsets.GuardEHContinuationTable]);
        lcd->GuardEHContinuationCount = *((uint32_t*)&ptr[offsets.GuardEHContinuationCount]);
    }
    else
    {
        lcd->DeCommitFreeBlockThreshold = *((uint64_t*)&ptr[offsets.DeCommitFreeBlockThreshold]);
        lcd->DeCommitTotalFreeThreshold = *((uint64_t*)&ptr[offsets.DeCommitTotalFreeThreshold]);
        lcd->LockPrefixTable = *((uint64_t*)&ptr[offsets.LockPrefixTable]);
        lcd->MaximumAllocationSize = *((uint64_t*)&ptr[offsets.MaximumAllocationSize]);
        lcd->VirtualMemoryThreshold = *((uint64_t*)&ptr[offsets.VirtualMemoryThreshold]);
        lcd->ProcessAffinityMask = *((uint64_t*)&ptr[offsets.ProcessAffinityMask]);
        lcd->EditList = *((uint64_t*)&ptr[offsets.EditList]);
        lcd->SecurityCookie = *((uint64_t*)&ptr[offsets.SecurityCookie]);
        lcd->SEHandlerTable = *((uint64_t*)&ptr[offsets.SEHandlerTable]);
        lcd->SEHandlerCount = *((uint64_t*)&ptr[offsets.SEHandlerCount]);
        lcd->GuardCFCheckFunctionPointer = *((uint64_t*)&ptr[offsets.GuardCFCheckFunctionPointer]);
        lcd->GuardCFDispatchFunctionPointer = *((uint64_t*)&ptr[offsets.GuardCFDispatchFunctionPointer]);
        lcd->GuardCFFunctionTable = *((uint64_t*)&ptr[offsets.GuardCFFunctionTable]);
        lcd->GuardCFFunctionCount = *((uint64_t*)&ptr[offsets.GuardCFFunctionCount]);
        lcd->CodeIntegrity.Flags = *((uint16_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Flags]);
        lcd->CodeIntegrity.Catalog = *((uint16_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Catalog]);
        lcd->CodeIntegrity.CatalogOffset = *((uint32_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.CatalogOffset]);
        lcd->CodeIntegrity.Reserved = *((uint32_t*)&ptr[offsets.CodeIntegrity + PeImageLoadConfigCodeIntegrityOffsets.Reserved]);
        lcd->GuardAddressTakenIatEntryTable = *((uint64_t*)&ptr[offsets.GuardAddressTakenIatEntryTable]);
        lcd->GuardAddressTakenIatEntryCount = *((uint64_t*)&ptr[offsets.GuardAddressTakenIatEntryCount]);
        lcd->GuardLongJumpTargetTable = *((uint64_t*)&ptr[offsets.GuardLongJumpTargetTable]);
        lcd->GuardLongJumpTargetCount = *((uint64_t*)&ptr[offsets.GuardLongJumpTargetCount]);
        lcd->DynamicValueRelocTable = *((uint64_t*)&ptr[offsets.DynamicValueRelocTable]);
        lcd->CHPEMetadataPointer = *((uint64_t*)&ptr[offsets.CHPEMetadataPointer]);
        lcd->GuardRFFailureRoutine = *((uint64_t*)&ptr[offsets.GuardRFFailureRoutine]);
        lcd->GuardRFFailureRoutineFunctionPointer = *((uint64_t*)&ptr[offsets.GuardRFFailureRoutineFunctionPointer]);
        lcd->GuardRFVerifyStackPointerFunctionPointer = *((uint64_t*)&ptr[offsets.GuardRFVerifyStackPointerFunctionPointer]);
        lcd->EnclaveConfigurationPointer = *((uint64_t*)&ptr[offsets.EnclaveConfigurationPointer]);
        lcd->VolatileMetadataPointer = *((uint64_t*)&ptr[offsets.VolatileMetadataPointer]);
        lcd->GuardEHContinuationTable = *((uint64_t*)&ptr[offsets.GuardEHContinuationTable]);
        lcd->GuardEHContinuationCount = *((uint64_t*)&ptr[offsets.GuardEHContinuationCount]);
    }

    return 0;
}





/**
 * Parse ImageResourceTable, i.e. DataDirectory[RESOURCE]
 *
 * @param oh
 * @param nr_of_sections
 */
void PE_parseImageResourceTable(PE64OptHeader* oh,
                                uint16_t nr_of_sections,
                                size_t start_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* block_s,
                                SVAS* svas)
{
    PE_IMAGE_RESOURCE_DIRECTORY rd;
    size_t table_fo;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_RESOURCE, nr_of_sections, "Resource", svas);
    if ( table_fo == 0 )
        return;

    // fill root PE_IMAGE_RESOURCE_DIRECTORY info
    if ( PE_fillImageResourceDirectory(&rd, table_fo, start_file_offset, file_size, fp, block_s) != 0 )
        return;
    PE_printImageResourceDirectory(&rd, table_fo, 0);

    PE_recurseImageResourceDirectory(table_fo + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
                                    rd.NumberOfIdEntries, 0, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
}

int PE_fillImageResourceDirectory(PE_IMAGE_RESOURCE_DIRECTORY* rd,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    size_t size;
    uint8_t* ptr = NULL;
    struct Pe_Image_Resource_Directory_Offsets offsets = PeImageResourceDirectoryOffsets;

    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DIRECTORY_SIZE, file_size))
        return 1;

    offset = offset + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE, block_s);
    if ( size == 0 )
        return 2;
    offset = 0;

    ptr = &block_s[offset];
    
    memset(rd, 0, PE_RESOURCE_DIRECTORY_SIZE);
    rd->Characteristics = GetIntXValueAtOffset(uint32_t, ptr, offsets.Characteristics);
    rd->TimeDateStamp = GetIntXValueAtOffset(uint32_t, ptr, offsets.TimeDateStamp);
    rd->MajorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MajorVersion);
    rd->MinorVersion = GetIntXValueAtOffset(uint16_t, ptr, offsets.MinorVersion);
    rd->NumberOfNamedEntries = GetIntXValueAtOffset(uint16_t, ptr, offsets.NumberOfNamedEntries);
    rd->NumberOfIdEntries = GetIntXValueAtOffset(uint16_t, ptr, offsets.NumberOfIdEntries);
    // follows immediately and will be iterated on its own.
//	rd->DirectoryEntries[0].Name = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.Name]);
//	rd->DirectoryEntries[0].OffsetToData = *((uint32_t*) &ptr[offsets.DirectoryEntries + PeImageResourceDirectoryEntryOffsets.OffsetToData]);

    return 0;
}

int PE_recurseImageResourceDirectory(
    size_t offset,
    size_t table_fo,
    uint16_t
    nr_of_named_entries,
    uint16_t nr_of_id_entries,
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
)
{
    uint16_t i;
    int s;

    PE_printImageResourceDirectoryEntryHeader(0, nr_of_named_entries, level);
    for ( i = 0; i < nr_of_named_entries; i++)
    {
        s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_named_entries, level, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
        if ( s != 0 )
            continue;

        offset += PE_RESOURCE_ENTRY_SIZE;
    }

    PE_printImageResourceDirectoryEntryHeader(1, nr_of_id_entries, level);
    for ( i = 0; i < nr_of_id_entries; i++)
    {
        s = PE_parseResourceDirectoryEntry(i, offset, table_fo, nr_of_id_entries, level, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
        if ( s != 0 )
            continue;
        
        offset += PE_RESOURCE_ENTRY_SIZE;
    }

    return 0;
}


int PE_parseResourceDirectoryEntry(
    uint16_t id, 
    size_t offset, 
    size_t table_fo, 
    uint16_t nr_of_entries, 
    uint16_t level,
    size_t start_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_s,
    SVAS* svas,
    uint16_t nr_of_sections
)
{
    PE_IMAGE_RESOURCE_DIRECTORY rd;
    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY re;
    PE_IMAGE_RESOURCE_DATA_ENTRY de;
    
    int s;
    size_t dir_offset = 0;
    uint32_t fotd;
    
    PE_fillImageResourceDirectoryEntry(&re, offset, table_fo, start_file_offset, file_size, fp, block_s);
    PE_printImageResourceDirectoryEntry(&re, table_fo, offset, level, id, nr_of_entries, start_file_offset, file_size, fp, block_s);

    dir_offset = table_fo + re.OFFSET_UNION.DATA_STRUCT.OffsetToDirectory;

    if ( re.OFFSET_UNION.DATA_STRUCT.DataIsDirectory )
    {
        s = PE_fillImageResourceDirectory(&rd, dir_offset, start_file_offset, file_size, fp, block_s);
        if ( s != 0 )
            return 1;
        PE_printImageResourceDirectory(&rd, dir_offset, level+1);
        PE_recurseImageResourceDirectory((size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
                                        rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s, svas, nr_of_sections);
    }
    else
    {
        PE_fillImageResourceDataEntry(&de, dir_offset, start_file_offset, file_size, fp, block_s);
        fotd = (uint32_t)PE_Rva2Foa(de.OffsetToData, svas, nr_of_sections);
        fotd += (uint32_t)start_file_offset;
        PE_printImageResourceDataEntry(&de, fotd, dir_offset, level);
    }
    
    return 0;
}

int PE_fillImageResourceDirectoryEntry(PE_IMAGE_RESOURCE_DIRECTORY_ENTRY* re,
                                       size_t offset,
                                       size_t table_fo,
                                       size_t start_file_offset,
                                       size_t file_size,
                                       FILE* fp,
                                       uint8_t* block_s)
{
    struct Pe_Image_Resource_Directory_Entry_Offsets entry_offsets = PeImageResourceDirectoryEntryOffsets;
    uint8_t* ptr = NULL;
    size_t size;

    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_ENTRY_SIZE, file_size))
        return 1;

    offset += start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE, block_s);
    if ( size == 0 )
        return 2;

    ptr = block_s;

    memset(re, 0, PE_RESOURCE_ENTRY_SIZE);
    re->NAME_UNION.Name = *((uint32_t*) &ptr[entry_offsets.Name]);
    re->OFFSET_UNION.OffsetToData = *((uint32_t*) &ptr[entry_offsets.OffsetToData]);

    return 0;
}

int PE_fillImageResourceDataEntry(PE_IMAGE_RESOURCE_DATA_ENTRY* de,
                                  size_t offset,
                                  size_t start_file_offset,
                                  size_t file_size,
                                  FILE* fp,
                                  uint8_t* block_s)
{
    uint8_t* ptr;
    size_t size;
    
    if ( !checkFileSpace(offset, start_file_offset, PE_RESOURCE_DATA_ENTRY_SIZE, file_size))
        return 1;
    
    offset += start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE, block_s);
    if ( size == 0 )
        return 2;
    
    ptr = block_s;

    memset(de, 0, PE_RESOURCE_ENTRY_SIZE);
    de->OffsetToData = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.OffsetToData]);
    de->Size = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.Size]);
    de->CodePage = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.CodePage]);
    de->Reserved = *((uint32_t*) &ptr[PeImageResourceDataEntryOffsets.Reserved]);

    return 0;
}

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
    if ( table_fo == (size_t) -1 )
        return 0;

    return table_fo;
}




int PE_fillDebugTableEntry(
    PE_DEBUG_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
);
int PE_parseCodeViewDbgH(
    PE_DEBUG_TABLE_ENTRY* dte,
    size_t file_size,
    size_t start_file_offset,
    size_t* abs_file_offset,
    FILE* fp,
    uint8_t* block_s
);
int PE_parseImageDebugTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    int extended
)
{
    size_t table_fo;
    size_t fo;
    size_t offset;
    size_t dte_offset;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t entry_id = 0;
    int s = 0;

    PEDataDirectory* dte = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    PE_DEBUG_TABLE_ENTRY entry;
    size_t entry_size = PE_DEBUG_TABLE_ENTRY_SIZE;
    uint32_t nr_of_entries;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_DEBUG, nr_of_sections, "Debug", svas);

    if (table_fo == 0)
        return -3;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, dte->Size, file_size) )
        return -1;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if (size == 0)
        return -2;
    offset = 0;
    dte_offset = 0;
    nr_of_entries = (uint32_t)(dte->Size/entry_size);

#ifdef DEBUG_PRINT
    printf("offset: 0x%zx\n", offset);
    printf("abs_file_offset: 0x%zx\n", *abs_file_offset);
    printf("dte->Size: 0x%x\n", dte->Size);
    printf("nrEntries: 0x%x\n", nr_of_entries);
#endif

    PE_printDebugTableHeader();

    while ( dte_offset < dte->Size )
    {
        if ( !checkFileSpace(offset, start_file_offset, dte->Size - dte_offset, file_size) )
            return -1;
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, dte->Size - dte_offset, block_l, fp) )
            return -2;
        ptr = &block_l[offset];
       
        s = PE_fillDebugTableEntry(&entry, offset, ptr);
        if ( s != 0 )
            break;

        PE_printDebugTableEntry(&entry, entry_id+1, nr_of_entries, start_file_offset);

        if ( extended )
        {
            switch ( entry.Type )
            {
                case PE_IMAGE_DEBUG_TYPE_CODEVIEW:
                    PE_parseCodeViewDbgH(&entry, file_size, start_file_offset, abs_file_offset, fp, block_s);
                    break;

                default:
                    break;
            }
        }
//#ifdef DEBUG_PRINT_INFO
        //printf(" - entry_id: 0x%x\n", entry_id);
        //printf("   - Characteristics: 0x%x\n", entry.Characteristics);
        //printf("   - TimeDateStamp: 0x%x\n", entry.TimeDateStamp);
        //printf("   - MajorVersion: 0x%x\n", entry.MajorVersion);
        //printf("   - MinorVersion: 0x%x\n", entry.MinorVersion);
        //printf("   - Type: 0x%x\n", entry.Type);
        //printf("   - SizeOfData: 0x%x\n", entry.SizeOfData);
        //printf("   - AddressOfRawData.va: 0x%x\n", entry.AddressOfRawData);
        //printf("   - PointerToRawData.va: 0x%x\n", entry.PointerToRawData);
//#endif

        dte_offset += entry_size;
        offset += entry_size;
        entry_id++;
    }
    printf("\n");

    return 0;
}

int PE_fillDebugTableEntry(
    PE_DEBUG_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
)
{
    memset(entry, 0, PE_DEBUG_TABLE_ENTRY_SIZE);

    entry->Characteristics = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.Characteristics);
    entry->TimeDateStamp = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.TimeDateStamp);
    entry->MajorVersion = GetIntXValueAtOffset(uint16_t, ptr, PeImageDebugTableEntryOffsets.MajorVersion);
    entry->MinorVersion = GetIntXValueAtOffset(uint16_t, ptr, PeImageDebugTableEntryOffsets.MinorVersion);
    entry->Type = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.Type);
    entry->SizeOfData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.SizeOfData);
    entry->AddressOfRawData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.AddressOfRawData);
    entry->PointerToRawData = GetIntXValueAtOffset(uint32_t, ptr, PeImageDebugTableEntryOffsets.PointerToRawData);

    return 0;
}

int PE_parseCodeViewDbgH(
    PE_DEBUG_TABLE_ENTRY* dte,
    size_t file_size,
    size_t start_file_offset,
    size_t* abs_file_offset,
    FILE* fp,
    uint8_t* block_s
)
{
    size_t size;
    size_t offset;
    PE_CODEVIEW_DBG_H entry;
    uint8_t* ptr = NULL;
    size_t i;

    if ( !checkFileSpace(dte->PointerToRawData, start_file_offset, dte->SizeOfData, file_size) )
        return -1;

    offset = dte->PointerToRawData + start_file_offset;
    size = readFile(fp, offset, BLOCKSIZE_SMALL, block_s);
    if (size == 0)
        return -2;
    ptr = block_s;

    entry.Signature = GetIntXValueAtOffset(uint32_t, ptr, PeCodeViewDbgHOffsets.Signature);
    for ( i = 0; i < 16; i += 8 )
    {
        *(uint64_t*)(&entry.Guid[i]) = GetIntXValueAtOffset(uint64_t, ptr, PeCodeViewDbgHOffsets.Guid+i);
    }
    entry.Age = GetIntXValueAtOffset(uint32_t, ptr, PeCodeViewDbgHOffsets.Age);
    entry.PathPtr = (char*)&ptr[PeCodeViewDbgHOffsets.Path];
    block_s[BLOCKSIZE_SMALL-1] = 0;

    PE_printCodeViewDbgH(&entry, start_file_offset, block_s);

    return 0;
}




int PE_fillExceptionTableEntry(
    PE_IMAGE_EXCEPTION_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
);
int PE_parseImageExceptionTable(
    PE64OptHeader* oh,
    uint16_t nr_of_sections,
    SVAS* svas,
    uint8_t bitness,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s
)
{
    size_t table_fo;
    size_t fo;
    size_t offset;
    size_t dte_offset;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t entry_id = 0;
    int s = 0;

    PEDataDirectory* dte = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

    PE_IMAGE_EXCEPTION_TABLE_ENTRY entry;
    size_t entry_size = PE_IMAGE_X64_EXCEPTION_TABLE_ENTRY_SIZE;
    //if ( 32-bit MIPS ) entry_size = PE_IMAGE_MIPS_EXCEPTION_TABLE_ENTRY_SIZE;
    //if ( 32-ARM, PowerPC, SH3 and SH4 Windows CE MIPS ) entry_size = PE_IMAGE_ARM_EXCEPTION_TABLE_ENTRY_SIZE;
    uint32_t nr_of_entries;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_EXCEPTION, nr_of_sections, "Exception", svas);

    if (table_fo == 0)
        return -3;

    offset = table_fo;

    // read new  block to ease up offsetting
    if ( !checkFileSpace(offset, start_file_offset, dte->Size, file_size) )
        return -1;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if (size == 0)
        return -2;
    offset = 0;
    dte_offset = 0;
    
//#ifdef DEBUG_PRINT_INFO
    printf("offset: 0x%zx\n", offset);
    printf("abs_file_offset: 0x%zx\n", *abs_file_offset);
    printf("dte->Size: 0x%x\n", dte->Size);
//#endif

//    PE_printImageBaseRelocationTable();
//
    while ( dte_offset < dte->Size )
    {
        if ( !checkFileSpace(offset, start_file_offset, dte->Size - dte_offset, file_size) )
            return -1;
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, dte->Size - dte_offset, block_l, fp) )
            return -2;
        ptr = &block_l[offset];
       
        s = PE_fillExceptionTableEntry(&entry, offset, ptr);
        if ( s != 0 )
            break;

        //PE_printExceptionTableEntry(&entry, entry_id, start_file_offset);
//#ifdef DEBUG_PRINT_INFO
        printf(" - entry_id: 0x%x\n", entry_id);
        fo = PE_Rva2Foa(entry.BeginAddress, svas, nr_of_sections);
        printf("   - BeginAddress.va: 0x%x\n", entry.BeginAddress);
        printf("   - BeginAddress.fo: 0x%zx\n", fo);
        fo = PE_Rva2Foa(entry.EndAddress, svas, nr_of_sections);
        printf("   - EndAddress.va: 0x%x\n", entry.EndAddress);
        printf("   - EndAddress.fo: 0x%zx\n", fo);
        fo = PE_Rva2Foa(entry.UnwindInformation, svas, nr_of_sections);
        printf("   - UnwindInformation.va: 0x%x\n", entry.UnwindInformation);
        printf("   - UnwindInformation.fo: 0x%zx\n", fo);
//#endif

        dte_offset += entry_size;
        offset += entry_size;
        entry_id++;
    }
    printf("\n");

    return 0;
}

int PE_fillExceptionTableEntry(
    PE_IMAGE_EXCEPTION_TABLE_ENTRY* entry,
    size_t offset,
    uint8_t* ptr
)
{
    memset(entry, 0, PE_IMAGE_MIPS_EXCEPTION_TABLE_ENTRY_SIZE);

    //if ( 32-bit MIPS )
    //{
    //    entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.BeginAddress);
    //    entry->EndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.EndAddress);
    //    entry->ExceptionHandler = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.ExceptionHandler);
    //    entry->HandlerData = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.HandlerData);
    //    entry->PrologEndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.PrologEndAddress);
    //}
    //if ( ARM, PowerPC, SH3 and SH4 Windows CE )
    //{
    //    entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.BeginAddress);
    //    entry->Flags = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEnryOffsets.Flags);
    //}
    //if ( x64 and Itanium )
    {
        entry->BeginAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.BeginAddress);
        entry->EndAddress = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.EndAddress);
        entry->UnwindInformation = GetIntXValueAtOffset(uint32_t, ptr, PeImageExceptionTableEntryOffsets.UnwindInformation);
    }

    return 0;
}





int PE_parseImageBaseRelocationTable(PE64OptHeader* oh,
                                     uint16_t nr_of_sections,
                                     SVAS* svas,
                                     uint8_t bitness,
                                     size_t start_file_offset,
                                     size_t* abs_file_offset,
                                     size_t file_size,
                                     FILE* fp,
                                     uint8_t* block_l,
                                     uint8_t* block_s)
{
    size_t table_fo;
    size_t offset;
    size_t reloc_o;
    size_t size;
    uint8_t* ptr = NULL;
    uint32_t e_i;
    uint32_t b_i = 0;

    PEDataDirectory* reloc = &oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASE_RELOC];

    PE_BASE_RELOCATION_BLOCK block;
    PE_BASE_RELOCATION_ENTRY entry;
    uint32_t nr_of_entries;

    table_fo = PE_getDataDirectoryEntryFileOffset(oh->DataDirectory, IMAGE_DIRECTORY_ENTRY_BASE_RELOC, nr_of_sections, "Base Relocation", svas);

    if (table_fo == 0)
        return -3;

    offset = table_fo;

    // read new  block to ease up offsetting
    if (!checkFileSpace(offset, start_file_offset, reloc->Size, file_size))
        return -1;

    *abs_file_offset = offset + start_file_offset;
    size = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if (size == 0)
        return -2;
    offset = 0;
    reloc_o = 0;
    
#ifdef DEBUG_PRINT_INFO
    debug_info("offset: 0x%zx\n", offset);
    debug_info("abs_file_offset: 0x%zx\n", *abs_file_offset);
    debug_info("reloc->Size: 0x%x\n", reloc->Size);
    debug_info("sizeof(PE_BASE_RELOCATION_BLOCK): 0x%zx\n", sizeof(PE_BASE_RELOCATION_BLOCK));
    debug_info("sizeof(PE_BASE_RELOCATION_ENTRY): 0x%zx\n", sizeof(PE_BASE_RELOCATION_ENTRY));
#endif

    PE_printImageBaseRelocationTable();

    while (reloc_o < reloc->Size)
    {
        if (!checkFileSpace(offset, start_file_offset, reloc->Size - reloc_o, file_size))
            return -1;
        if (!checkLargeBlockSpace(&offset, abs_file_offset, reloc->Size - reloc_o, block_l, fp))
            return -2;
        ptr = &block_l[offset];

        block.VirtualAddress = *((uint32_t*)&ptr[PeBaseRelocationBlockOffsets.VirtualAddress]);
        block.SizeOfBlock = *((uint32_t*)&ptr[PeBaseRelocationBlockOffsets.SizeOfBlock]);

        nr_of_entries = PE_numberOfRelocationEntries(block.SizeOfBlock);

        PE_printImageBaseRelocationBlockHeader(&block, b_i, start_file_offset);
#ifdef DEBUG_PRINT_INFO
        debug_info(" - VirtualAddress: 0x%x\n", block.VirtualAddress);
        debug_info(" - SizeOfBlock: 0x%x\n", block.SizeOfBlock);
        debug_info(" - nr_of_entries: 0x%x\n", nr_of_entries);
        debug_info(" - - expected new block offset: 0x%zx\n", (offset + block.SizeOfBlock));
#endif

        offset += sizeof(PE_BASE_RELOCATION_BLOCK);
        for (e_i = 0; e_i < nr_of_entries; e_i++)
        {
            ptr = &block_l[offset];

            entry.Data = 0;

            entry.Data = *((uint16_t*)&ptr[PeBaseRelocationEntryOffsets.Type]);
            
#ifdef DEBUG_PRINT_INFO
            debug_info("  - data: 0x%x\n", entry.Data);
            debug_info("  - Type: 0x%x\n", (entry.Data >> 12));
            debug_info("  - Offset: 0x%x\n", (entry.Data & 0x0FFF));
#endif

            PE_printImageBaseRelocationBlockEntry(&entry);

            offset += sizeof(PE_BASE_RELOCATION_ENTRY);
        }
        
#ifdef DEBUG_PRINT_INFO
        debug_info(" - - new block offset: 0x%zx\n", offset);
#endif
        //offset += block.SizeOfBlock;
        reloc_o += block.SizeOfBlock;
        b_i++;
    }
    printf("\n");

    return 0;
}

uint32_t PE_numberOfRelocationEntries(uint32_t SizeOfBlock)
{
    return (SizeOfBlock - sizeof(PE_BASE_RELOCATION_BLOCK)) / sizeof(PE_BASE_RELOCATION_ENTRY);
}

//typedef struct RdiData
//{
//    size_t offset;
//    uint16_t NumberOfNamedEntries;
//    uint16_t NumberOfIdEntries;
//    uint16_t level;
//} RdiData, *PRdiData;
//
//int PE_iterateImageResourceDirectory(size_t offset,
//                                     size_t table_fo,
//                                     uint16_t
//                                     nr_of_named_entries,
//                                     uint16_t nr_of_id_entries,
//                                     uint16_t level,
//                                     size_t start_file_offset,
//                                     size_t file_size,
//                                     FILE* fp,
//                                     uint8_t* block_s)
//{
//    uint16_t i;
//    int s;
//    Fifo fifo;
//    RdiData rdid;
//    PRdiData act;
//    PFifoEntryData act_e;
//
//    Fifo_init(&fifo);
//
//    rdid.offset = (size_t)offset;
//    rdid.NumberOfNamedEntries = nr_of_named_entries;
//    rdid.NumberOfIdEntries = nr_of_id_entries;
//    rdid.level = level;
//
//    Fifo_push(&fifo, &rdid, sizeof(RdiData));
//
//    while ( !Fifo_empty(&fifo) )
//    {
//        act_e = Fifo_front(&fifo);
//        act = (PRdiData)act_e->bytes;
//
//        offset = act->offset;
//        nr_of_named_entries = act->NumberOfNamedEntries;
//        nr_of_id_entries = act->NumberOfIdEntries;
//        level = act->level;
//
//        PE_printImageResourceDirectoryEntryHeader(0, nr_of_named_entries, level);
//        for ( i = 0; i < nr_of_named_entries; i++ )
//        {
//            s = PE_parseResourceDirectoryEntryI(i, offset, table_fo, nr_of_named_entries, level, start_file_offset,
//                                                file_size, fp, block_s, &fifo);
//            if ( s != 0 )
//                continue;
//
//            offset += PE_RESOURCE_ENTRY_SIZE;
//        }
//
//        PE_printImageResourceDirectoryEntryHeader(1, nr_of_id_entries, level);
//        for ( i = 0; i < nr_of_id_entries; i++ )
//        {
//            s = PE_parseResourceDirectoryEntryI(i, offset, table_fo, nr_of_id_entries, level, start_file_offset,
//                                                file_size, fp, block_s, &fifo);
//            if ( s != 0 )
//                continue;
//
//            offset += PE_RESOURCE_ENTRY_SIZE;
//        }
//
//        Fifo_pop_front(&fifo);
//    }
//
//    return 0;
//}
//
//int PE_parseResourceDirectoryEntryI(uint16_t id,
//                                   size_t offset,
//                                   size_t table_fo,
//                                   uint16_t nr_of_entries,
//                                   uint16_t level,
//                                   size_t start_file_offset,
//                                   size_t file_size,
//                                   FILE* fp,
//                                   uint8_t* block_s,
//                                   PFifo fifo)
//{
//    PE_IMAGE_RESOURCE_DIRECTORY rd;
//    PE_IMAGE_RESOURCE_DIRECTORY_ENTRY re;
//    PE_IMAGE_RESOURCE_DATA_ENTRY de;
//    RdiData rdid;
//
//    int s;
//    uint32_t dir_offset = 0;
//
//    PE_fillImageResourceDirectoryEntry(&re, offset, table_fo, start_file_offset, file_size, fp, block_s);
//    PE_printImageResourceDirectoryEntry(&re, table_fo, offset, level, id, nr_of_entries, start_file_offset, file_size, fp, block_s);
//
//    dir_offset = table_fo + re.OFFSET_UNION.DATA_STRUCT.OffsetToDirectory;
//
//    if ( re.OFFSET_UNION.DATA_STRUCT.DataIsDirectory )
//    {
//        s = PE_fillImageResourceDirectory(&rd, dir_offset, start_file_offset, file_size, fp, block_s);
//        if ( s != 0 )
//            return 1;
//        PE_printImageResourceDirectory(&rd, dir_offset, level+1);
////        PE_recurseImageResourceDirectory((size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE, table_fo, rd.NumberOfNamedEntries,
////                                         rd.NumberOfIdEntries, level + 1, start_file_offset, file_size, fp, block_s);
//        rdid.offset = (size_t)dir_offset + PE_RESOURCE_DIRECTORY_SIZE;
//        rdid.NumberOfNamedEntries = rd.NumberOfNamedEntries;
//        rdid.NumberOfIdEntries = rd.NumberOfIdEntries;
//        rdid.level = level + 1;
//
//        Fifo_push(fifo, &rdid, sizeof(RdiData));
//    }
//    else
//    {
//        PE_fillImageResourceDataEntry(&de, dir_offset, start_file_offset, file_size, fp, block_s);
//        PE_printImageResourceDataEntry(&de, dir_offset, level);
//    }
//
//    return 0;
//}

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
