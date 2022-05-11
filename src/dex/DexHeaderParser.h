#ifndef HEADER_PARSER_DEX_DEX_HEADER_PARSER_H
#define HEADER_PARSER_DEX_DEX_HEADER_PARSER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../ArchitectureInfo.h"
#include "../HeaderData.h"
#include "../Globals.h"
#include "../stringPool.h"
#include "../utils/common_fileio.h"
#include "../utils/Converter.h"
#include "../utils/Helper.h"

#include "DexFileHeader.h"
#include "DexHeaderOffsets.h"
#include "DexHeaderPrinter.h"


typedef void (*DEX_fillXXXIdItem)(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);


static void parseDexHeader(PHeaderData hd, PGlobalParams gp);

static void DEX_fillVersion(size_t start_file_offset, unsigned char* block, size_t file_size);
static void DEX_readFileHeader(DEXFileHeader *fh, unsigned char* block_l, size_t start_file_offset, size_t file_size);
static int DEX_readItemIds(size_t offset, uint32_t size, uint32_t item_size, char* item_label, DEX_fillXXXIdItem filler, PGlobalParams gp, char** strings, uint32_t stringsNr);

static void DEX_fillStringIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);
static void DEX_fillTypeIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);
static void DEX_fillProtoIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);
static void DEX_fillFieldIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);
static void DEX_fillMethodIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);
static void DEX_fillClassDefItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings, uint32_t stringsNr);

static int DEX_readMap(DEXFileHeader *fh, unsigned char* block_l, uint8_t info_level, size_t* abs_file_offset, size_t start_file_offset, PHeaderData hd, FILE* fp, size_t file_size);
static size_t DEX_readMapItem(size_t offset, uint32_t idx, uint32_t ln, unsigned char* block_l, uint8_t info_level, size_t abs_file_offset, PHeaderData hd);
static void DEX_fillCodeRegion(DexMapItem* item, PHeaderData hd);



void parseDexHeader(PHeaderData hd, PGlobalParams gp)
{
    uint32_t i;
    int s;
    DEXFileHeader file_header = {0};
    DEX_fillVersion(gp->file.start_offset, gp->data.block_main, gp->file.size);
    DEX_readFileHeader(&file_header, gp->data.block_main, gp->file.start_offset, gp->file.size);
    char** strings = NULL;
    size_t stringsCb;
    uint32_t stringsNr = 0;

//    debug_info(" - architecture: %s\n", dex_arch_id_mapper[0].arch.name);

    hd->headertype = HEADER_TYPE_DEX;
    hd->endian = ( file_header.endian_tag == DEX_ENDIAN_CONSTANT ) ? ENDIAN_LITTLE : ENDIAN_BIG;
    hd->CPU_arch = ARCH_ANDROID;
    hd->Machine = dex_arch_id_mapper[0].arch.name;
    hd->h_bitness = 32;
    hd->i_bitness = 32;

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printFileHeader(&file_header, hd->endian, gp->file.start_offset);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
    {
        if ( file_header.string_ids_size > 0 )
        {
            stringsNr = file_header.string_ids_size;
            stringsCb = file_header.string_ids_size*sizeof(char*);
            strings = (char**) malloc(stringsCb);
            if ( strings == NULL )
            {
                header_error("ERROR: strings table could not be allocated!\n");
                return;
            }
            memset(strings, 0, stringsCb);
        }

        s = DEX_readItemIds(file_header.string_ids_off, file_header.string_ids_size, DEX_SIZE_OF_STRING_ID_ITEM, "String Ids", DEX_fillStringIdItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading String ids failed!\n");
        }
        s = DEX_readItemIds(file_header.type_ids_off, file_header.type_ids_size, DEX_SIZE_OF_TYPE_ID_ITEM, "Type Ids", DEX_fillTypeIdItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading Type ids failed!\n");
        }
        s = DEX_readItemIds(file_header.proto_ids_off, file_header.proto_ids_size, DEX_SIZE_OF_PROTO_ID_ITEM, "Proto Ids", DEX_fillProtoIdItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading Proto ids failed!\n");
        }
        s = DEX_readItemIds(file_header.field_ids_off, file_header.field_ids_size, DEX_SIZE_OF_FIELD_ID_ITEM, "Filed Ids", DEX_fillFieldIdItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading Filed ids failed!\n");
        }
        s = DEX_readItemIds(file_header.method_ids_off, file_header.method_ids_size, DEX_SIZE_OF_METHOD_ID_ITEM, "Method Ids", DEX_fillMethodIdItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading Method ids failed!\n");
        }
        s = DEX_readItemIds(file_header.class_defs_off, file_header.class_defs_size, DEX_SIZE_OF_CLASS_DEF_ITEM, "Class Ids", DEX_fillClassDefItem, gp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading Class ids failed!\n");
        }
    }

    DEX_readMap(&file_header, gp->data.block_main, gp->info_level, &gp->file.abs_offset, gp->file.start_offset, hd, gp->file.handle, gp->file.size);

    if ( strings != NULL )
    {
        for ( i = 0; i < stringsNr; i++ )
        {
            if ( strings[i] )
                free(strings[i]);
        }
        free(strings);
    }
}

void DEX_fillVersion(size_t start_file_offset,
                     unsigned char* block,
                     size_t file_size)
{
    unsigned char *ptr;
    char* architecture;

    if ( !checkFileSpace(0, start_file_offset, MAGIC_DEX_BYTES_FULL_LN, file_size) )
        return;

    ptr = &block[0];

    architecture = dex_arch_id_mapper[0].arch.name;
    architecture[24] = (char)ptr[4];
    architecture[25] = (char)ptr[5];
    architecture[26] = (char)ptr[6];
}

void DEX_readFileHeader(DEXFileHeader *fh,
                        unsigned char* block_l,
                        size_t start_file_offset,
                        size_t file_size)
{
    unsigned char *ptr;
    int i;

    if ( !checkFileSpace(0, start_file_offset, DEX_FILE_HEADER_SIZE, file_size) )
        return;

    ptr = &block_l[0];

    for ( i = 0; i < MAGIC_DEX_BYTES_FULL_LN; i++ )
        fh->magic[i] = (char)ptr[DEXFileHeaderOffsets.magic + i];
    fh->checksum = *((uint32_t*) &ptr[DEXFileHeaderOffsets.checksum]);
    for ( i = 0; i < DEX_SIGNATURE_LN; i++ )
        fh->signature[i] = (char)ptr[DEXFileHeaderOffsets.signature + i];
    fh->file_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.file_size]);
    fh->header_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.header_size]);
    fh->endian_tag = *((uint32_t*) &ptr[DEXFileHeaderOffsets.endian_tag]);
    fh->link_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.link_size]);
    fh->link_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.link_off]);
    fh->map_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.map_off]);
    fh->string_ids_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.string_ids_size]);
    fh->string_ids_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.string_ids_off]);
    fh->type_ids_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.type_ids_size]);
    fh->type_ids_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.type_ids_off]);
    fh->proto_ids_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.proto_ids_size]);
    fh->proto_ids_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.proto_ids_off]);
    fh->field_ids_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.field_ids_size]);
    fh->field_ids_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.field_ids_off]);
    fh->method_ids_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.method_ids_size]);
    fh->method_ids_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.method_ids_off]);
    fh->class_defs_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.class_defs_size]);
    fh->class_defs_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.class_defs_off]);
    fh->data_size = *((uint32_t*) &ptr[DEXFileHeaderOffsets.data_size]);
    fh->data_off = *((uint32_t*) &ptr[DEXFileHeaderOffsets.data_off]);

//    debug_info("DEXreadFileHeader()\n");
//    debug_info(" - endian_tag: 0x%x\n",fh->endian_tag);
}

int DEX_readItemIds(size_t offset,
                        uint32_t size,
                        uint32_t item_size,
                        char* item_label,
                        DEX_fillXXXIdItem filler,
                        PGlobalParams gp,
                        char** strings,
                        uint32_t stringsNr)
{
    size_t i;

    if ( !checkFileSpace(offset, gp->file.start_offset, DEX_FILE_HEADER_SIZE, gp->file.size) )
    {
        header_error("ERROR: Data beyond file size.\n");
        return ERROR_DATA_BEYOND_FILE_SIZE;
    }

    // read block at start to ease up offsetting
//	i = readCustomBlock(gp->file_name, offset+gp->file.start_offset, BLOCKSIZE_LARGE, gp->data.block_main);
    i = readFile(gp->file.handle, offset+gp->file.start_offset, BLOCKSIZE_LARGE, gp->data.block_main);
    if ( i == 0 )
    {
        header_error("ERROR: reading block failed.\n");
        return 1;
    }
    gp->file.abs_offset = offset+gp->file.start_offset;
    offset = 0;

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        printf("%s (%u):\n", item_label, size);

    for ( i = 0; i < size; i++ )
    {
        if ( !checkFileSpace(offset, gp->file.abs_offset, item_size, gp->file.size) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }
        if ( !checkLargeBlockSpace(&offset, &gp->file.abs_offset, item_size, gp->data.block_main, gp->file.handle) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }

        filler((uint32_t)offset, (uint32_t)i, size, gp, strings, stringsNr);
        
        offset += item_size;
    }

    return 0;
}

void DEX_fillStringIdItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          char** strings,
                          uint32_t stringsNr)
{
    size_t r_size;
    uint32_t utf16_size;
    uint8_t utf16_size_ln;
    DexStringIdItem item;
    DexStringDataItem data;
    unsigned char* ptr = &gp->data.block_main[offset];
    char* string = NULL;
    size_t data_fo;

    item.offset = *((uint32_t*) &ptr[DexStringIdItemOffsets.offset]);
    data_fo = item.offset + gp->file.start_offset;

    r_size = readFile(gp->file.handle, data_fo, BLOCKSIZE_SMALL, gp->data.block_sub);
    if ( r_size == 0 )
    {
        header_error("ERROR: Reading block failed!\n");
        return;
    }

    ptr = &gp->data.block_sub[0];
    utf16_size_ln = (uint8_t)parseUleb128(ptr, DexStringDataItemOffsets.utf16_size, &utf16_size);
    data.utf16_size.val = utf16_size;
//	data.data = item.offset;

    if ( data.utf16_size.val >= BLOCKSIZE_SMALL )
    {
        header_error("ERROR: string size too big!\n")
        return;
    }
    if ( utf16_size_ln + data.utf16_size.val >= BLOCKSIZE_SMALL )
    {
        data_fo += utf16_size_ln;
        r_size = readFile(gp->file.handle, data_fo, BLOCKSIZE_SMALL, gp->data.block_sub);
        if ( r_size == 0 )
        {
            header_error("ERROR: Reading block failed!\n");
            return;
        }
        ptr = &gp->data.block_sub[0];
    }
    else
    {
        ptr = &gp->data.block_sub[utf16_size_ln];
    }

    if ( idx < stringsNr )
    {
        string = (char*) malloc((data.utf16_size.val+1)*sizeof(char));
        if ( string != NULL )
        {
            memcpy(string, ptr, data.utf16_size.val);
            string[data.utf16_size.val] = 0;
        }

        strings[idx] = string;
    }

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printStringIdItem(&item, &data, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset, gp->file.start_offset, gp->data.block_sub);
}

void DEX_fillTypeIdItem(uint32_t offset,
                        uint32_t idx,
                        uint32_t size,
                        PGlobalParams gp,
                        char** strings,
                        uint32_t stringsNr)
{
    DexTypeIdItem item;
    unsigned char* ptr = &gp->data.block_main[offset];

    item.descriptor_idx = *((uint32_t*) &ptr[DexTypeIdItemOffsets.descriptor_idx]);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printTypeIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillProtoIdItem(uint32_t offset,
                         uint32_t idx,
                         uint32_t size,
                         PGlobalParams gp,
                         char** strings,
                         uint32_t stringsNr)
{
    DexProtoIdItem item;
    unsigned char* ptr = &gp->data.block_main[offset];
    (void)strings;

    item.shorty_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.shorty_idx]);
    item.return_type_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.return_type_idx]);
    item.parameters_off = *((uint32_t*) &ptr[DexProtoIdItemOffsets.parameters_off]);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printProtoIdItem(&item, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillFieldIdItem(uint32_t offset,
                         uint32_t idx,
                         uint32_t size,
                         PGlobalParams gp,
                         char** strings,
                         uint32_t stringsNr)
{
    DexFieldIdItem item;
    unsigned char* ptr = &gp->data.block_main[offset];

    item.class_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.class_idx]);
    item.type_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.type_idx]);
    item.name_idx = *((uint32_t*) &ptr[DexFieldIdItemOffsets.name_idx]);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printFieldIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillMethodIdItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          char** strings,
                          uint32_t stringsNr)
{
    DexMethodIdItem item;
    unsigned char* ptr = &gp->data.block_main[offset];

    item.class_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.class_idx]);
    item.proto_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.proto_idx]);
    item.name_idx = *((uint32_t*) &ptr[DexMethodIdItemOffsets.name_idx]);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printMethodIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillClassDefItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          char** strings,
                          uint32_t stringsNr)
{
    DexClassDefItem item;
    unsigned char* ptr = &gp->data.block_main[offset];

    item.class_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_idx]);
    item.access_flags = *((uint32_t*) &ptr[DexClassDefItemOffsets.access_flags]);
    item.superclass_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.superclass_idx]);
    item.interfaces_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.interfaces_off]);
    item.source_file_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.source_file_idx]);
    item.annotations_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.annotations_off]);
    item.class_data_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_data_off]);
    item.static_values_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.static_values_off]);

    // jump to class_data_off, fill class_data_item

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        DEX_printClassDefItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

int DEX_readMap(DEXFileHeader *fh,
                    unsigned char* block_l,
                    uint8_t ilevel,
                    size_t* abs_file_offset,
                    size_t start_file_offset,
                    PHeaderData hd,
                    FILE* fp,
                    size_t file_size)
{
    unsigned char* ptr;
    size_t i;
    uint32_t item_size = DEX_SIZE_OF_MAP_ITEM;
    size_t offset = fh->map_off;
    DexMapList l;

    if ( !checkFileSpace(offset, start_file_offset, 4, file_size) )
    {
        header_error("ERROR: Data beyond file size.\n");
        return ERROR_DATA_BEYOND_FILE_SIZE;
    }
    *abs_file_offset = offset+start_file_offset;
//	i = readCustomBlock(file_name, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
    i = readFile(fp, (size_t)*abs_file_offset, BLOCKSIZE_LARGE, block_l);
    if ( i == 0 )
    {
        header_error("ERROR: reading block failed.\n");
        return 2;
    }
    offset = 0;
    ptr = &block_l[offset];

    l.size = *((uint32_t*) &ptr[DexMapListOffsets.size]);

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        DEX_printMapList(&l, *abs_file_offset+offset);

    offset = DexMapListOffsets.map_item_list;

    for ( i = 0; i < l.size; i++ )
    {
        if ( !checkFileSpace(offset, *abs_file_offset, item_size, file_size) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }
        if ( !checkLargeBlockSpace(&offset, abs_file_offset, item_size, block_l, fp) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }

        DEX_readMapItem(offset, (uint32_t)(i+1), l.size, block_l, ilevel, *abs_file_offset, hd);

        offset += item_size;
    }

    return 0;
}

size_t DEX_readMapItem(size_t offset,
                       uint32_t idx,
                       uint32_t ln,
                       unsigned char* block_l,
                       uint8_t ilevel,
                       size_t abs_file_offset,
                       PHeaderData hd)
{
    unsigned char* ptr;
    DexMapItem item;

    ptr = &block_l[offset];

    item.type = *((uint16_t*) &ptr[DexMapItemOffsets.type]);
    item.unused = *((uint16_t*) &ptr[DexMapItemOffsets.unused]);
    item.size = *((uint32_t*) &ptr[DexMapItemOffsets.size]);
    item.offset = *((uint32_t*) &ptr[DexMapItemOffsets.offset]);

    if ( ilevel >= INFO_LEVEL_EXTENDED )
        DEX_printMapItem(&item, idx, ln, abs_file_offset+offset);

    if ( item.type == TYPE_CODE_ITEM )
    {
        DEX_fillCodeRegion(&item, hd);
    }

    return offset;
}

void DEX_fillCodeRegion(DexMapItem* item,
                        PHeaderData hd)
{
    CodeRegionData code_region_data;
    char* name = NULL;
    memset(&code_region_data, 0, sizeof(code_region_data));

    // malloc name, to don't break pattern of other types
    name = (char*) calloc(9, sizeof(char));
    if (name)
    {
        strcpy(name, "bytecode");
        name[8] = 0;
        code_region_data.name = name;
    }
    code_region_data.start = item->offset;
    code_region_data.end = item->offset + item->size;

    addCodeRegionDataToHeaderData(&code_region_data, hd);
}

#endif