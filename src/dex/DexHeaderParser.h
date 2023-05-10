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


typedef void (*DEX_fillXXXIdItem)(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);


static void parseDexHeader(PHeaderData hd, PGlobalParams gp, PDexParams dexp);

static void DEX_fillVersion(size_t start_file_offset, uint8_t* block, size_t file_size);

static void DEX_readFileHeader(
    DEXFileHeader *fh,
    uint8_t* block_main,
    size_t start_file_offset,
    size_t file_size,
    PDexParams dexp
);

static int DEX_readItemIds(
    size_t offset,
    uint32_t size,
    uint32_t item_size,
    char* item_label,
    DEX_fillXXXIdItem filler,
    PGlobalParams gp,
    PDexParams dexp,
    char** strings,
    uint32_t stringsNr
);

static void DEX_fillStringIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);
static void DEX_fillTypeIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);
static void DEX_fillProtoIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);
static void DEX_fillFieldIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);
static void DEX_fillMethodIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);
static void DEX_fillClassDefItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, PDexParams dexp, char** strings, uint32_t stringsNr);

static int DEX_readMap(
    DEXFileHeader *fh,
    uint8_t* block_main,
    HPFile* file,
    PHeaderData hd,
    PDexParams dexp
);
static size_t DEX_readMapItem(
    size_t offset,
    uint32_t idx,
    uint32_t ln,
    uint8_t* block_main,
    size_t abs_file_offset,
    PHeaderData hd,
    PDexParams dexp
);
static void DEX_fillCodeRegion(DexMapItem* item, PHeaderData hd);



void parseDexHeader(PHeaderData hd, PGlobalParams gp, PDexParams dexp)
{
    uint32_t i;
    int s;
    DEXFileHeader file_header = {0};
    DEX_fillVersion(gp->file.start_offset, gp->data.block_main, gp->file.size);
    DEX_readFileHeader(&file_header, gp->data.block_main, gp->file.start_offset, gp->file.size, dexp);
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

    if ( dexp->info_level & INFO_LEVEL_DEX_FILE_H )
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

        // always read string ids
        s = DEX_readItemIds(file_header.string_ids_off, file_header.string_ids_size, DEX_SIZE_OF_STRING_ID_ITEM, "String Ids", DEX_fillStringIdItem, gp, dexp, strings, stringsNr);
        if ( s != 0 )
        {
            header_info("WARNING: Reading String ids failed!\n");
        }

        if ( dexp->info_level&INFO_LEVEL_DEX_TYPE_IDS)
        {
            s = DEX_readItemIds(file_header.type_ids_off, file_header.type_ids_size, DEX_SIZE_OF_TYPE_ID_ITEM, "Type Ids", DEX_fillTypeIdItem, gp, dexp, strings, stringsNr);
            if ( s != 0 )
            {
                header_info("WARNING: Reading Type ids failed!\n");
            }
        }

        if ( dexp->info_level&INFO_LEVEL_DEX_PROTO_IDS)
        {
            s = DEX_readItemIds(file_header.proto_ids_off, file_header.proto_ids_size, DEX_SIZE_OF_PROTO_ID_ITEM, "Proto Ids", DEX_fillProtoIdItem, gp, dexp, strings, stringsNr);
            if ( s != 0 )
            {
                header_info("WARNING: Reading Proto ids failed!\n");
            }
        }

        if ( dexp->info_level&INFO_LEVEL_DEX_FIELD_IDS)
        {
            s = DEX_readItemIds(file_header.field_ids_off, file_header.field_ids_size, DEX_SIZE_OF_FIELD_ID_ITEM, "Filed Ids", DEX_fillFieldIdItem, gp, dexp, strings, stringsNr);
            if ( s != 0 )
            {
                header_info("WARNING: Reading Filed ids failed!\n");
            }
        }

        if ( dexp->info_level&INFO_LEVEL_DEX_METHOD_IDS)
        {
            s = DEX_readItemIds(file_header.method_ids_off, file_header.method_ids_size, DEX_SIZE_OF_METHOD_ID_ITEM, "Method Ids", DEX_fillMethodIdItem, gp, dexp, strings, stringsNr);
            if ( s != 0 )
            {
                header_info("WARNING: Reading Method ids failed!\n");
            }
        }

        if ( dexp->info_level&INFO_LEVEL_DEX_CLASS_DEFS)
        {
            s = DEX_readItemIds(file_header.class_defs_off, file_header.class_defs_size, DEX_SIZE_OF_CLASS_DEF_ITEM, "Class Ids", DEX_fillClassDefItem, gp, dexp, strings, stringsNr);
            if ( s != 0 )
            {
                header_info("WARNING: Reading Class ids failed!\n");
            }
        }
    }

    if ( gp->info_level == INFO_LEVEL_BASIC || dexp->info_level&INFO_LEVEL_DEX_MAP )
    {
        s = DEX_readMap(&file_header, gp->data.block_main, &gp->file, hd, dexp);
         if ( s != 0 )
        {
            header_info("WARNING: Reading Map failed!\n");
        }
    }

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
                     uint8_t* block,
                     size_t file_size)
{
    uint8_t *ptr;
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
                        uint8_t* block_main,
                        size_t start_file_offset,
                        size_t file_size,
                        PDexParams dexp)
{
    uint8_t *ptr;
    int i;

    if ( !checkFileSpace(0, start_file_offset, DEX_FILE_HEADER_SIZE, file_size) )
        return;

    ptr = &block_main[0];

    for ( i = 0; i < MAGIC_DEX_BYTES_FULL_LN; i++ )
        fh->magic[i] = (char)ptr[DEXFileHeaderOffsets.magic + i];
    fh->checksum = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.checksum);
    for ( i = 0; i < DEX_SIGNATURE_LN; i++ )
        fh->signature[i] = (char)ptr[DEXFileHeaderOffsets.signature + i];
    fh->file_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.file_size);
    fh->header_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.header_size);
    fh->endian_tag = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.endian_tag);
    fh->link_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.link_size);
    fh->link_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.link_off);
    fh->map_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.map_off);
    fh->string_ids_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.string_ids_size);
    fh->string_ids_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.string_ids_off);
    fh->type_ids_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.type_ids_size);
    fh->type_ids_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.type_ids_off);
    fh->proto_ids_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.proto_ids_size);
    fh->proto_ids_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.proto_ids_off);
    fh->field_ids_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.field_ids_size);
    fh->field_ids_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.field_ids_off);
    fh->method_ids_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.method_ids_size);
    fh->method_ids_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.method_ids_off);
    fh->class_defs_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.class_defs_size);
    fh->class_defs_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.class_defs_off);
    fh->data_size = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.data_size);
    fh->data_off = GetIntXValueAtOffset(uint32_t, ptr, DEXFileHeaderOffsets.data_off);

//    debug_info("DEXreadFileHeader()\n");
//    debug_info(" - endian_tag: 0x%x\n",fh->endian_tag);
}

int DEX_readItemIds(size_t offset,
                        uint32_t size,
                        uint32_t item_size,
                        char* item_label,
                        DEX_fillXXXIdItem filler,
                        PGlobalParams gp,
                        PDexParams dexp,
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
    i = readFile(gp->file.handle, offset+gp->file.start_offset, BLOCKSIZE_LARGE, gp->data.block_main);
    if ( i == 0 )
    {
        header_error("ERROR: reading block failed.\n");
        return 1;
    }
    gp->file.abs_offset = offset+gp->file.start_offset;
    offset = 0;

    if ( filler == DEX_fillStringIdItem && dexp->info_level&INFO_LEVEL_DEX_STRING_IDS)
        printf("%s (%u):\n", item_label, size);
    else if ( filler == DEX_fillTypeIdItem && dexp->info_level&INFO_LEVEL_DEX_TYPE_IDS)
        printf("%s (%u):\n", item_label, size);
    else if ( filler == DEX_fillProtoIdItem && dexp->info_level&INFO_LEVEL_DEX_PROTO_IDS)
        printf("%s (%u):\n", item_label, size);
    else if ( filler == DEX_fillFieldIdItem && dexp->info_level&INFO_LEVEL_DEX_FIELD_IDS)
        printf("%s (%u):\n", item_label, size);
    else if ( filler == DEX_fillMethodIdItem && dexp->info_level&INFO_LEVEL_DEX_METHOD_IDS)
        printf("%s (%u):\n", item_label, size);
    else if ( filler == DEX_fillClassDefItem && dexp->info_level&INFO_LEVEL_DEX_CLASS_DEFS)
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

        filler((uint32_t)offset, (uint32_t)i, size, gp, dexp, strings, stringsNr);
        
        offset += item_size;
    }

    return 0;
}

void DEX_fillStringIdItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          PDexParams dexp,
                          char** strings,
                          uint32_t stringsNr)
{
    size_t r_size;
    uint32_t utf16_size;
    uint8_t utf16_size_ln;
    DexStringIdItem item;
    DexStringDataItem data;
    uint8_t* ptr = &gp->data.block_main[offset];
    char* string = NULL;
    size_t data_fo;

    item.offset = GetIntXValueAtOffset(uint32_t, ptr, DexStringIdItemOffsets.offset);
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

    if ( idx < stringsNr && data.utf16_size.val )
    {
        string = (char*) malloc((data.utf16_size.val+1));
        if ( string != NULL )
        {
            // memzro(string, (data.utf16_size.val+1)); // no build warning
            memcpy(string, ptr, data.utf16_size.val);
            string[data.utf16_size.val] = 0;
        }

        strings[idx] = string;
    }

    if ( dexp->info_level & INFO_LEVEL_DEX_STRING_IDS )
        DEX_printStringIdItem(&item, &data, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset, gp->file.start_offset, gp->data.block_sub);
}

void DEX_fillTypeIdItem(uint32_t offset,
                        uint32_t idx,
                        uint32_t size,
                        PGlobalParams gp,
                        PDexParams dexp,
                        char** strings,
                        uint32_t stringsNr)
{
    DexTypeIdItem item;
    uint8_t* ptr = &gp->data.block_main[offset];

    item.descriptor_idx = GetIntXValueAtOffset(uint32_t, ptr, DexTypeIdItemOffsets.descriptor_idx);

    if ( dexp->info_level >= INFO_LEVEL_DEX_TYPE_IDS )
        DEX_printTypeIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillProtoIdItem(uint32_t offset,
                         uint32_t idx,
                         uint32_t size,
                         PGlobalParams gp,
                         DexParams* dexp,
                         char** strings,
                         uint32_t stringsNr)
{
    DexProtoIdItem item;
    uint8_t* ptr = &gp->data.block_main[offset];
    (void)strings;

    item.shorty_idx = GetIntXValueAtOffset(uint32_t, ptr, DexProtoIdItemOffsets.shorty_idx);
    item.return_type_idx = GetIntXValueAtOffset(uint32_t, ptr, DexProtoIdItemOffsets.return_type_idx);
    item.parameters_off = GetIntXValueAtOffset(uint32_t, ptr, DexProtoIdItemOffsets.parameters_off);

    if ( dexp->info_level >= INFO_LEVEL_DEX_PROTO_IDS )
        DEX_printProtoIdItem(&item, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillFieldIdItem(uint32_t offset,
                         uint32_t idx,
                         uint32_t size,
                         PGlobalParams gp,
                         PDexParams dexp,
                         char** strings,
                         uint32_t stringsNr)
{
    DexFieldIdItem item;
    uint8_t* ptr = &gp->data.block_main[offset];

    item.class_idx = GetIntXValueAtOffset(uint16_t, ptr, DexFieldIdItemOffsets.class_idx);
    item.type_idx = GetIntXValueAtOffset(uint16_t, ptr, DexFieldIdItemOffsets.type_idx);
    item.name_idx = GetIntXValueAtOffset(uint32_t, ptr, DexFieldIdItemOffsets.name_idx);

    if ( dexp->info_level >= INFO_LEVEL_DEX_FIELD_IDS )
        DEX_printFieldIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillMethodIdItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          PDexParams dexp,
                          char** strings,
                          uint32_t stringsNr)
{
    DexMethodIdItem item;
    uint8_t* ptr = &gp->data.block_main[offset];

    item.class_idx = GetIntXValueAtOffset(uint16_t, ptr, DexMethodIdItemOffsets.class_idx);
    item.proto_idx = GetIntXValueAtOffset(uint16_t, ptr, DexMethodIdItemOffsets.proto_idx);
    item.name_idx = GetIntXValueAtOffset(uint32_t, ptr, DexMethodIdItemOffsets.name_idx);

    if ( dexp->info_level >= INFO_LEVEL_DEX_METHOD_IDS )
        DEX_printMethodIdItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

void DEX_fillClassDefItem(uint32_t offset,
                          uint32_t idx,
                          uint32_t size,
                          PGlobalParams gp,
                          PDexParams dexp,
                          char** strings,
                          uint32_t stringsNr)
{
    DexClassDefItem item;
    uint8_t* ptr = &gp->data.block_main[offset];

    item.class_idx = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.class_idx);
    item.access_flags = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.access_flags);
    item.superclass_idx = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.superclass_idx);
    item.interfaces_off = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.interfaces_off);
    item.source_file_idx = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.source_file_idx);
    item.annotations_off = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.annotations_off);
    item.class_data_off = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.class_data_off);
    item.static_values_off = GetIntXValueAtOffset(uint32_t, ptr, DexClassDefItemOffsets.static_values_off);

    // jump to class_data_off, fill class_data_item

    if ( dexp->info_level & INFO_LEVEL_DEX_CLASS_DEFS )
        DEX_printClassDefItem(&item, strings, stringsNr, idx + 1, size, gp->file.abs_offset+offset);
}

int DEX_readMap(
    DEXFileHeader *fh,
    uint8_t* block_main,
    HPFile* file,
    PHeaderData hd,
    PDexParams dexp
)
{
    uint8_t* ptr;
    size_t i;
    uint32_t item_size = DEX_SIZE_OF_MAP_ITEM;
    size_t offset = fh->map_off;
    DexMapList l;

    if ( !checkFileSpace(offset, file->start_offset, 4, file->size) )
    {
        header_error("ERROR: Data beyond file size.\n");
        return ERROR_DATA_BEYOND_FILE_SIZE;
    }
    file->abs_offset = offset+file->start_offset;
    i = readFile(file->handle, (size_t)file->abs_offset, BLOCKSIZE_LARGE, block_main);
    if ( i == 0 )
    {
        header_error("ERROR: reading block failed.\n");
        return 2;
    }
    offset = 0;
    ptr = &block_main[offset];

    l.size = GetIntXValueAtOffset(uint32_t, ptr, DexMapListOffsets.size);

    if ( dexp->info_level & INFO_LEVEL_DEX_MAP )
        DEX_printMapList(&l, file->abs_offset+offset);

    offset = DexMapListOffsets.map_item_list;

    for ( i = 0; i < l.size; i++ )
    {
        if ( !checkFileSpace(offset, file->abs_offset, item_size, file->size) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }
        if ( !checkLargeBlockSpace(&offset, &file->abs_offset, item_size, block_main, file->handle) )
        {
            header_error("ERROR: Data beyond file size.\n");
            return ERROR_DATA_BEYOND_FILE_SIZE;
        }

        DEX_readMapItem(offset, (uint32_t)(i+1), l.size, block_main, file->abs_offset, hd, dexp);

        offset += item_size;
    }

    return 0;
}

size_t DEX_readMapItem(size_t offset,
                       uint32_t idx,
                       uint32_t ln,
                       uint8_t* block_main,
                       size_t abs_file_offset,
                       PHeaderData hd,
                       DexParams* dexp)
{
    uint8_t* ptr;
    DexMapItem item;

    ptr = &block_main[offset];

    item.type = GetIntXValueAtOffset(uint16_t, ptr, DexMapItemOffsets.type);
    item.unused = GetIntXValueAtOffset(uint16_t, ptr, DexMapItemOffsets.unused);
    item.size = GetIntXValueAtOffset(uint32_t, ptr, DexMapItemOffsets.size);
    item.offset = GetIntXValueAtOffset(uint32_t, ptr, DexMapItemOffsets.offset);

    if ( dexp->info_level & INFO_LEVEL_DEX_MAP )
        DEX_printMapItem(&item, idx, ln, abs_file_offset+offset);

    if ( item.type == TYPE_CODE_ITEM )
    {
        DEX_fillCodeRegion(&item, hd);
    }

    return offset;
}

#define DEX_CRN_BUFFER_SIZE (0x9)
void DEX_fillCodeRegion(DexMapItem* item,
                        PHeaderData hd)
{
    CodeRegionData code_region_data;
    char* name = NULL;
    memset(&code_region_data, 0, sizeof(code_region_data));

    // malloc name, to don't break pattern of other types
    name = (char*) calloc(DEX_CRN_BUFFER_SIZE, sizeof(char));
    if (name)
    {
        strcpy(name, "bytecode");
        name[DEX_CRN_BUFFER_SIZE-1] = 0;
        code_region_data.name = name;
    }
    code_region_data.start = item->offset;
    code_region_data.end = item->offset + item->size;

    addCodeRegionDataToHeaderData(&code_region_data, hd);
}
#undef DEX_CRN_BUFFER_SIZE

#endif