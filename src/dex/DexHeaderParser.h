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


typedef void (*DEX_fillXXXIdItem)(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);


static void parseDexHeader(PHeaderData hd, PGlobalParams gp);

static void DEX_fillVersion(uint64_t start_file_offset, unsigned char* block, size_t file_size);
static void DEX_readFileHeader(DEXFileHeader *fh, unsigned char* block_l, uint64_t start_file_offset, size_t file_size);
static uint8_t DEX_readItemIds(uint64_t offset, uint32_t size, uint32_t item_size, char* item_label, DEX_fillXXXIdItem filler, PGlobalParams gp, char** strings);

static void DEX_fillStringIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);
static void DEX_fillTypeIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);
static void DEX_fillProtoIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);
static void DEX_fillFieldIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);
static void DEX_fillMethodIdItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);
static void DEX_fillClassDefItem(uint32_t offset, uint32_t idx, uint32_t size, PGlobalParams gp, char** strings);

static uint8_t DEX_readMap(DEXFileHeader *fh, unsigned char* block_l, uint8_t info_level, uint64_t* abs_file_offset, uint64_t start_file_offset, PHeaderData hd, FILE* fp, size_t file_size);
static uint64_t DEX_readMapItem(uint64_t offset, uint32_t idx, uint32_t ln, unsigned char* block_l, uint8_t info_level, uint64_t abs_file_offset, PHeaderData hd);
static void DEX_fillCodeRegion(DexMapItem* item, PHeaderData hd);



void parseDexHeader(PHeaderData hd, PGlobalParams gp)
{
	uint32_t i;
	uint8_t s;
	DEXFileHeader file_header;
	DEX_fillVersion(gp->start_file_offset, gp->block_large, gp->file_size);
	DEX_readFileHeader(&file_header, gp->block_large, gp->start_file_offset, gp->file_size);
	char** strings = NULL;

	debug_info(" - architecture: %s\n", dex_arch_id_mapper[0].arch.name);

	hd->headertype = HEADER_TYPE_DEX;
	hd->endian = ( file_header.endian_tag == DEX_ENDIAN_CONSTANT ) ? ENDIAN_LITTLE : ENDIAN_BIG;
	hd->CPU_arch = ARCH_ANDROID;
	hd->Machine = dex_arch_id_mapper[0].arch.name;
	hd->bitness = 32;

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printFileHeader(&file_header, hd->endian, gp->start_file_offset);

	if ( gp->info_level >= INFO_LEVEL_FULL )
	{
		strings = (char**) malloc(file_header.string_ids_size*sizeof(char*));
		if ( strings == NULL )
		{
			header_error("ERROR: strings table could not be allocated!\n");
			return;
		}

		s = DEX_readItemIds(file_header.string_ids_off, file_header.string_ids_size, DEX_SIZE_OF_STRING_ID_ITEM, "String Ids", DEX_fillStringIdItem, gp, strings);
		s = DEX_readItemIds(file_header.type_ids_off, file_header.type_ids_size, DEX_SIZE_OF_TYPE_ID_ITEM, "Type Ids", DEX_fillTypeIdItem, gp, strings);
		s = DEX_readItemIds(file_header.proto_ids_off, file_header.proto_ids_size, DEX_SIZE_OF_PROTO_ID_ITEM, "Proto Ids", DEX_fillProtoIdItem, gp, strings);
		s = DEX_readItemIds(file_header.field_ids_off, file_header.field_ids_size, DEX_SIZE_OF_FIELD_ID_ITEM, "Filed Ids", DEX_fillFieldIdItem, gp, strings);
		s = DEX_readItemIds(file_header.method_ids_off, file_header.method_ids_size, DEX_SIZE_OF_METHOD_ID_ITEM, "Method Ids", DEX_fillMethodIdItem, gp, strings);
		s = DEX_readItemIds(file_header.class_defs_off, file_header.class_defs_size, DEX_SIZE_OF_CLASS_DEF_ITEM, "Class Ids", DEX_fillClassDefItem, gp, strings);
	}

	DEX_readMap(&file_header, gp->block_large, gp->info_level, &gp->abs_file_offset, gp->start_file_offset, hd, gp->fp, gp->file_size);

	if ( strings != NULL )
	{
		for ( i = 0; i < file_header.string_ids_size; i++ )
		{
			free(strings[i]);
		}
		free(strings);
	}
}

void DEX_fillVersion(uint64_t start_file_offset,
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
						uint64_t start_file_offset,
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

	debug_info("DEXreadFileHeader()\n");
	debug_info(" - endian_tag: 0x%x\n",fh->endian_tag);
}

uint8_t DEX_readItemIds(uint64_t offset,
						uint32_t size,
						uint32_t item_size,
						char* item_label,
						DEX_fillXXXIdItem filler,
						PGlobalParams gp,
						char** strings)
{
	uint32_t i;

	if ( !checkFileSpace(offset, gp->start_file_offset, DEX_FILE_HEADER_SIZE, gp->file_size) )
		return 2;

	// read block at start to ease up offsetting
//	i = readCustomBlock(gp->file_name, offset+gp->start_file_offset, BLOCKSIZE_LARGE, gp->block_large);
	i = readFile(gp->fp, offset+gp->start_file_offset, BLOCKSIZE_LARGE, gp->block_large);
	if ( i == 0 )
	{
		header_error("ERROR: reading block failed.\n");
		return 1;
	}
	gp->abs_file_offset = offset+gp->start_file_offset;
	offset = 0;

	if ( gp->info_level >= INFO_LEVEL_FULL )
		printf("%s (%u):\n", item_label, size);

	for ( i = 0; i < size; i++ )
	{
		if ( !checkFileSpace(offset, gp->abs_file_offset, item_size, gp->file_size) )
			return 2;
		if ( !checkLargeBlockSpace(&offset, &gp->abs_file_offset, item_size, gp->block_large, gp->fp) )
			return 3;

		filler(offset, i, size, gp, strings);

		offset += item_size;
	}

	return 0;
}

void DEX_fillStringIdItem(uint32_t offset,
						  uint32_t idx,
						  uint32_t size,
						  PGlobalParams gp,
						  char** strings)
{
	uint32_t r_size;
	uint32_t utf16_size;
	uint8_t utf16_size_ln;
	DexStringIdItem item;
	DexStringDataItem data;
	unsigned char* ptr = &gp->block_large[offset];
	char* string = NULL;

	item.offset = *((uint32_t*) &ptr[DexStringIdItemOffsets.offset]);

//	r_size = readCustomBlock(gp->file_name, item.offset+gp->start_file_offset, BLOCKSIZE, gp->block_standard);
	r_size = readFile(gp->fp, item.offset+gp->start_file_offset, BLOCKSIZE, gp->block_standard);
	if ( r_size == 0 )
	{
		header_error("ERROR: Reading block failed!\n");
		return;
	}

	ptr = &gp->block_standard[0];
	utf16_size_ln = parseUleb128(ptr, DexStringDataItemOffsets.utf16_size, &utf16_size);
	data.utf16_size.val = utf16_size;
//	data.data = item.offset;

	string = (char*) malloc((data.utf16_size.val+1)*sizeof(char));
	memcpy(string, &ptr[utf16_size_ln], data.utf16_size.val);
	string[data.utf16_size.val] = 0;
	strings[idx] = string;

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printStringIdItem(&item, &data, strings, idx + 1, size, gp->abs_file_offset+offset, gp->start_file_offset, gp->block_standard);
}

void DEX_fillTypeIdItem(uint32_t offset,
						uint32_t idx,
						uint32_t size,
						PGlobalParams gp,
						char** strings)
{
	DexTypeIdItem item;
	unsigned char* ptr = &gp->block_large[offset];

	item.descriptor_idx = *((uint32_t*) &ptr[DexTypeIdItemOffsets.descriptor_idx]);

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printTypeIdItem(&item, strings, idx + 1, size, gp->abs_file_offset+offset);
}

void DEX_fillProtoIdItem(uint32_t offset,
						 uint32_t idx,
						 uint32_t size,
						 PGlobalParams gp,
						 char** strings)
{
	DexProtoIdItem item;
	unsigned char* ptr = &gp->block_large[offset];

	item.shorty_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.shorty_idx]);
	item.return_type_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.return_type_idx]);
	item.parameters_off = *((uint32_t*) &ptr[DexProtoIdItemOffsets.parameters_off]);

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printProtoIdItem(&item, idx + 1, size, gp->abs_file_offset+offset);
}

void DEX_fillFieldIdItem(uint32_t offset,
						 uint32_t idx,
						 uint32_t size,
						 PGlobalParams gp,
						 char** strings)
{
	DexFieldIdItem item;
	unsigned char* ptr = &gp->block_large[offset];

	item.class_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.class_idx]);
	item.type_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.type_idx]);
	item.name_idx = *((uint32_t*) &ptr[DexFieldIdItemOffsets.name_idx]);

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printFieldIdItem(&item, strings, idx + 1, size, gp->abs_file_offset+offset);
}

void DEX_fillMethodIdItem(uint32_t offset,
						  uint32_t idx,
						  uint32_t size,
						  PGlobalParams gp,
						  char** strings)
{
	DexMethodIdItem item;
	unsigned char* ptr = &gp->block_large[offset];

	item.class_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.class_idx]);
	item.proto_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.proto_idx]);
	item.name_idx = *((uint32_t*) &ptr[DexMethodIdItemOffsets.name_idx]);

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printMethodIdItem(&item, strings, idx + 1, size, gp->abs_file_offset+offset);
}

void DEX_fillClassDefItem(uint32_t offset,
						  uint32_t idx,
						  uint32_t size,
						  PGlobalParams gp,
						  char** strings)
{
	DexClassDefItem item;
	unsigned char* ptr = &gp->block_large[offset];

	item.class_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_idx]);
	item.access_flags = *((uint32_t*) &ptr[DexClassDefItemOffsets.access_flags]);
	item.superclass_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.superclass_idx]);
	item.interfaces_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.interfaces_off]);
	item.source_file_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.source_file_idx]);
	item.annotations_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.annotations_off]);
	item.class_data_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_data_off]);
	item.static_values_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.static_values_off]);

	// jump to class_data_off, fill class_data_item

	if ( gp->info_level >= INFO_LEVEL_FULL )
		DEX_printClassDefItem(&item, strings, idx + 1, size, gp->abs_file_offset+offset);
}

uint8_t DEX_readMap(DEXFileHeader *fh,
					unsigned char* block_l,
					uint8_t info_level,
					uint64_t* abs_file_offset,
					uint64_t start_file_offset,
					PHeaderData hd,
					FILE* fp,
					size_t file_size)
{
	unsigned char* ptr;
	uint32_t i;
	uint32_t item_size = DEX_SIZE_OF_MAP_ITEM;
	uint64_t offset = fh->map_off;
	DexMapList l;

	if ( !checkFileSpace(offset, start_file_offset, 4, file_size) )
		return 1;

	*abs_file_offset = offset+start_file_offset;
//	i = readCustomBlock(file_name, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
	i = readFile(fp, *abs_file_offset, BLOCKSIZE_LARGE, block_l);
	if ( i == 0 )
	{
		header_error("ERROR: reading block failed.\n");
		return 2;
	}
	offset = 0;
	ptr = &block_l[offset];

	l.size = *((uint32_t*) &ptr[DexMapListOffsets.size]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEX_printMapList(&l, *abs_file_offset+offset);

	offset = DexMapListOffsets.map_item_list;

	for ( i = 0; i < l.size; i++ )
	{
		if ( !checkFileSpace(offset, *abs_file_offset, item_size, file_size) )
			return 3;
		if ( !checkLargeBlockSpace(&offset, abs_file_offset, item_size, block_l, fp) )
			return 4;

		DEX_readMapItem(offset, i+1, l.size, block_l, info_level, *abs_file_offset, hd);

		offset += item_size;
	}

	return 0;
}

uint64_t DEX_readMapItem(uint64_t offset,
						 uint32_t idx,
						 uint32_t ln,
						 unsigned char* block_l,
						 uint8_t info_level,
						 uint64_t abs_file_offset,
						 PHeaderData hd)
{
	unsigned char* ptr;
	DexMapItem item;

	ptr = &block_l[offset];

	item.type = *((uint16_t*) &ptr[DexMapItemOffsets.type]);
	item.unused = *((uint16_t*) &ptr[DexMapItemOffsets.unused]);
	item.size = *((uint32_t*) &ptr[DexMapItemOffsets.size]);
	item.offset = *((uint32_t*) &ptr[DexMapItemOffsets.offset]);

	if ( info_level >= INFO_LEVEL_FULL )
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
		strncpy(name, "bytecode", 8);
		code_region_data.name = name;
	}
	code_region_data.start = item->offset;
	code_region_data.end = item->offset + item->size;

	addCodeRegionDataToHeaderData(&code_region_data, hd);
}

#endif