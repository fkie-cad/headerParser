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

char** strings = NULL;



static void parseDexHeader();
static void DEXfillVersion();
static void DEXreadFileHeader(DEXFileHeader *fh);
static void DEXfillStringIdItem(uint32_t offset, uint32_t idx, uint32_t size);
static void DEXfillTypeIdItem(uint32_t offset, uint32_t idx, uint32_t size);
static void DEXfillProtoIdItem(uint32_t offset, uint32_t idx, uint32_t size);
static void DEXfillFieldIdItem(uint32_t offset, uint32_t idx, uint32_t size);
static void DEXfillMethodIdItem(uint32_t offset, uint32_t idx, uint32_t size);
static void DEXfillClassDefItem(uint32_t offset, uint32_t idx, uint32_t size);
static uint8_t DEXreadMap(DEXFileHeader *fh);
static uint64_t DEXreadMapItem(uint64_t offset, uint32_t idx, uint32_t ln);
static uint8_t DEXreadItemIds(uint64_t offset, uint32_t size, uint32_t item_size, char* item_label, void (* itemFiller)(uint32_t, uint32_t, uint32_t));
static void DEXfillCodeRegion(DexMapItem* item);



void parseDexHeader()
{
	uint32_t i;
	uint8_t s;
	DEXFileHeader file_header;
	DEXfillVersion();
	DEXreadFileHeader(&file_header);

	debug_info(" - architecture: %s\n", dex_arch_id_mapper[0].arch.name);

	HD->headertype = HEADER_TYPE_DEX;
	HD->endian = ( file_header.endian_tag == DEX_ENDIAN_CONSTANT ) ? ENDIAN_LITTLE : ENDIAN_BIG;
	HD->CPU_arch = ARCH_ANDROID;
	HD->Machine = dex_arch_id_mapper[0].arch.name;
	HD->bitness = 32;

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintFileHeader(&file_header);

	if ( info_level >= INFO_LEVEL_FULL )
	{
		strings = (char**) malloc(file_header.string_ids_size*sizeof(char*));
		if ( strings == NULL )
		{
			header_error("ERROR: strings table could not be allocated!\n");
			return;
		}

		s = DEXreadItemIds(file_header.string_ids_off, file_header.string_ids_size, DEX_SIZE_OF_STRING_ID_ITEM, "String Ids", DEXfillStringIdItem);
		s = DEXreadItemIds(file_header.type_ids_off, file_header.type_ids_size, DEX_SIZE_OF_TYPE_ID_ITEM, "Type Ids", DEXfillTypeIdItem);
		s = DEXreadItemIds(file_header.proto_ids_off, file_header.proto_ids_size, DEX_SIZE_OF_PROTO_ID_ITEM, "Proto Ids", DEXfillProtoIdItem);
		s = DEXreadItemIds(file_header.field_ids_off, file_header.field_ids_size, DEX_SIZE_OF_FIELD_ID_ITEM, "Filed Ids", DEXfillFieldIdItem);
		s = DEXreadItemIds(file_header.method_ids_off, file_header.method_ids_size, DEX_SIZE_OF_METHOD_ID_ITEM, "Method Ids", DEXfillMethodIdItem);
		s = DEXreadItemIds(file_header.class_defs_off, file_header.class_defs_size, DEX_SIZE_OF_CLASS_DEF_ITEM, "Class Ids", DEXfillClassDefItem);
	}

	DEXreadMap(&file_header);

	if ( strings != NULL )
	{
		for ( i = 0; i < file_header.string_ids_size; i++ )
		{
			free(strings[i]);
		}
		free(strings);
	}
}

void DEXfillVersion()
{
	unsigned char *ptr;
	char* architecture;

	if ( !checkFileSpace(0, start_file_offset, MAGIC_DEX_BYTES_FULL_LN, "MAGIC_DEX_BYTES_FULL_LN") )
		return;

	ptr = &block_large[0];

	architecture = dex_arch_id_mapper[0].arch.name;
	architecture[24] = ptr[4];
	architecture[25] = ptr[5];
	architecture[26] = ptr[6];
}

void DEXreadFileHeader(DEXFileHeader *fh)
{
	unsigned char *ptr;
	int i;

	if ( !checkFileSpace(0, start_file_offset, DEX_FILE_HEADER_SIZE, "DEX_FILE_HEADER_SIZE") )
		return;

	ptr = &block_large[0];

	for ( i = 0; i < MAGIC_DEX_BYTES_FULL_LN; i++ )
		fh->magic[i] = ptr[DEXFileHeaderOffsets.magic + i];
	fh->checksum = *((uint32_t*) &ptr[DEXFileHeaderOffsets.checksum]);
	for ( i = 0; i < DEX_SIGNATURE_LN; i++ )
		fh->signature[i] = ptr[DEXFileHeaderOffsets.signature + i];
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

uint8_t DEXreadItemIds(uint64_t offset, uint32_t size, uint32_t item_size, char* item_label, void (* itemFiller)(uint32_t, uint32_t, uint32_t))
{
	uint32_t i;

	if ( !checkFileSpace(offset, start_file_offset, DEX_FILE_HEADER_SIZE, "DEX_FILE_HEADER_SIZE") )
		return 2;

	// read block at start to ease up offsetting
	i = readLargeBlock(file_name, offset+start_file_offset);
	if ( i == 0 )
	{
		header_error("ERROR: reading block failed.\n");
		return 1;
	}
	abs_file_offset = offset+start_file_offset;
	offset = 0;

	if ( info_level >= INFO_LEVEL_FULL )
		printf("%s (%u):\n", item_label, size);

	for ( i = 0; i < size; i++ )
	{
		if ( !checkFileSpace(offset, abs_file_offset, item_size, "item_size") )
			return 2;
		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, item_size, item_label) )
			return 3;

		itemFiller(offset, i, size);

		offset += item_size;
	}

	return 0;
}

void DEXfillStringIdItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	uint32_t r_size;
	uint32_t utf16_size;
	uint8_t utf16_size_ln;
	DexStringIdItem item;
	DexStringDataItem data;
	unsigned char* ptr = &block_large[offset];
	char* string = NULL;

	item.offset = *((uint32_t*) &ptr[DexStringIdItemOffsets.offset]);

	r_size = readBlock(file_name, item.offset+start_file_offset);
	if ( r_size == 0 )
	{
		header_error("ERROR: Reading block failed!\n");
		return;
	}

	ptr = &block_standard[0];
	utf16_size_ln = parseUleb128(ptr, DexStringDataItemOffsets.utf16_size, &utf16_size);
	data.utf16_size.val = utf16_size;
//	data.data = item.offset;

	string = (char*) malloc((data.utf16_size.val+1)*sizeof(char));
	memcpy(string, &ptr[utf16_size_ln], data.utf16_size.val);
	string[data.utf16_size.val] = 0;
	strings[idx] = string;

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintStringIdItem(&item, &data, strings, idx + 1, size, abs_file_offset+offset);
}

void DEXfillTypeIdItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	DexTypeIdItem item;
	unsigned char* ptr = &block_large[offset];

	item.descriptor_idx = *((uint32_t*) &ptr[DexTypeIdItemOffsets.descriptor_idx]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintTypeIdItem(&item, strings, idx + 1, size, abs_file_offset+offset);
}

void DEXfillProtoIdItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	DexProtoIdItem item;
	unsigned char* ptr = &block_large[offset];

	item.shorty_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.shorty_idx]);
	item.return_type_idx = *((uint32_t*) &ptr[DexProtoIdItemOffsets.return_type_idx]);
	item.parameters_off = *((uint32_t*) &ptr[DexProtoIdItemOffsets.parameters_off]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintProtoIdItem(&item, idx + 1, size, abs_file_offset+offset);
}

void DEXfillFieldIdItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	DexFieldIdItem item;
	unsigned char* ptr = &block_large[offset];

	item.class_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.class_idx]);
	item.type_idx = *((uint16_t*) &ptr[DexFieldIdItemOffsets.type_idx]);
	item.name_idx = *((uint32_t*) &ptr[DexFieldIdItemOffsets.name_idx]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintFieldIdItem(&item, strings, idx + 1, size, abs_file_offset+offset);
}

void DEXfillMethodIdItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	DexMethodIdItem item;
	unsigned char* ptr = &block_large[offset];

	item.class_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.class_idx]);
	item.proto_idx = *((uint16_t*) &ptr[DexMethodIdItemOffsets.proto_idx]);
	item.name_idx = *((uint32_t*) &ptr[DexMethodIdItemOffsets.name_idx]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintMethodIdItem(&item, strings, idx + 1, size, abs_file_offset+offset);
}

void DEXfillClassDefItem(uint32_t offset, uint32_t idx, uint32_t size)
{
	DexClassDefItem item;
	unsigned char* ptr = &block_large[offset];

	item.class_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_idx]);
	item.access_flags = *((uint32_t*) &ptr[DexClassDefItemOffsets.access_flags]);
	item.superclass_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.superclass_idx]);
	item.interfaces_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.interfaces_off]);
	item.source_file_idx = *((uint32_t*) &ptr[DexClassDefItemOffsets.source_file_idx]);
	item.annotations_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.annotations_off]);
	item.class_data_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.class_data_off]);
	item.static_values_off = *((uint32_t*) &ptr[DexClassDefItemOffsets.static_values_off]);

	// jump to class_data_off, fill class_data_item

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintClassDefItem(&item, strings, idx + 1, size, abs_file_offset+offset);
}

uint8_t DEXreadMap(DEXFileHeader *fh)
{
	unsigned char* ptr;
	uint32_t i;
	uint32_t item_size = DEX_SIZE_OF_MAP_ITEM;
	uint64_t offset = fh->map_off;
	DexMapList l;

	if ( !checkFileSpace(offset, start_file_offset, 4, "map size info") )
		return 1;

	abs_file_offset = offset+start_file_offset;
	i = readLargeBlock(file_name, abs_file_offset);
	if ( i == 0 )
	{
		header_error("ERROR: reading block failed.\n");
		return 2;
	}
	offset = 0;
	ptr = &block_large[offset];

	l.size = *((uint32_t*) &ptr[DexMapListOffsets.size]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintMapList(&l, abs_file_offset+offset);

	offset = DexMapListOffsets.map_item_list;

	for ( i = 0; i < l.size; i++ )
	{
		if ( !checkFileSpace(offset, abs_file_offset, item_size, "item_size") )
			return 3;
		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, item_size, "DEX_SIZE_OF_MAP_ITEM") )
			return 4;

		DEXreadMapItem(offset, i+1, l.size);

		offset += item_size;
	}

	return 0;
}

uint64_t DEXreadMapItem(uint64_t offset, uint32_t idx, uint32_t ln)
{
	unsigned char* ptr;
	DexMapItem item;

	ptr = &block_large[offset];

	item.type = *((uint16_t*) &ptr[DexMapItemOffsets.type]);
	item.unused = *((uint16_t*) &ptr[DexMapItemOffsets.unused]);
	item.size = *((uint32_t*) &ptr[DexMapItemOffsets.size]);
	item.offset = *((uint32_t*) &ptr[DexMapItemOffsets.offset]);

	if ( info_level >= INFO_LEVEL_FULL )
		DEXprintMapItem(&item, idx, ln, abs_file_offset+offset);

	if ( item.type == TYPE_CODE_ITEM )
	{
		DEXfillCodeRegion(&item);
	}

	return offset;
}

void DEXfillCodeRegion(DexMapItem* item)
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

	addCodeRegionDataToHeaderData(&code_region_data, HD);
}

#endif