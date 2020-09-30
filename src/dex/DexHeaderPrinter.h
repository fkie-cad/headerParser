#ifndef HEADER_PARSER_DEX_HEADER_PRINTER_H
#define HEADER_PARSER_DEX_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "../stringPool.h"
#include "DexFileHeader.h"

static void DEXprintFileHeader(DEXFileHeader* h);
static void DEXprintStringIdItem(DexStringIdItem* item, DexStringDataItem* data, char** strings, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintTypeIdItem(DexTypeIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintProtoIdItem(DexProtoIdItem* item, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintFieldIdItem(DexFieldIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintMethodIdItem(DexMethodIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintClassDefItem(DexClassDefItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset);
static void DEXprintMapList(DexMapList* l, uint64_t offset);
static void DEXprintMapItem(DexMapItem* i, uint32_t idx, uint32_t ln, uint64_t offset);
static char* getMapItemType(uint16_t type);

void DEXprintFileHeader(DEXFileHeader* h)
{
	int i;
	DEX_File_Header_Offsets offsets = DEXFileHeaderOffsets;

	printf("DEX File header:\n");
	printf(" - magic%s: ", fillOffset(offsets.magic, 0, start_file_offset));
	for ( i = 0; i < MAGIC_DEX_BYTES_FULL_LN; i++ )
	{
		if ( h->magic[i] == '\n' )
			printf("%s", "\\n");
		else
			printf("%c", h->magic[i]);
	}
	printf(" (0x");
	for ( i = 0; i < MAGIC_DEX_BYTES_FULL_LN; i++ )
		printf("%02x", h->magic[i]);
	printf(")\n");
	printf(" - checksum%s: 0x%x\n", fillOffset(offsets.checksum, 0, start_file_offset), h->checksum);
	printf(" - signature%s: ", fillOffset(offsets.signature, 0, start_file_offset));
	for ( i = 0; i < DEX_SIGNATURE_LN; i++ )
		printf("%02x", (unsigned char) h->signature[i]);
	printf("\n");
	printf(" - file_size%s: %u\n", fillOffset(offsets.file_size, 0, start_file_offset), h->file_size);
	printf(" - header_size%s: %u\n", fillOffset(offsets.header_size, 0, start_file_offset), h->header_size);
	printf(" - endian_tag%s: %s (0x%x)\n", fillOffset(offsets.endian_tag, 0, start_file_offset), endian_type_names[HD->endian], h->endian_tag);
	printf(" - link_size%s: %u\n", fillOffset(offsets.link_size, 0, start_file_offset), h->link_size);
	printf(" - link_off%s: 0x%x (%u)\n", fillOffset(offsets.link_off, 0, start_file_offset), h->link_off, h->link_off);
	printf(" - map_off%s: 0x%x (%u)\n", fillOffset(offsets.map_off, 0, start_file_offset), h->map_off, h->map_off);
	printf(" - string_ids_size%s: %u\n", fillOffset(offsets.string_ids_size, 0, start_file_offset), h->string_ids_size);
	printf(" - string_ids_off%s: 0x%x (%u)\n", fillOffset(offsets.string_ids_off, 0, start_file_offset), h->string_ids_off, h->string_ids_off);
	printf(" - type_ids_size%s: %u\n", fillOffset(offsets.type_ids_size, 0, start_file_offset), h->type_ids_size);
	printf(" - type_ids_off%s: 0x%x (%u)\n", fillOffset(offsets.type_ids_off, 0, start_file_offset), h->type_ids_off, h->type_ids_off);
	printf(" - proto_ids_size%s: %u\n", fillOffset(offsets.proto_ids_size, 0, start_file_offset), h->proto_ids_size);
	printf(" - proto_ids_off%s: 0x%x (%u)\n", fillOffset(offsets.proto_ids_off, 0, start_file_offset), h->proto_ids_off, h->proto_ids_off);
	printf(" - field_ids_size%s: %u\n", fillOffset(offsets.field_ids_size, 0, start_file_offset), h->field_ids_size);
	printf(" - field_ids_off%s: 0x%x (%u)\n", fillOffset(offsets.field_ids_off, 0, start_file_offset), h->field_ids_off, h->field_ids_off);
	printf(" - method_ids_size%s: %u\n", fillOffset(offsets.method_ids_size, 0, start_file_offset), h->method_ids_size);
	printf(" - method_ids_off%s: 0x%x (%u)\n", fillOffset(offsets.method_ids_off, 0, start_file_offset), h->method_ids_off, h->method_ids_off);
	printf(" - class_defs_size%s: %u\n", fillOffset(offsets.class_defs_size, 0, start_file_offset), h->class_defs_size);
	printf(" - class_defs_off%s: 0x%x (%u)\n", fillOffset(offsets.class_defs_off, 0, start_file_offset), h->class_defs_off, h->class_defs_off);
	printf(" - data_size%s: %u\n", fillOffset(offsets.data_size, 0, start_file_offset), h->data_size);
	printf(" - data_off%s: 0x%x (%u)\n", fillOffset(offsets.data_off, 0, start_file_offset), h->data_off, h->data_off);
	printf("\n");
}

void DEXprintStringIdItem(DexStringIdItem* item, DexStringDataItem* data, char** strings, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_String_Id_Item_Offsets offsets = DexStringIdItemOffsets;

	int i;
	printf(" - String Id Item (%u / %u):\n", idx, ln);
	printf(" - - string_data_offset%s: 0x%x\n", fillOffset(offsets.offset, offset, 0), item->offset);
	printf(" - - string_data:\n");
	printf(" - - - utf16_size%s: %u\n", fillOffset(DexStringDataItemOffsets.utf16_size, item->offset, start_file_offset), data->utf16_size.val);
	printf(" - - - data%s: ", fillOffset(DexStringDataItemOffsets.data, item->offset, start_file_offset));
	for ( i = 0; i < data->utf16_size.val; i++ )
		printf("%c", block_standard[i+1]);
	printf("\n");
	printf(" - - - strings[%u]%s: %s\n", idx, fillOffset(DexStringDataItemOffsets.data, item->offset, start_file_offset), strings[idx-1]);
}

void DEXprintTypeIdItem(DexTypeIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Type_Id_Item_Offsets offsets = DexTypeIdItemOffsets;

	printf(" - Type Id Item (%u / %u):\n", idx, ln);
	printf(" - - descriptor_idx%s: 0x%x\n", fillOffset(offsets.descriptor_idx, offset, 0), item->descriptor_idx);
	printf(" - - descriptor: %s\n", strings[item->descriptor_idx]);
}

void DEXprintProtoIdItem(DexProtoIdItem* item, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Proto_Id_Item_Offsets offsets = DexProtoIdItemOffsets;

	printf(" - Proto Id Item (%u / %u):\n", idx, ln);
	printf(" - - shorty_idx%s: 0x%x\n", fillOffset(offsets.shorty_idx, offset, 0), item->shorty_idx);
	printf(" - - return_type_idx%s: 0x%x\n", fillOffset(offsets.return_type_idx, offset, 0), item->return_type_idx);
	printf(" - - parameters_off%s: 0x%x\n", fillOffset(offsets.parameters_off, offset, 0), item->parameters_off);
}

void DEXprintFieldIdItem(DexFieldIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Field_Id_Item_Offsets offsets = DexFieldIdItemOffsets;

	printf(" - Field Id Item (%u / %u):\n", idx, ln);
	printf(" - - class_idx%s: 0x%x\n", fillOffset(offsets.class_idx, offset, 0), item->class_idx);
	printf(" - - type_idx%s: 0x%x\n", fillOffset(offsets.type_idx, offset, 0), item->type_idx);
	printf(" - - name_idx%s: 0x%x\n", fillOffset(offsets.name_idx, offset, 0), item->name_idx);
	printf(" - - name: %s\n", strings[item->name_idx]);
}

void DEXprintMethodIdItem(DexMethodIdItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Method_Id_Item_Offsets offsets = DexMethodIdItemOffsets;

	printf(" - Method Id Item (%u / %u):\n", idx, ln);
	printf(" - - class_idx%s: 0x%x\n", fillOffset(offsets.class_idx, offset, 0), item->class_idx);
	printf(" - - proto_idx%s: 0x%x\n", fillOffset(offsets.proto_idx, offset, 0), item->proto_idx);
	printf(" - - name_idx%s: 0x%x\n", fillOffset(offsets.name_idx, offset, 0), item->name_idx);
	printf(" - - name: %s\n", strings[item->name_idx]);
}

void DEXprintClassDefItem(DexClassDefItem* item, char** strings, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Class_Def_Item_Offsets offsets = DexClassDefItemOffsets;

	printf(" - Class Def Item (%u / %u):\n", idx, ln);
	printf(" - - class_idx%s: 0x%x\n", fillOffset(offsets.class_idx, offset, 0), item->class_idx);
	printf(" - - access_flags%s: (0x%x)", fillOffset(offsets.access_flags, offset, 0), item->access_flags);
	printFlag32(item->access_flags, ACC_ABSTRACT, "ACC_ABSTRACT");
	printFlag32(item->access_flags, ACC_ANNOTATION, "ACC_ANNOTATION");
	printFlag32(item->access_flags, ACC_BRIDGE, "ACC_BRIDGE");
	printFlag32(item->access_flags, ACC_CONSTRUCTOR, "ACC_CONSTRUCTOR");
	printFlag32(item->access_flags, ACC_DECLARED_SYNCHRONIZED, "ACC_DECLARED_SYNCHRONIZED");
	printFlag32(item->access_flags, ACC_ENUM, "ACC_ENUM");
	printFlag32(item->access_flags, ACC_FINAL, "ACC_FINAL");
	printFlag32(item->access_flags, ACC_INTERFACE, "ACC_INTERFACE");
	printFlag32(item->access_flags, ACC_NATIVE, "ACC_NATIVE");
	printFlag32(item->access_flags, ACC_PRIVATE, "ACC_PRIVATE");
	printFlag32(item->access_flags, ACC_PROTECTED, "ACC_PROTECTED");
	printFlag32(item->access_flags, ACC_PUBLIC, "ACC_PUBLIC");
	printFlag32(item->access_flags, ACC_STATIC, "ACC_STATIC");
	printFlag32(item->access_flags, ACC_STRICT, "ACC_STRICT");
	printFlag32(item->access_flags, ACC_SYNCHRONIZED, "ACC_SYNCHRONIZED");
	printFlag32(item->access_flags, ACC_SYNTHETIC, "ACC_SYNTHETIC");
	printFlag32(item->access_flags, ACC_TRANSIENT, "ACC_TRANSIENT");
	printFlag32(item->access_flags, ACC_VARARGS, "ACC_VARARGS");
	printFlag32(item->access_flags, ACC_VOLATILE, "ACC_VOLATILE");
	printf("\n");
	printf(" - - superclass_idx%s: 0x%x\n", fillOffset(offsets.superclass_idx, offset, 0), item->superclass_idx);
	printf(" - - interfaces_off%s: 0x%x\n", fillOffset(offsets.interfaces_off, offset, 0), item->interfaces_off);
	printf(" - - source_file_idx%s: 0x%x\n", fillOffset(offsets.source_file_idx, offset, 0), item->source_file_idx);
	if ( item->source_file_idx != NO_INDEX )
		printf(" - - source_file: %s\n", strings[item->source_file_idx]);
	printf(" - - annotations_off%s: 0x%x\n", fillOffset(offsets.annotations_off, offset, 0), item->annotations_off);
	printf(" - - class_data_off%s: 0x%x\n", fillOffset(offsets.class_data_off, offset, 0), item->class_data_off);
	printf(" - - static_values_off%s: 0x%x\n", fillOffset(offsets.static_values_off, offset, 0), item->static_values_off);
}

void DEXprintMapList(DexMapList* l, uint64_t offset)
{
	Dex_Map_List_Offsets offsets = DexMapListOffsets;

	printf("Map List\n");
	printf(" - size%s: %u\n", fillOffset(offsets.size, offset, 0), l->size);
}

void DEXprintMapItem(DexMapItem* i, uint32_t idx, uint32_t ln, uint64_t offset)
{
	Dex_Map_Item_Offsets offsets = DexMapItemOffsets;

	printf(" - Map Item (%u / %u):\n", idx, ln);
	printf(" - - type%s: %s (0x%x)\n", fillOffset(offsets.type, offset, 0), getMapItemType(i->type), i->type);
	printf(" - - unused%s: 0x%x\n", fillOffset(offsets.unused, offset, 0), i->unused);
	printf(" - - size%s: %u\n", fillOffset(offsets.size, offset, 0), i->size);
	printf(" - - offset%s: 0x%x\n", fillOffset(offsets.offset, offset, 0), i->offset);
}

char* getMapItemType(uint16_t type)
{
	switch (type)
	{
		case TYPE_HEADER_ITEM: return "TYPE_HEADER_ITEM";
		case TYPE_STRING_ID_ITEM: return "TYPE_STRING_ID_ITEM";
		case TYPE_TYPE_ID_ITEM: return "TYPE_TYPE_ID_ITEM";
		case TYPE_PROTO_ID_ITEM: return "TYPE_PROTO_ID_ITEM";
		case TYPE_FIELD_ID_ITEM: return "TYPE_FIELD_ID_ITEM";
		case TYPE_METHOD_ID_ITEM: return "TYPE_METHOD_ID_ITEM";
		case TYPE_CLASS_DEF_ITEM: return "TYPE_CLASS_DEF_ITEM";
		case TYPE_CALL_SITE_ID_ITEM: return "TYPE_CALL_SITE_ID_ITEM";
		case TYPE_METHOD_HANDLE_ITEM: return "TYPE_METHOD_HANDLE_ITEM";
		case TYPE_MAP_LIST: return "TYPE_MAP_LIST";
		case TYPE_TYPE_LIST: return "TYPE_TYPE_LIST";
		case TYPE_ANNOTATION_SET_REF_LIST: return "TYPE_ANNOTATION_SET_REF_LIST";
		case TYPE_ANNOTATION_SET_ITEM: return "TYPE_ANNOTATION_SET_ITEM";
		case TYPE_CLASS_DATA_ITEM: return "TYPE_CLASS_DATA_ITEM";
		case TYPE_CODE_ITEM: return "TYPE_CODE_ITEM";
		case TYPE_STRING_DATA_ITEM: return "TYPE_STRING_DATA_ITEM";
		case TYPE_DEBUG_INFO_ITEM: return "TYPE_DEBUG_INFO_ITEM";
		case TYPE_ANNOTATION_ITEM: return "TYPE_ANNOTATION_ITEM";
		case TYPE_ENCODED_ARRAY_ITEM: return "TYPE_ENCODED_ARRAY_ITEM";
		case TYPE_ANNOTATIONS_DIRECTORY_ITEM: return "TYPE_ANNOTATIONS_DIRECTORY_ITEM";
		default: return "NONE";
	}
}

#endif
