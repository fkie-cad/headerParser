#ifndef HEADER_PARSER_DEX_DEX_HEADER_OFFSETS_H
#define HEADER_PARSER_DEX_DEX_HEADER_OFFSETS_H

#include <stdint.h>

typedef struct DEX_File_Header_Offsets
{
	uint8_t magic; //
	uint8_t checksum; // adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
	uint8_t signature; // SHA-1 signature (hash) of the rest of the file (everything but magic, checksum, and this field); used to uniquely identify files
	uint8_t file_size; // size of the entire file (including the header), in bytes
	uint8_t header_size; // = 0x70 	size of the header (this entire section), in bytes. This allows for at least a limited amount of backwards/forwards compatibility without invalidating the format.
	uint8_t endian_tag; // = ENDIAN_CONSTANT 	endianness tag. See discussion above under "ENDIAN_CONSTANT and REVERSE_ENDIAN_CONSTANT" for more details.
	uint8_t link_size; // size of the link section, or 0 if this file isn't statically linked
	uint8_t link_off; // offset from the start of the file to the link section, or 0 if link_size == 0. The offset, if non-zero, should be to an offset into the link_data section. The format of the data pointed at is left unspecified by this document; this header field (and the previous) are left as hooks for use by runtime implementations.
	uint8_t map_off; // offset from the start of the file to the map item. The offset, which must be non-zero, should be to an offset into the data section, and the data should be in the format specified by "map_list" below.
	uint8_t string_ids_size; // count of strings in the string identifiers list
	uint8_t string_ids_off; // offset from the start of the file to the string identifiers list, or 0 if string_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the string_ids section.
	uint8_t type_ids_size; // count of elements in the type identifiers list, at most 65535
	uint8_t type_ids_off; // offset from the start of the file to the type identifiers list, or 0 if type_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the type_ids section.
	uint8_t proto_ids_size; // count of elements in the prototype identifiers list, at most 65535
	uint8_t proto_ids_off; // offset from the start of the file to the prototype identifiers list, or 0 if proto_ids_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the proto_ids section.
	uint8_t field_ids_size; // count of elements in the field identifiers list
	uint8_t field_ids_off; // offset from the start of the file to the field identifiers list, or 0 if field_ids_size == 0. The offset, if non-zero, should be to the start of the field_ids section.
	uint8_t method_ids_size; // count of elements in the method identifiers list
	uint8_t method_ids_off; // offset from the start of the file to the method identifiers list, or 0 if method_ids_size == 0. The offset, if non-zero, should be to the start of the method_ids section.
	uint8_t class_defs_size; // count of elements in the class definitions list
	uint8_t class_defs_off; // offset from the start of the file to the class definitions list, or 0 if class_defs_size == 0 (admittedly a strange edge case). The offset, if non-zero, should be to the start of the class_defs section.
	uint8_t data_size; // Size of data section in bytes. Must be an even multiple of sizeof(uint8_t).
	uint8_t data_off; // offset from the start of the file to the start of the data section.
} DEX_File_Header_Offsets;

const DEX_File_Header_Offsets DEXFileHeaderOffsets = {
	.magic = 0,
	.checksum = 8,
	.signature = 12,
	.file_size = 32,
	.header_size = 36,
	.endian_tag = 40,
	.link_size = 44,
	.link_off = 48,
	.map_off = 52,
	.string_ids_size = 56,
	.string_ids_off = 60,
	.type_ids_size = 64,
	.type_ids_off = 68,
	.proto_ids_size = 72,
	.proto_ids_off = 76,
	.field_ids_size = 80,
	.field_ids_off = 84,
	.method_ids_size = 88,
	.method_ids_off = 92,
	.class_defs_size = 96,
	.class_defs_off = 100,
	.data_size = 104,
	.data_off = 108,
};

typedef struct Dex_String_Id_Item_Offsets {
	uint8_t offset;
} Dex_String_Id_Item_Offsets;

const Dex_String_Id_Item_Offsets DexStringIdItemOffsets = {
	.offset = 0,
};

typedef struct Dex_String_Data_Item_Offsets {
	uint8_t utf16_size;
	uint8_t data;
} Dex_String_Data_Item_Offsets;

const Dex_String_Data_Item_Offsets DexStringDataItemOffsets = {
	.utf16_size = 0,
	.data = 1,// [1,5]
};

typedef struct Dex_Type_Id_Item_Offsets {
	uint8_t descriptor_idx;
} Dex_Type_Id_Item_Offsets;

const Dex_Type_Id_Item_Offsets DexTypeIdItemOffsets = {
	.descriptor_idx = 0,
};

typedef struct Dex_Proto_Id_Item_Offsets {
	uint32_t shorty_idx;
	uint32_t return_type_idx;
	uint32_t parameters_off;
} Dex_Proto_Id_Item_Offsets;

const Dex_Proto_Id_Item_Offsets DexProtoIdItemOffsets = {
	.shorty_idx = 0,
	.return_type_idx = 4,
	.parameters_off = 8,
};

typedef struct Dex_Field_Id_Item_Offsets {
	uint32_t class_idx;
	uint32_t type_idx;
	uint32_t name_idx;
} Dex_Field_Id_Item_Offsets;

const Dex_Field_Id_Item_Offsets DexFieldIdItemOffsets = {
	.class_idx = 0,
	.type_idx = 2,
	.name_idx = 4,
};

typedef struct Dex_Method_Id_Item_Offsets {
	uint32_t class_idx;
	uint32_t proto_idx;
	uint32_t name_idx;
} Dex_Method_Id_Item_Offsets;

const Dex_Method_Id_Item_Offsets DexMethodIdItemOffsets = {
	.class_idx = 0,
	.proto_idx = 2,
	.name_idx = 4,
};

typedef struct Dex_Class_Def_Item_Offsets {
	uint32_t class_idx;
	uint32_t access_flags;
	uint32_t superclass_idx;
	uint32_t interfaces_off;
	uint32_t source_file_idx;
	uint32_t annotations_off;
	uint32_t class_data_off;
	uint32_t static_values_off;
} Dex_Class_Def_Item_Offsets;

const Dex_Class_Def_Item_Offsets DexClassDefItemOffsets = {
	.class_idx = 0,
	.access_flags = 4,
	.superclass_idx = 8,
	.interfaces_off = 12,
	.source_file_idx = 16,
	.annotations_off = 20,
	.class_data_off = 24,
	.static_values_off = 28,
};

typedef struct Dex_Map_Item_Offsets {
	uint8_t type;
	uint8_t unused;
	uint8_t size;
	uint8_t offset;
} Dex_Map_Item_Offsets;

const Dex_Map_Item_Offsets DexMapItemOffsets = {
	.type = 0,
	.unused = 2,
	.size = 4,
	.offset = 8,
};

typedef struct Dex_Map_List_Offsets {
	uint8_t size;
	uint8_t map_item_list;
} Dex_Map_List_Offsets;

const Dex_Map_List_Offsets DexMapListOffsets = {
	.size = 0,
	.map_item_list = 4
};

#endif
