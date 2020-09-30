#ifndef HEADER_PARSER_ART_ART_FILE_HEADER_H
#define HEADER_PARSER_ART_ART_FILE_HEADER_H

#include <stdint.h>

#define MAGIC_ART_BYTES_FULL_LN 8

const unsigned char MAGIC_ART_BYTES[] = {0x61, 0x72, 0x74, 0x0A}; // art\n(xxx\0 : xxx is version info and may differ)
const uint8_t MAGIC_ART_BYTES_LN = 4;

typedef struct ARTFileHeader009012
{
	char magic[MAGIC_ART_BYTES_FULL_LN]; //
	uint32_t image_begin; // Load Address of ART file (fixed)
	uint32_t image_size; // File Size
	uint32_t bitmap_off; // Offset of image bitmap
	uint32_t bitmap_size; // Size of bitma
	uint32_t checksum; // Adler32 of header
	uint32_t oat_begin; // Load address of OAT file
	uint32_t oat_data_begin; // Load address of OAT Data (Oat Begin + 0x1000)
	uint32_t oat_data_end; // Last address of OAT Data
	uint32_t oat_end; // Last address of OAT (begin + size)
	int32_t patch_delta; // Used in offset patching
	uint32_t image_roots; // Address of image roots, array of objects
	uint32_t compile_pic; // Indicates if image was compiled with position-independent-code enabled
} ARTFileHeader009012;
const uint8_t ART_FILE_HEADER_009012_SIZE = sizeof(ARTFileHeader009012);

typedef struct ARTFileHeader015
{
	char magic[MAGIC_ART_BYTES_FULL_LN]; //
	uint32_t image_begin; // Load Address of ART file (fixed)
	uint32_t image_size; // File Size
	uint32_t art_fields_offset; //
	uint32_t art_fields_size; //
	uint32_t bitmap_off; // Offset of image bitmap
	uint32_t bitmap_size; // Size of bitma
	uint32_t checksum; // Adler32 of header
	uint32_t oat_begin; // Load address of OAT file
	uint32_t oat_data_begin; // Load address of OAT Data (Oat Begin + 0x1000)
	uint32_t oat_data_end; // Last address of OAT Data
	uint32_t oat_end; // Last address of OAT (begin + size)
	int32_t patch_delta; // Used in offset patching
	uint32_t image_roots; // Address of image roots, array of objects
	uint32_t compile_pic; // Indicates if image was compiled with position-independent-code enabled
} ARTFileHeader015;
const uint8_t ART_FILE_HEADER_015_SIZE = sizeof(ARTFileHeader015);

typedef struct ARTFileHeader017
{
	char magic[MAGIC_ART_BYTES_FULL_LN]; //
	uint32_t image_begin; // Load Address of ART file (fixed)
	uint32_t image_size; // File Size
	uint32_t oat_checksum; //
	uint32_t oat_begin; // Load address of OAT file
	uint32_t oat_data_begin; // Load address of OAT Data (Oat Begin + 0x1000)
	uint32_t oat_data_end; // Last address of OAT Data
	uint32_t oat_end; // Last address of OAT (begin + size)
	int32_t patch_delta; // Used in offset patching
	uint32_t image_roots; // Address of image roots
	uint32_t size_of_pointer; //
	uint32_t compile_pic; //
	uint32_t objects_off; //
	uint32_t objects_size; //
	uint32_t fields_off; //
	uint32_t fields_size; //
	uint32_t methods_off; //
	uint32_t methods_size; //
	uint32_t strings_off; //
	uint32_t strings_size; //
	uint32_t bitmap_off; // Offset of image bitmap
	uint32_t bitmap_size; // Size of bitmat
} ARTFileHeader017;
const uint8_t ART_FILE_HEADER_017_SIZE = sizeof(ARTFileHeader017);

#endif
