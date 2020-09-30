#ifndef HEADER_PARSER_ART_ART_HEADER_OFFSETS_H
#define HEADER_PARSER_ART_ART_HEADER_OFFSETS_H

#include <stdint.h>

typedef struct ART_File_Header_009012_Offsets
{
	uint8_t magic; //
	uint8_t image_begin; //
	uint8_t image_size; //
	uint8_t bitmap_off; //
	uint8_t bitmap_size; //
	uint8_t checksum; // adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
	uint8_t oat_begin; //
	uint8_t oat_data_begin; //
	uint8_t oat_data_end; //
	uint8_t oat_end; //
	uint8_t patch_delta; //
	uint8_t image_roots; //
	uint8_t compile_pic; //
} ART_File_Header_009012_Offsets;

const ART_File_Header_009012_Offsets ARTFileHeader009012Offsets = {
	.magic = 0,
	.image_begin = 8,
	.image_size = 12,
	.bitmap_off = 16,
	.bitmap_size = 20,
	.checksum = 24,
	.oat_begin = 28,
	.oat_data_begin = 32,
	.oat_data_end = 36,
	.oat_end = 40,
	.patch_delta = 44,
	.image_roots = 48,
	.compile_pic = 52,
};

#endif
