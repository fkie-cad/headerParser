#ifndef HEADER_PARSER_ART_ART_HEADER_PRINTER_H
#define HEADER_PARSER_ART_ART_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "../stringPool.h"
#include "ArtFileHeader.h"
#include "../utils/Helper.h"

void ARTprintFileHeader009012(ARTFileHeader009012* h, uint64_t start_file_offset);

void ARTprintFileHeader009012(ARTFileHeader009012* h, uint64_t start_file_offset)
{
	int i;
	ART_File_Header_009012_Offsets offsets = ARTFileHeader009012Offsets;

	printf("ART File header:\n");
	printf(" - magic%s: ", fillOffset(offsets.magic, 0, start_file_offset));
	for ( i = 0; i < MAGIC_ART_BYTES_FULL_LN; i++ )
	{
		if ( h->magic[i] == '\n' )
			printf("%s", "\\n");
		else
			printf("%c", h->magic[i]);
	}
	printf(" (0x");
	for ( i = 0; i < MAGIC_ART_BYTES_FULL_LN; i++ )
		printf("%02x", h->magic[i]);
	printf(")\n");
	printf(" - image_begin%s: 0x%x (%u)\n", fillOffset(offsets.image_begin, 0, start_file_offset), h->image_begin, h->image_begin);
	printf(" - image_size%s: 0x%x (%u)\n", fillOffset(offsets.image_size, 0, start_file_offset), h->image_size, h->image_size);
	printf(" - bitmap_off%s: 0x%x (%u)\n", fillOffset(offsets.bitmap_off, 0, start_file_offset), h->bitmap_off, h->bitmap_off);
	printf(" - bitmap_size%s: 0x%x (%u)\n", fillOffset(offsets.bitmap_size, 0, start_file_offset), h->bitmap_size, h->bitmap_size);
	printf(" - checksum%s: 0x%x\n", fillOffset(offsets.checksum, 0, start_file_offset), h->checksum);
	printf(" - oat_begin%s: 0x%x (%u)\n", fillOffset(offsets.oat_begin, 0, start_file_offset), h->oat_begin, h->oat_begin);
	printf(" - oat_data_begin%s: 0x%x (%u)\n", fillOffset(offsets.oat_data_begin, 0, start_file_offset), h->oat_data_begin, h->oat_data_begin);
	printf(" - oat_data_end%s: 0x%x (%u)\n", fillOffset(offsets.oat_data_end, 0, start_file_offset), h->oat_data_end, h->oat_data_end);
	printf(" - oat_end%s: 0x%x (%u)\n", fillOffset(offsets.oat_end, 0, start_file_offset), h->oat_end, h->oat_end);
	printf(" - patch_delta%s: 0x%x (%u)\n", fillOffset(offsets.patch_delta, 0, start_file_offset), h->patch_delta, h->patch_delta);
	printf(" - image_roots%s: 0x%x (%u)\n", fillOffset(offsets.image_roots, 0, start_file_offset), h->image_roots, h->image_roots);
	printf(" - compile_pic%s: 0x%x (%u)\n", fillOffset(offsets.compile_pic, 0, start_file_offset), h->compile_pic, h->compile_pic);
	printf("\n");
}

#endif