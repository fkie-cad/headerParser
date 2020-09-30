#ifndef HEADER_PARSER_ART_ART_HEADER_PARSER_H
#define HEADER_PARSER_ART_ART_HEADER_PARSER_H

#include <stdint.h>

#include "ArtFileHeader.h"
#include "ArtHeaderOffsets.h"
#include "ArtHeaderPrinter.h"
#include "../ArchitectureInfo.h"
#include "../Globals.h"
#include "../utils/common_fileio.h"
#include "../utils/Helper.h"

static void parseArtHeader();
static void ARTreadFileHeader(ARTFileHeader009012 *fh);
static void ARTfillVersion();

void parseArtHeader()
{
	ARTFileHeader009012 file_header;

	ARTfillVersion();

	HD->headertype = HEADER_TYPE_ART;
//	HD->endian = ( file_header.endian_tag == ART_ENDIAN_CONSTANT ) ? ENDIAN_LITTLE : ENDIAN_BIG;
	HD->CPU_arch = ARCH_ANDROID;
	HD->Machine = art_arch_id_mapper[0].arch.name;
	HD->bitness = 32;

	ARTreadFileHeader(&file_header);

	if ( info_level >= INFO_LEVEL_FULL )
		ARTprintFileHeader009012(&file_header);
}

void ARTfillVersion()
{
	unsigned char *ptr;
	char* architecture;

	if ( !checkFileSpace(0, start_file_offset, MAGIC_ART_BYTES_FULL_LN, "MAGIC_ART_BYTES_FULL_LN") )
		return;

	ptr = &block_large[0];

	architecture = art_arch_id_mapper[0].arch.name;
	architecture[25] = ptr[4];
	architecture[26] = ptr[5];
	architecture[27] = ptr[6];
}

void ARTreadFileHeader(ARTFileHeader009012 *fh)
{
	unsigned char *ptr;
	int i;

	if ( !checkFileSpace(0, start_file_offset, ART_FILE_HEADER_009012_SIZE, "ART_FILE_HEADER_SIZE") )
		return;

	ptr = &block_large[0];

	for ( i = 0; i < MAGIC_ART_BYTES_FULL_LN; i++ )
		fh->magic[i] = ptr[ARTFileHeader009012Offsets.magic + i];
	fh->image_begin = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.image_begin]);
	fh->image_size = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.image_size]);
	fh->bitmap_off = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.bitmap_off]);
	fh->bitmap_size = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.bitmap_size]);
	fh->checksum = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.checksum]);
	fh->oat_begin = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.oat_begin]);
	fh->oat_data_begin = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.oat_data_begin]);
	fh->oat_data_end = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.oat_data_end]);
	fh->oat_end = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.oat_end]);
	fh->patch_delta = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.patch_delta]);
	fh->image_roots = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.image_roots]);
	fh->compile_pic = *((uint32_t*) &ptr[ARTFileHeader009012Offsets.compile_pic]);
}

#endif