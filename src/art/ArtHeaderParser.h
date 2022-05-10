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



static void parseArtHeader(PHeaderData hd, PGlobalParams gp);
static void ARTfillVersion(size_t start_file_offset, size_t file_size, unsigned char* block);
static void ARTreadFileHeader(ARTFileHeader009012 *fh, size_t start_file_offset, size_t file_size, unsigned char* block);



void parseArtHeader(PHeaderData hd, PGlobalParams gp)
{
    ARTFileHeader009012 file_header;

    ARTfillVersion(gp->file.start_offset, gp->file.size, gp->data.block_main);

    hd->headertype = HEADER_TYPE_ART;
//	hd->endian = ( file_header.endian_tag == ART_ENDIAN_CONSTANT ) ? ENDIAN_LITTLE : ENDIAN_BIG;
    hd->CPU_arch = ARCH_ANDROID;
    hd->Machine = art_arch_id_mapper[0].arch.name;
    hd->h_bitness = 32;
    hd->i_bitness = 32;

    ARTreadFileHeader(&file_header, gp->file.start_offset, gp->file.size, gp->data.block_main);

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        ARTprintFileHeader009012(&file_header, gp->file.start_offset);
}

void ARTfillVersion(size_t start_file_offset, size_t file_size, unsigned char* block)
{
    unsigned char *ptr;
    char* architecture;

    if ( !checkFileSpace(0, start_file_offset, MAGIC_ART_BYTES_FULL_LN, file_size) )
        return;

    ptr = &block[0];

    architecture = art_arch_id_mapper[0].arch.name;
    architecture[25] = (char) ptr[4];
    architecture[26] = (char) ptr[5];
    architecture[27] = (char) ptr[6];
}

void ARTreadFileHeader(ARTFileHeader009012 *fh, size_t start_file_offset, size_t file_size, unsigned char* block)
{
    unsigned char *ptr;
    int i;

    if ( !checkFileSpace(0, start_file_offset, ART_FILE_HEADER_009012_SIZE, file_size) )
        return;

    ptr = &block[0];

    for ( i = 0; i < MAGIC_ART_BYTES_FULL_LN; i++ )
        fh->magic[i] = (char)ptr[ARTFileHeader009012Offsets.magic + i];
    fh->image_begin = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.image_begin);
    fh->image_size = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.image_size);
    fh->bitmap_off = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.bitmap_off);
    fh->bitmap_size = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.bitmap_size);
    fh->checksum = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.checksum);
    fh->oat_begin = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.oat_begin);
    fh->oat_data_begin = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.oat_data_begin);
    fh->oat_data_end = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.oat_data_end);
    fh->oat_end = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.oat_end);
    fh->patch_delta = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.patch_delta);
    fh->image_roots = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.image_roots);
    fh->compile_pic = GetIntXValueAtOffset(uint32_t, ptr, ARTFileHeader009012Offsets.compile_pic);
}

#endif