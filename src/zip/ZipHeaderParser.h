#ifndef HEADER_PARSER_ZIP_HEADER_PARSER_H
#define HEADER_PARSER_ZIP_HEADER_PARSER_H

#include "../utils/common_fileio.h"
#include "../utils/blockio.h"
#include "../utils/Helper.h"
#include "../stringPool.h"
#include "../ArchitectureInfo.h"
#include "ZipHeader.h"
#include "ZipHeaderOffsets.h"
#include "ZipHeaderPrinter.h"



static void parseZip(PHeaderData hd, PGlobalParams gp);

static size_t ZIP_handleFileRecord(size_t offset,
                                     uint16_t* found_needles,
                                     uint32_t record_count,
                                     size_t* abs_file_offset,
                                     size_t file_size,
                                     uint8_t ilevel,
                                     FILE* fp,
                                     unsigned char* block_s,
                                     unsigned char* block_l);
static size_t ZIP_fillRecored(ZipFileRecord* fr,
                              const unsigned char* ptr,
                              size_t offset,
                              size_t abs_file_offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_s);
static uint8_t ZIP_usesDataDescritpor(const ZipFileRecord* fr);
static size_t ZIP_findDataDescriptionOffset(size_t offset,
                                              ZipFileRecord* fr,
                                              size_t abs_file_offset,
                                              size_t file_size,
                                              FILE* fp,
                                              unsigned char* block_s);
static size_t ZIP_handleDirEntry(size_t offset,
                                   uint16_t* found_needles,
                                   uint32_t record_count,
                                   size_t* abs_file_offset,
                                   size_t file_size,
                                   uint8_t ilevel,
                                   FILE* fp,
                                   unsigned char* block_s,
                                   unsigned char* block_l);
static void ZIP_fillDirEntry(ZipDirEntry* de,
                             const unsigned char* ptr);
static size_t ZIP_handleEndLocator(size_t offset,
                                     size_t* abs_file_offset,
                                     size_t file_size,
                                     uint8_t ilevel,
                                     FILE* fp,
                                     unsigned char* block_s,
                                     unsigned char* block_l);
static void ZIP_fillEndLocator(ZipEndLocator* r, const unsigned char* ptr);
static uint8_t ZIP_checkNameOfRecord(const unsigned char* ptr, uint16_t frFileNameLength, const char* expected);
static uint8_t ZIP_nameHasFileType(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle);
static uint8_t ZIP_nameStartsWith(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle);
static uint8_t ZIP_checkNeedles(ZipFileRecord* r,
                                size_t offset,
                                uint16_t* found_needles,
                                uint32_t record_count,
                                size_t abs_file_offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s,
                                unsigned char* block_l);
static uint8_t isJar(const uint16_t found_needles[4]);



void parseZip(PHeaderData hd, PGlobalParams gp)
{
    size_t offset = 0;
    uint32_t record_count = 0;
    uint32_t dir_count = 0;
    uint16_t found_needles[5] = {0};

    debug_info("parseZip\n");

    while ( 1 )
    {
        if ( !checkFileSpace(offset, gp->abs_file_offset, MAGIC_ZIP_BYTES_LN, gp->file_size) )
            break;
        if ( !checkLargeBlockSpace(&offset, &gp->abs_file_offset, MAGIC_ZIP_BYTES_LN, gp->block_large, gp->fp))
            break;

        debug_info("magic: %02x%02x%02x%02x\n", gp->block_large[offset], gp->block_large[offset+1], gp->block_large[offset+2], gp->block_large[offset+3]);
        debug_info("offset: 0x%zx\n", offset);
        debug_info("abs_file_offset: 0x%zx\n", gp->abs_file_offset);

        if ( checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &gp->block_large[offset]) )
        {
            debug_info("record: %u\n", record_count);
            offset = ZIP_handleFileRecord(offset, found_needles, record_count, &gp->abs_file_offset, gp->file_size,
                                 gp->info_level, gp->fp, gp->block_standard, gp->block_large);
            if ( offset == UINT64_MAX )
                break;

            record_count++;
        }
        else if ( gp->info_level == INFO_LEVEL_BASIC )
        {
            break;
        }
        else if ( checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &gp->block_large[offset]) )
        {
            debug_info("dir: %u\n", dir_count);
            offset = ZIP_handleDirEntry(offset, found_needles, dir_count, &gp->abs_file_offset, gp->file_size, gp->info_level,
                               gp->fp, gp->block_standard, gp->block_large);
            if ( offset == UINT64_MAX )
                break;

            dir_count++;
        }
        else if ( checkBytes(MAGIC_ZIP_END_LOCATOR_BYTES, MAGIC_ZIP_BYTES_LN, &gp->block_large[offset]) )
        {
            debug_info("The end!\n");
            offset = ZIP_handleEndLocator(offset, &gp->abs_file_offset, gp->file_size, gp->info_level, gp->fp,
                                 gp->block_standard, gp->block_large);
            break;
        }
        else
        {
            break;
        }

        if ( gp->abs_file_offset + offset > gp->file_size )
        {
            header_info("INFO: Reached end of file.\n");
            break;
        }
    }

    if ( isJar(found_needles) )
    {
        hd->headertype = HEADER_TYPE_JAR;
        hd->CPU_arch = ARCH_JAVA;
        hd->Machine = "Jar Archive";
    }
    else if ( found_needles[3] > 0 )
    {
        hd->headertype = HEADER_TYPE_WORD_DOC_X;
        hd->CPU_arch = ARCH_UNSUPPORTED;
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
    }
    else if ( found_needles[4] > 0 )
    {
        hd->headertype = HEADER_TYPE_APK;
        hd->CPU_arch = ARCH_ANDROID;
        // TODO: find classes.dex and parse
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
    }
    else
    {
        hd->headertype = HEADER_TYPE_ZIP;
        hd->CPU_arch = ARCH_UNSUPPORTED;
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
    }
}

size_t ZIP_handleFileRecord(size_t offset,
                              uint16_t* found_needles,
                              uint32_t record_count,
                              size_t* abs_file_offset,
                              size_t file_size,
                              uint8_t ilevel,
                              FILE* fp,
                              unsigned char* block_s,
                              unsigned char* block_l)
{
    ZipFileRecord fr = {0};
    unsigned char* ptr;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_RECORD;
    size_t dd_offset;

    if ( !checkFileSpace(offset, *abs_file_offset, size_of_entry, file_size) )
        return UINT64_MAX;
    debug_info("offset: 0x%zx\n", offset);
    if ( !checkLargeBlockSpace(&offset, abs_file_offset, size_of_entry, block_l, fp) )
        return UINT64_MAX;

    ptr = &block_l[offset];

    dd_offset = ZIP_fillRecored(&fr, ptr, offset, *abs_file_offset, file_size, fp, block_s);

    if ( ilevel >= INFO_LEVEL_FULL )
        ZIP_printFileEntry(&fr, ptr, record_count, *abs_file_offset + offset, dd_offset, file_size, fp, block_s);

    ZIP_checkNeedles(&fr, offset, found_needles, record_count, *abs_file_offset, file_size, fp, block_s, block_l);

    debug_info(" - - - frDataDescr.ddCompressedSize: 0x%x (%u)\n", fr.dataDescr.ddCompressedSize, fr.dataDescr.ddCompressedSize);
    offset += fr.compressedSize + fr.fileNameLength + fr.extraFieldLength + size_of_entry;
//	offset += size_of_entry + ((fr.compressedSize > 0) ? fr.compressedSize : fr.uncompressedSize) + fr.fileNameLength + fr.extraFieldLength;
    debug_info(" - abs_file_offset+offset: 0x%zx + 0x%zx =  0x%zx\n", *abs_file_offset, offset, (*abs_file_offset+offset));
    if ( ZIP_usesDataDescritpor(&fr) )
        offset = dd_offset + SIZE_OF_ZIP_DATA_DESCRIPTION - *abs_file_offset;
//		offset += SIZE_OF_ZIP_DATA_DESCRIPTION;
//		if ( fr.compressedSize == 0 )
//			offset += fr.dataDescr.ddCompressedSize;

    debug_info(" - abs_file_offset+offset: 0x%zx + 0x%zx =  0x%zx\n", *abs_file_offset, offset, (*abs_file_offset+offset));
    debug_info(" - offset += dd_offset + SIZE_OF_ZIP_DATA_DESCRIPTION - abs_file_offset: 0x%zx+ 0x%x - 0x%zx =  0x%zx\n",
            dd_offset, SIZE_OF_ZIP_DATA_DESCRIPTION, *abs_file_offset, (dd_offset+ SIZE_OF_ZIP_DATA_DESCRIPTION- *abs_file_offset));


    return offset;
}

size_t ZIP_fillRecored(ZipFileRecord* fr,
                       const unsigned char* ptr,
                       size_t offset,
                       size_t abs_file_offset,
                       size_t file_size,
                       FILE* fp,
                       unsigned char* block_s)
{
    size_t dd_offset = 0;
    int i;
    size_t r_size;

    for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
        fr->signature[i] = (char)ptr[ZipFileRecoredOffsets.signature + i];
    fr->version.version = GetIntXValueAtOffset(uint8_t, ptr, (ZipFileRecoredOffsets.version + ZipVersionOffsets.version));
    fr->version.hostOs = GetIntXValueAtOffset(uint8_t, ptr, (ZipFileRecoredOffsets.version + ZipVersionOffsets.hostOs));
    fr->flags = GetIntXValueAtOffset(uint16_t, ptr, ZipFileRecoredOffsets.flags);
    fr->compression = GetIntXValueAtOffset(uint16_t, ptr, ZipFileRecoredOffsets.compression);
    fr->compressedSize = GetIntXValueAtOffset(uint32_t, ptr, ZipFileRecoredOffsets.compressedSize);
    fr->uncompressedSize = GetIntXValueAtOffset(uint32_t, ptr, ZipFileRecoredOffsets.uncompressedSize);
    fr->fileNameLength = GetIntXValueAtOffset(uint16_t, ptr, ZipFileRecoredOffsets.fileNameLength);
    fr->extraFieldLength = GetIntXValueAtOffset(uint16_t, ptr, ZipFileRecoredOffsets.extraFieldLength);

//	debug_info(" - - frFlags: %u\n", r->frFlags);
//	debug_info(" - - frVersion.version: %u\n", r->frVersion.version);
//	debug_info(" - - frVersion.hostOs: %u\n", r->frVersion.hostOs);
//	debug_info(" - - frCompressedSize: %u\n", r->frCompressedSize);
//	debug_info(" - - frFileNameLength: %u\n", r->frFileNameLength);
//	debug_info(" - - frExtraFieldLength: %u\n", r->frExtraFieldLength);

    if ( ZIP_usesDataDescritpor(fr) )
    {
        dd_offset = (size_t)ZIP_findDataDescriptionOffset(offset, fr, abs_file_offset, file_size, fp, block_s);
//		dd_offset = ZIP_findDataDescriptionOffset(offset + fr->fileNameLength + ZipFileRecoredOffsets.fileName);
//		uint32_t r_size = readCustomBlock(file_name, dd_offset, BLOCKSIZE, block_s);
        r_size = readFile(fp, dd_offset, BLOCKSIZE, block_s);
        if ( r_size == 0 )
            return 0;
        debug_info(" - - dd_offset: 0x%zx\n", dd_offset);
        debug_info(" - - abs_file_offset +  dd_offset: 0x%zx\n", abs_file_offset + dd_offset);
        if ( dd_offset < UINT64_MAX )
        {
            ptr = &block_s[0];

            if ( checkBytes(MAGIC_ZIP_DATA_DESCRIPTOR_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[0]) )
            {
                fr->dataDescr.ddSignature[0] =  *((uint8_t*) &ptr[ZipDataDescriptionOffsets.signature + 0]);
                fr->dataDescr.ddSignature[1] =  *((uint8_t*) &ptr[ZipDataDescriptionOffsets.signature + 1]);
                fr->dataDescr.ddSignature[2] =  *((uint8_t*) &ptr[ZipDataDescriptionOffsets.signature + 2]);
                fr->dataDescr.ddSignature[3] =  *((uint8_t*) &ptr[ZipDataDescriptionOffsets.signature + 3]);
                fr->dataDescr.ddCRC = *((uint32_t*) &ptr[ZipDataDescriptionOffsets.crc]);
                fr->dataDescr.ddCompressedSize =  *((uint32_t*) &ptr[ZipDataDescriptionOffsets.compressedSize]);
                fr->dataDescr.ddUncompressedSize =  *((uint32_t*) &ptr[ZipDataDescriptionOffsets.uncompressedSize]);
            }
            else
            {
                fr->dataDescr.ddSignature[0] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[0];
                fr->dataDescr.ddSignature[1] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[1];
                fr->dataDescr.ddSignature[2] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[2];
                fr->dataDescr.ddSignature[3] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[3];
                fr->dataDescr.ddCRC = *((uint32_t*) &ptr[ZipDataDescriptionOffsets.crc - 4]);
                fr->dataDescr.ddCompressedSize =  *((uint32_t*) &ptr[ZipDataDescriptionOffsets.compressedSize - 4]);
                fr->dataDescr.ddUncompressedSize =  *((uint32_t*) &ptr[ZipDataDescriptionOffsets.uncompressedSize - 4]);

                dd_offset -= 4;
            }
        }

//		debug_info(" - - frDataDescr.ddCRC: %u\n", r->frDataDescr.ddCRC);
//		debug_info(" - - frDataDescr.ddCompressedSize: %u\n", r->frDataDescr.ddCompressedSize);
//		debug_info(" - - frDataDescr.ddUncompressedSize: %u\n", r->frDataDescr.ddUncompressedSize);
    }

    return dd_offset;
}

/**
 * This descriptor MUST exist if bit 3 of the general purpose bit flag is set (see below)
 * It is byte aligned and immediately follows the last byte of compressed data.
 *
 * @param fr ZipFileRecord*
 * @return uint8 bool value
 */
uint8_t ZIP_usesDataDescritpor(const ZipFileRecord* fr)
{
    return hasFlag16(fr->flags, ZipFlagTypes.FLAG_DescriptorUsedMask);
//	return r->frVersion.version >= ZIP_VS_2_0 && hasFlag16(r->frFlags, ZipFlagTypes.FLAG_DescriptorUsedMask);
}

/**
 * It is byte aligned and immediately follows the last byte of compressed data.
 * Although not originally assigned a signature,
 * the value 0x08074b50 has commonly been adopted as a signature value for the data descriptor record.
 * Implementers SHOULD be aware that ZIP files MAY be encountered with or without this signature marking data descriptors
 *
 * @param start_i
 * @return
 */
size_t ZIP_findDataDescriptionOffset(size_t offset,
                                       ZipFileRecord* fr,
                                       size_t abs_file_offset,
                                       size_t file_size,
                                       FILE* fp,
                                       unsigned char* block_s)
{
    size_t dd_offset;
    size_t f_offset;
    const unsigned char* ptr;
    size_t r_size;
    size_t bytes_searched = 0;

    if ( fr->compressedSize != 0 )
    {
        // if compressed size, dd should immediately follow ?
        dd_offset =  abs_file_offset + offset + MIN_SIZE_OF_ZIP_RECORD + fr->compressedSize + fr->fileNameLength + fr->extraFieldLength;

        r_size = readFile(fp, (size_t)dd_offset, BLOCKSIZE, block_s);
        if ( r_size == 0 )
            return UINT64_MAX;
        ptr = &block_s[0];

        // if magic dd bytes fit, return
        if ( checkBytes(MAGIC_ZIP_DATA_DESCRIPTOR_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[0])
            &&
            (checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION])
             ||
             checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION]))
            )
            return dd_offset;
        // if not, i.e. magic bytes may not be used, check if a file or dir entry follows directly, and return, if so
        else if ( checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION-4])
                    ||
                checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION-4])
                    )
            return dd_offset;
    }

    // otherwise just linear search the dd magic and check for reasonability.
    dd_offset = offset + MIN_SIZE_OF_ZIP_RECORD + fr->compressedSize + fr->fileNameLength + fr->extraFieldLength;
    f_offset = abs_file_offset + dd_offset;

//	r_size = readCustomBlock(file_name, f_offset, BLOCKSIZE, block_s);
    r_size = readFile(fp, (size_t)f_offset, BLOCKSIZE, block_s);
    if ( r_size == 0 )
        return UINT64_MAX;
    offset = 0;
    debug_info(" - - ZIP_findDataDescriptionOffset\n");
    debug_info(" - - - offset: 0x%zx\n", offset);
    debug_info(" - - - f_offset: 0x%zx\n", f_offset);

    while ( 1 )
    {
        if ( !checkStandardBlockSpace(&offset, &f_offset, SIZE_OF_ZIP_DATA_DESCRIPTION+4, block_s, fp) )
            return UINT64_MAX;

        ptr = &block_s[offset];
//		debug_info(" - - - offset : 0x%lx, f_offset : 0x%lx, ptr[%lx:%lx]: %02x|%02x|%02x|%02x\n", offset, f_offset, offset, offset+3
//		, ptr[offset], ptr[offset+1], ptr[offset+2], ptr[offset+3]);

        if ( checkBytes(MAGIC_ZIP_DATA_DESCRIPTOR_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[0])
            &&
            (checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION])
             ||
             checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[SIZE_OF_ZIP_DATA_DESCRIPTION]))
             &&
            *((uint32_t*) &ptr[ZipDataDescriptionOffsets.compressedSize]) == bytes_searched
        )
        {
            debug_info(" - - - - found 0x%zx\n", offset);
            return f_offset + offset;
        }

        offset++;
        bytes_searched++;
        if ( f_offset + SIZE_OF_ZIP_DATA_DESCRIPTION > file_size )
        {
            debug_info(" - - - - f_offset (0x%zx) + 0x%x = (0x%zx) > file_size (0x%zx)\n", f_offset, SIZE_OF_ZIP_DATA_DESCRIPTION, f_offset+3, file_size);
            break;
        }
    }
    return UINT64_MAX;
}

size_t ZIP_handleDirEntry(size_t offset,
                            uint16_t* found_needles,
                            uint32_t record_count,
                            size_t* abs_file_offset,
                            size_t file_size,
                            uint8_t ilevel,
                            FILE* fp,
                            unsigned char* block_s,
                            unsigned char* block_l)
{
    ZipDirEntry de;
    unsigned char* ptr;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_DIR_ENTRY;
    (void)found_needles;

    if ( !checkFileSpace(offset, *abs_file_offset, size_of_entry, file_size) )
        return UINT64_MAX;
    if ( !checkLargeBlockSpace(&offset, abs_file_offset, size_of_entry, block_l, fp) )
        return UINT64_MAX;

    ptr = &block_l[offset];

    ZIP_fillDirEntry(&de, ptr);

    if ( ilevel >= INFO_LEVEL_FULL )
        ZIP_printDirEntry(&de, ptr, record_count, *abs_file_offset + offset, file_size, fp, block_s);

    offset += size_of_entry + de.fileNameLength + de.fileCommentLength + de.extraFieldLength;
    debug_info(" - abs_file_offset+offset: 0x%zx (%zx)\n", *abs_file_offset+offset, *abs_file_offset+offset);

    return offset;
}

void ZIP_fillDirEntry(ZipDirEntry* de, const unsigned char* ptr)
{
    int i;

    for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
        de->signature[i] = (char)ptr[ZipDirEntryOffsets.signature + i];
    de->versionMadeBy.version = *((uint8_t*) &ptr[ZipDirEntryOffsets.versionMadeBy + ZipVersionOffsets.version]);
    de->versionMadeBy.hostOs = *((uint8_t*) &ptr[ZipDirEntryOffsets.versionMadeBy + ZipVersionOffsets.hostOs]);
    de->versionToExtract.version = *((uint8_t*) &ptr[ZipDirEntryOffsets.versionToExtract + ZipVersionOffsets.version]);
    de->versionToExtract.hostOs = *((uint8_t*) &ptr[ZipDirEntryOffsets.versionToExtract + ZipVersionOffsets.hostOs]);
    de->flags = *((uint16_t*) &ptr[ZipDirEntryOffsets.flags]);
    de->compression = *((uint16_t*) &ptr[ZipDirEntryOffsets.compression]);
    de->fileTime = *((uint16_t*) &ptr[ZipDirEntryOffsets.fileTime]);
    de->fileDate = *((uint16_t*) &ptr[ZipDirEntryOffsets.fileDate]);
    de->crc = *((uint32_t*) &ptr[ZipDirEntryOffsets.crc]);
    de->compressedSize = *((uint32_t*) &ptr[ZipDirEntryOffsets.compressedSize]);
    de->uncompressedSize = *((uint32_t*) &ptr[ZipDirEntryOffsets.uncompressedSize]);
    de->fileNameLength = *((uint16_t*) &ptr[ZipDirEntryOffsets.fileNameLength]);
    de->extraFieldLength = *((uint16_t*) &ptr[ZipDirEntryOffsets.extraFieldLength]);
    de->fileCommentLength = *((uint16_t*) &ptr[ZipDirEntryOffsets.fileCommentLength]);
    de->diskNumberStart = *((uint16_t*) &ptr[ZipDirEntryOffsets.diskNumberStart]);
    de->internalAttributes = *((uint16_t*) &ptr[ZipDirEntryOffsets.internalAttributes]);
    de->externalAttributes = *((uint32_t*) &ptr[ZipDirEntryOffsets.externalAttributes]);
    de->headerOffset = *((uint32_t*) &ptr[ZipDirEntryOffsets.headerOffset]);
}

size_t ZIP_handleEndLocator(size_t offset,
                              size_t* abs_file_offset,
                              size_t file_size,
                              uint8_t ilevel,
                              FILE* fp,
                              unsigned char* block_s,
                              unsigned char* block_l)
{
    ZipEndLocator el;
    unsigned char* ptr;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_END_LOCATOR;

    debug_info("ZIP_handleEndLocator\n");
    debug_info("offset: %zx\n", offset);

    if ( !checkFileSpace(offset, *abs_file_offset, size_of_entry, file_size) )
        return UINT64_MAX;
    if ( !checkLargeBlockSpace(&offset, abs_file_offset, size_of_entry, block_l, fp))
        return UINT64_MAX;

    ptr = &block_l[offset];

    ZIP_fillEndLocator(&el, ptr);

    debug_info(" - abs_file_offset+offset: 0x%zx (%zx)\n", *abs_file_offset+offset, *abs_file_offset+offset);

    if ( ilevel >= INFO_LEVEL_FULL )
        ZIP_printEndLocator(&el, ptr, *abs_file_offset + offset, file_size, fp, block_s);

    return offset;
}

void ZIP_fillEndLocator(ZipEndLocator* r,
                        const unsigned char* ptr)
{
    int i;

    for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
        r->signature[i] = (char)ptr[ZipEndLocatorOffsets.signature + i];
    r->diskNumber = *((uint16_t*) &ptr[ZipEndLocatorOffsets.diskNumber]);
    r->startDiskNumber = *((uint16_t*) &ptr[ZipEndLocatorOffsets.startDiskNumber]);
    r->entriesOnDisk = *((uint16_t*) &ptr[ZipEndLocatorOffsets.entriesOnDisk]);
    r->entriesInDirectory = *((uint16_t*) &ptr[ZipEndLocatorOffsets.entriesInDirectory]);
    r->directorySize = *((uint16_t*) &ptr[ZipEndLocatorOffsets.directorySize]);
    r->directoryOffset = *((uint16_t*) &ptr[ZipEndLocatorOffsets.directoryOffset]);
    r->commentLength = *((uint16_t*) &ptr[ZipEndLocatorOffsets.commentLength]);
}

uint8_t ZIP_checkNameOfRecord(const unsigned char* ptr,
                              uint16_t frFileNameLength,
                              const char* expected)
{
    uint16_t i;
    for ( i = 0; i < frFileNameLength; i++ )
    {
        if ( ptr[ZipFileRecoredOffsets.fileName + i] != expected[i] )
            return 0;
    }

    return 1;
}

uint8_t ZIP_nameHasFileType(const unsigned char* ptr,
                            uint16_t frFileNameLength,
                            const char* needle)
{
    int32_t i, j;
    int32_t end_i = frFileNameLength - (int32_t)strlen(needle);
    int32_t start_i = frFileNameLength - 1;
    int32_t start_j = (int32_t)strlen(needle) - 1;

    if ( end_i < 0 )
        return 0;

    for ( i = start_i, j=start_j; i >= end_i; i--, j-- )
    {
        if ( ptr[ZipFileRecoredOffsets.fileName + i] != needle[j] )
            return 0;
    }
    return 1;
}

uint8_t ZIP_nameStartsWith(const unsigned char* ptr,
                           uint16_t frFileNameLength,
                           const char* needle)
{
    int32_t i;
    int32_t end_i = (int32_t)strlen(needle);

    if ( end_i > frFileNameLength )
        return 0;

    for ( i = 0; i < end_i; i++ )
    {
        if ( ptr[ZipFileRecoredOffsets.fileName + i] != needle[i] )
            return 0;
    }
    return 1;
}


/**
 * Check filename containing needles, which are special type identifiers.
 *
 * @param r ZipRecord*
 * @param offset size_t
 * @param found_needles uint16_t*
 * @param record_count uint32_t
 * @return 0|1
 */
uint8_t ZIP_checkNeedles(ZipFileRecord* r,
                         size_t offset,
                         uint16_t* found_needles,
                         uint32_t record_count,
                         size_t abs_file_offset,
                         size_t file_size,
                         FILE* fp,
                         unsigned char* block_s,
                         unsigned char* block_l)
{
    int i;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_RECORD;
    const char* needles[] = {
            "META-INF/",
            "META-INF/MANIFEST.MF",
            ".class",
            "word",
            "AndroidManifest.xml", // apk
    };
    unsigned char* ptr = &block_l[offset];

    if ( r->fileNameLength != 0 )
    {
        if ( !checkFileSpace(offset, abs_file_offset, size_of_entry + r->fileNameLength, file_size) )
            return 0;
        i = readStandardBlockIfLargeBlockIsExceeded(offset, abs_file_offset, size_of_entry+r->fileNameLength, block_s, fp);
        if ( i == 2 )
            ptr = &block_s[0];
        else if ( i == 0 )
            return 0;

//		debug_info(" - - name: ");
//		for ( i = 0; i < r->frFileNameLength; i++ )
//		{
//			debug_info("%c", ptr[ZipRecoredOffsets.frFileName+i]);
//		}
//		debug_info("\n");

        if ( record_count < 2 )
        {
            if ( !ZIP_checkNameOfRecord(ptr, r->fileNameLength, needles[record_count]) )
                found_needles[record_count]++;
        }
        else
        {
            if ( ZIP_nameHasFileType(ptr, r->fileNameLength, needles[2]) )
                found_needles[2]++;
            if ( ZIP_nameStartsWith(ptr, r->fileNameLength, needles[3]) )
                found_needles[3]++;
        }
    }

    return 1;
}

uint8_t isJar(const uint16_t found_needles[4])
{
    return (found_needles[0]>0 && found_needles[1]>0 && found_needles[2]>0)
           ||
           found_needles[2]>found_needles[3];
}

#endif
