#ifndef HEADER_PARSER_ZIP_HEADER_PRINTER_H
#define HEADER_PARSER_ZIP_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "../utils/Helper.h"
#include "ZipHeader.h"

static void ZIP_printFileEntry(const ZipFileRecord* fr,
                               uint32_t idx,
                               size_t offset,
                               size_t dd_offset,
                               size_t file_size,
                               FILE* fp,
                               uint8_t* buffer,
                               size_t buffer_cb);

static void ZIP_printDirEntry(const ZipDirEntry* r,
                              uint32_t idx,
                              size_t offset,
                              size_t file_size,
                              FILE* fp,
                              uint8_t* buffer,
                              size_t buffer_cb);

static void ZIP_printEndLocator(const ZipEndLocator* r,
                                size_t offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* buffer,
                                size_t buffer_cb);

static const char* ZIP_getCompressionString(uint16_t type);



/**
 * Check space left in large block, depending on offset and needed size.
 * If data.block_main is too small, read in new bytes into data.block_sub.
 * abs_file_offset is not adjusted.
 *
 * @param rel_offset size_t*
 * @param abs_offset size_t*
 * @param needed  uint16_t
 * @param block_s uint8_t[BLOCKSIZE_SMALL]
 * @param file_name const char*
 * @return uint8_t 0: failed, 1: nothing happend (enough space), 2: data.block_sub filled.
 */
size_t readNewIfBlockIsExceeded(
    size_t fo,
    size_t offset,
    size_t size,
    uint8_t* buffer,
    size_t buffer_cb,
    FILE* fp
)
{
    FEnter();
    DPrint("offset: 0x%zx\n", offset);
    DPrint("size: 0x%zx\n", size);
    DPrint("buffer: %p\n", buffer);
    DPrint("buffer_cb: 0x%zx\n", buffer_cb);

    size_t r_size = 0;
    if ( offset + size > buffer_cb )
    {
        DPrint("reading new into buffer\n");
        r_size = readFile(fp, fo+offset, size, buffer);
        if ( r_size == 0 )
        {
            FLeave();
            return (size_t)-1;
        }

        FLeave();
        return r_size;
    }
    FLeave();
    return 0;
}

//
// Print `size` bytes starting at absolute file offset `fo`, reading in
// buffer_cb-sized chunks so arbitrarily large fields work.
//
static void ZIP_printBytesChunked(size_t fo, size_t size, uint8_t* buffer, size_t buffer_cb, FILE* fp, char* format)
{
    size_t remaining = size;
    while ( remaining > 0 )
    {
        size_t chunk = min(remaining, buffer_cb);
        size_t r = readFile(fp, fo, chunk, buffer);
        if ( r == 0 )
            break;

        for ( size_t i = 0; i < r; i++ )
            printf(format, buffer[i]);

        fo += r;
        remaining -= r;
    }
}

void ZIP_printFileEntry(const ZipFileRecord* fr,
                        uint32_t idx,
                        size_t offset,
                        size_t dd_offset,
                        size_t file_size,
                        FILE* fp,
                        uint8_t* buffer,
                        size_t buffer_cb)
{
    FEnter();

    const Zip_File_Recored_Offsets *offsets = &ZipFileRecoredOffsets;

    printf("Zip File Entry %u:\n", idx);
    printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets->signature, offset, 0), fr->signature[0], fr->signature[1], fr->signature[2], fr->signature[3]);
    printf(" - version.version%s: %f\n", fillOffset((size_t)offsets->version+ZipVersionOffsets.version, offset, 0), fr->version.version / 10.0);
    printf(" - version.hostOs%s: %u\n", fillOffset((size_t)offsets->version+ZipVersionOffsets.hostOs, offset, 0), fr->version.hostOs);
//	printf(" - frFlags: %u\n", r->frFlags);
    printf(" - flags%s:", fillOffset(offsets->flags, offset, 0));
    printFlag16(fr->flags, ZipFlagTypes.FLAG_Encrypted, "Encrypted");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CompressionFlagBit1, "CompressionFlagBit1");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CompressionFlagBit2, "CompressionFlagBit2");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_DescriptorUsedMask, "DescriptorUsed");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_Reserved1, "Reserved1");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_Reserved2, "Reserved2");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_StrongEncrypted, "StrongEncrypted");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CurrentlyUnused1, "CurrentlyUnused1");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CurrentlyUnused2, "CurrentlyUnused2");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CurrentlyUnused3, "CurrentlyUnused3");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CurrentlyUnused4, "CurrentlyUnused4");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_Utf8, "Utf8");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_ReservedPKWARE1, "ReservedPKWARE1");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_CDEncrypted, "CDEncrypted");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_ReservedPKWARE2, "ReservedPKWARE2");
    printFlag16(fr->flags, ZipFlagTypes.FLAG_ReservedPKWARE3, "ReservedPKWARE3");
    printf("\n");
    printf(" - compression%s: %s (%u)\n", fillOffset(offsets->compression, offset, 0), ZIP_getCompressionString(fr->compression), fr->compression);
    printf(" - compressedSize%s: 0x%x (%u)\n", fillOffset(offsets->compressedSize, offset, 0), fr->compressedSize, fr->compressedSize);
    printf(" - uncompressedSize%s: 0x%x (%u)\n", fillOffset(offsets->uncompressedSize, offset, 0), fr->uncompressedSize, fr->uncompressedSize);
    printf(" - fileNameLength%s: 0x%x (%u)\n", fillOffset(offsets->fileNameLength, offset, 0), fr->fileNameLength, fr->fileNameLength);
    printf(" - extraFieldLength%s: 0x%x (%u)\n", fillOffset(offsets->extraFieldLength, offset, 0), fr->extraFieldLength, fr->extraFieldLength);
    if ( fr->fileNameLength != 0 )
    {
        if ( !checkFileSpace(offset, 0, offsets->fileName + fr->fileNameLength, file_size) )
            return;
        
        printf(" - fileName%s: ", fillOffset(offsets->fileName, offset, 0));
        ZIP_printBytesChunked(offset + offsets->fileName, fr->fileNameLength, buffer, buffer_cb, fp, "%c");
        printf("\n");
    }
    if ( fr->extraFieldLength != 0 )
    {
        size_t ef_offset = offsets->fileName + fr->fileNameLength;
        if ( !checkFileSpace(offset, 0, ef_offset + fr->extraFieldLength, file_size) )
            return;
        
        printf(" - extraField%s: ", fillOffset(ef_offset, offset, 0));
        ZIP_printBytesChunked(offset + ef_offset, fr->extraFieldLength, buffer, buffer_cb, fp, "%02x ");
        printf("\n");
    }
    if ( hasFlag16(fr->flags, ZipFlagTypes.FLAG_DescriptorUsedMask) )
    {
        printf(" - dataDescr:\n");
        DPrint("    offset: 0x%zx\n", dd_offset);
        printf("   - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(ZipDataDescriptionOffsets.signature, dd_offset, 0), fr->dataDescr.ddSignature[0], fr->dataDescr.ddSignature[1], fr->dataDescr.ddSignature[2], fr->dataDescr.ddSignature[3]);
        printf("   - crc%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.crc, dd_offset, 0), fr->dataDescr.ddCRC, fr->dataDescr.ddCRC);
        printf("   - compressedSize%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.compressedSize, dd_offset, 0), fr->dataDescr.ddCompressedSize, fr->dataDescr.ddCompressedSize);
        printf("   - uncompressedSize%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.uncompressedSize, dd_offset, 0), fr->dataDescr.ddUncompressedSize, fr->dataDescr.ddUncompressedSize);
    }

    FLeave();
}

const char* ZIP_getCompressionString(const uint16_t type)
{
    switch ( type )
    {
        case COMP_STORED: return "COMP_STORED";
        case COMP_SHRUNK: return "COMP_SHRUNK";
        case COMP_REDUCED1: return "COMP_REDUCED1";
        case COMP_REDUCED2: return "COMP_REDUCED2";
        case COMP_REDUCED3: return "COMP_REDUCED3";
        case COMP_REDUCED4: return "COMP_REDUCED4";
        case COMP_IMPLODED: return "COMP_IMPLODED";
        case COMP_TOKEN: return "COMP_TOKEN";
        case COMP_DEFLATE: return "COMP_DEFLATE";
        case COMP_DEFLATE64: return "COMP_DEFLATE64";
        default: return "None";
    }
}

void ZIP_printDirEntry(const ZipDirEntry* r,
                       uint32_t idx,
                       size_t offset,
                       size_t file_size,
                       FILE* fp,
                       uint8_t* buffer,
                       size_t buffer_cb)
{
    const Zip_Dir_Entry_Offsets *offsets = &ZipDirEntryOffsets;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_DIR_ENTRY;

    printf("Zip Directory Entry %u:\n", idx);
    printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets->signature, offset, 0), r->signature[0], r->signature[1], r->signature[2], r->signature[3]);
    printf(" - versionMadeBy.version%s: %u\n", fillOffset(offsets->versionMadeBy + ZipVersionOffsets.version, offset, 0), r->versionMadeBy.version);
    printf(" - versionMadeBy.hostOs%s: %u\n", fillOffset(offsets->versionMadeBy + ZipVersionOffsets.hostOs, offset, 0), r->versionMadeBy.hostOs);
    printf(" - versionToExtract.version%s: %u\n", fillOffset(offsets->versionToExtract + ZipVersionOffsets.version, offset, 0), r->versionToExtract.version);
    printf(" - versionToExtract.hostOs%s: %u\n", fillOffset(offsets->versionToExtract + ZipVersionOffsets.hostOs, offset, 0), r->versionToExtract.hostOs);
    printf(" - flags%s:", fillOffset(offsets->flags, offset, 0));
    printFlag16(r->flags, ZipFlagTypes.FLAG_Encrypted, "Encrypted");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CompressionFlagBit1, "CompressionFlagBit1");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CompressionFlagBit2, "CompressionFlagBit2");
    printFlag16(r->flags, ZipFlagTypes.FLAG_DescriptorUsedMask, "DescriptorUsedMask");
    printFlag16(r->flags, ZipFlagTypes.FLAG_Reserved1, "Reserved1");
    printFlag16(r->flags, ZipFlagTypes.FLAG_Reserved2, "Reserved2");
    printFlag16(r->flags, ZipFlagTypes.FLAG_StrongEncrypted, "StrongEncrypted");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CurrentlyUnused1, "CurrentlyUnused1");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CurrentlyUnused2, "CurrentlyUnused2");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CurrentlyUnused3, "CurrentlyUnused3");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CurrentlyUnused4, "CurrentlyUnused4");
    printFlag16(r->flags, ZipFlagTypes.FLAG_Utf8, "Utf8");
    printFlag16(r->flags, ZipFlagTypes.FLAG_ReservedPKWARE1, "ReservedPKWARE1");
    printFlag16(r->flags, ZipFlagTypes.FLAG_CDEncrypted, "CDEncrypted");
    printFlag16(r->flags, ZipFlagTypes.FLAG_ReservedPKWARE2, "ReservedPKWARE2");
    printFlag16(r->flags, ZipFlagTypes.FLAG_ReservedPKWARE3, "ReservedPKWARE3");
    printf("\n");
    printf(" - compression%s: %s (%u)\n", fillOffset(offsets->compression, offset, 0), ZIP_getCompressionString(r->compression), r->compression);
    printf(" - fileTime%s: %u\n", fillOffset(offsets->fileTime, offset, 0), r->fileTime);
    printf(" - fileDate%s: %u\n", fillOffset(offsets->fileDate, offset, 0), r->fileDate);
    printf(" - crc%s: %u\n", fillOffset(offsets->crc, offset, 0), r->crc);
    printf(" - compressedSize%s: 0x%x (%u)\n", fillOffset(offsets->compressedSize, offset, 0), r->compressedSize, r->compressedSize);
    printf(" - uncompressedSize%s: 0x%x (%u)\n", fillOffset(offsets->uncompressedSize, offset, 0), r->uncompressedSize, r->uncompressedSize);
    printf(" - fileNameLength%s: 0x%x (%u)\n", fillOffset(offsets->fileNameLength, offset, 0), r->fileNameLength, r->fileNameLength);
    printf(" - extraFieldLength%s: 0x%x (%u)\n", fillOffset(offsets->extraFieldLength, offset, 0), r->extraFieldLength, r->extraFieldLength);
    printf(" - fileCommentLength%s: 0x%x (%u)\n", fillOffset(offsets->fileCommentLength, offset, 0), r->fileCommentLength, r->fileCommentLength);
    printf(" - diskNumberStart%s: 0x%x (%u)\n", fillOffset(offsets->diskNumberStart, offset, 0), r->diskNumberStart, r->diskNumberStart);
    printf(" - internalAttributes%s: 0x%x (%u)\n", fillOffset(offsets->internalAttributes, offset, 0), r->internalAttributes, r->internalAttributes);
    printf(" - externalAttributes%s: 0x%x (%u)\n", fillOffset(offsets->externalAttributes, offset, 0), r->externalAttributes, r->externalAttributes);
    printf(" - headerOffset%s: 0x%x (%u)\n", fillOffset(offsets->headerOffset, offset, 0), r->headerOffset, r->headerOffset);
    if ( r->fileNameLength != 0 )
    {
        if ( !checkFileSpace(offset, 0, size_of_entry + r->fileNameLength, file_size) )
            return;
        
        printf(" - fileName%s: ", fillOffset(offsets->fileName, offset, 0));
        ZIP_printBytesChunked(offset + offsets->fileName, r->fileNameLength, buffer, buffer_cb, fp, "%c");
        printf("\n");
    }
    if ( r->extraFieldLength != 0 )
    {
        size_t ef_offset = offsets->fileName + r->fileNameLength;
        if ( !checkFileSpace(offset, 0, ef_offset + r->extraFieldLength, file_size) )
            return;
        
        printf(" - extraField%s: ", fillOffset(ef_offset, offset, 0));
        ZIP_printBytesChunked(offset + ef_offset, r->extraFieldLength, buffer, buffer_cb, fp, "%02x ");
        printf("\n");
    }
    if ( r->fileCommentLength != 0 )
    {
        size_t comment_offset = offsets->fileName + r->fileNameLength + r->extraFieldLength;
        if ( !checkFileSpace(offset, 0, comment_offset + r->fileCommentLength, file_size) )
            return;

        printf(" - comment%s: ", fillOffset(comment_offset, offset, 0));
        ZIP_printBytesChunked(offset + comment_offset, r->fileCommentLength, buffer, buffer_cb, fp, "%c");
        printf("\n");
    }

    return;
}

void ZIP_printEndLocator(const ZipEndLocator* r,
                         size_t offset,
                         size_t file_size,
                         FILE* fp,
                         uint8_t* buffer,
                         size_t buffer_cb)
{
    const Zip_End_Locator_Offsets *offsets = &ZipEndLocatorOffsets;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_END_LOCATOR;

    printf("Zip End Locator:\n");
    printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets->signature, offset, 0), r->signature[0], r->signature[1], r->signature[2], r->signature[3]);
    printf(" - diskNumber%s: %u\n", fillOffset(offsets->diskNumber, offset, 0), r->diskNumber);
    printf(" - startDiskNumber%s: %u\n", fillOffset(offsets->startDiskNumber, offset, 0), r->startDiskNumber);
    printf(" - entriesOnDisk%s: %u\n", fillOffset(offsets->entriesOnDisk, offset, 0), r->entriesOnDisk);
    printf(" - entriesInDirectory%s: %u\n", fillOffset(offsets->entriesInDirectory, offset, 0), r->entriesInDirectory);
    printf(" - directorySize%s: %u\n", fillOffset(offsets->directorySize, offset, 0), r->directorySize);
    printf(" - directoryOffset%s: %u\n", fillOffset(offsets->directoryOffset, offset, 0), r->directoryOffset);
    printf(" - commentLength%s: %u\n", fillOffset(offsets->commentLength, offset, 0), r->commentLength);
    if ( r->commentLength != 0 )
    {
        if ( !checkFileSpace(offset, 0, size_of_entry + r->commentLength, file_size) )
            return;
        
        printf(" - comment%s: ", fillOffset(offsets->comment, offset, 0));
        ZIP_printBytesChunked(offset + offsets->comment, r->commentLength, buffer, buffer_cb, fp, "%c");
        printf("\n");
    }
}

#endif
