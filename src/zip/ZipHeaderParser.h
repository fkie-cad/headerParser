#ifndef HEADER_PARSER_ZIP_HEADER_PARSER_H
#define HEADER_PARSER_ZIP_HEADER_PARSER_H

#include "../print.h"
#include "../utils/common_fileio.h"
#include "../utils/blockio.h"
#include "../utils/Helper.h"
#include "../stringPool.h"
// #include "../ArchitectureInfo.h"

#include "ZipHeader.h"
#include "ZipHeaderOffsets.h"
#include "ZipHeaderPrinter.h"
#include <stdint.h>



static void parseZip(PHeaderData hd, PGlobalParams gp);

static size_t ZIP_findEndLocator(size_t file_size, FILE* fp, uint8_t* block, size_t block_cb);

static int ZIP_handleFileRecord(size_t offset,
                                   PGlobalParams gp,
                                   ZipFileRecord *fr);
static int ZIP_fillFileRecord(ZipFileRecord* fr,
                                const uint8_t* ptr);
int ZIP_fillFileRecordDataDescriptor(size_t offset,
                         PGlobalParams gp,
                         ZipFileRecord *fr);
static uint8_t ZIP_usesDataDescritpor(const ZipFileRecord* fr);
static int ZIP_handleDirEntry(size_t offset,
                                   uint16_t* found_needles,
                                   size_t abs_file_offset,
                                   size_t file_size,
                                   FILE* fp,
                                   uint8_t* buffer,
                                   size_t buffer_cb,
                                   ZipDirEntry *de);
static void ZIP_fillDirEntry(ZipDirEntry* de,
                             const uint8_t* ptr);
static int ZIP_fillEndLocator(ZipEndLocator* r, size_t offset, PGlobalParams gp);
static uint8_t ZIP_checkNameOfRecord(const char* name, uint16_t frFileNameLength, const char* expected);
static uint8_t ZIP_nameHasFileType(const char* name, uint16_t frFileNameLength, const char* needle);
static uint8_t ZIP_nameStartsWith(const char* name, uint16_t frFileNameLength, const char* needle);
static uint8_t ZIP_checkNeedlesDe(ZipDirEntry* de,
                                size_t offset,
                                uint16_t* found_needles,
                                size_t abs_file_offset,
                                size_t file_size,
                                FILE* fp,
                                uint8_t* buffer,
                                size_t buffer_cb);
static uint8_t isJar(const uint16_t found_needles[4]);



void parseZip(PHeaderData hd, PGlobalParams gp)
{
    FEnter();
    int s = 0;
    
    ZipEndLocator el = {0};

    uint16_t found_needles[5] = {0};

    size_t eocd = ZIP_findEndLocator(gp->file.size, gp->file.handle, gp->data.block_main, gp->data.block_main_size);
    if ( eocd == UINT64_MAX )
    { 
        EPrint("Cant't find EOCD! ZIP invalid!\n");
        goto clean;
    }
    debug_info("found eocd: 0x%zx\n", eocd);

    // read + fill EOCD  (fix the uint16_t→uint32_t reads here)
    s = ZIP_fillEndLocator(&el, eocd, gp);
    if ( s != 0 )
    {
        EPrint("Cant't fill EOCD!\n");
        goto clean;
    }

    if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        ZIP_printEndLocator(
        &el, 
        gp->file.abs_offset + eocd, 
        gp->file.size, 
        gp->file.handle, 
        gp->data.block_main,
        gp->data.block_main_size);

    // TODO ZIP64: if directoryOffset==0xFFFFFFFF or entries==0xFFFF,
    //             follow the ZIP64 EOCD locator that precedes `eocd`.
    if ( el.directoryOffset == (uint32_t)-1 || el.entriesOnDisk == (uint16_t)-1 )
    {
        EPrint("ZIP64 not implemented yet!\n");
        goto clean;
    }
    
    size_t cd_off = el.directoryOffset;

    for ( uint32_t i = 0; i < el.entriesInDirectory; i++ )
    {
        // check offset for validity
        if ( cd_off > eocd 
            || cd_off < el.directoryOffset
            || cd_off > el.directoryOffset + el.directorySize )
        {
            EPrint("Directory offset invalid!\n");
            goto clean;
        }

        debug_info("dir: %u\n", i);
        
        ZipDirEntry de = { 0 };
        s = ZIP_handleDirEntry(
                    cd_off, 
                    found_needles, 
                    gp->file.abs_offset, 
                    gp->file.size, 
                    gp->file.handle, 
                    gp->data.block_main, 
                    gp->data.block_main_size, 
                    &de
                );
        if ( s != 0 )
        {
            EPrint("Fill Directory Entry failed!\n");
            goto clean;
        }
        if ( gp->info_level >= INFO_LEVEL_EXTENDED )
            ZIP_printDirEntry(
                    &de, 
                    i, 
                    gp->file.abs_offset + cd_off, 
                    gp->file.size, 
                    gp->file.handle, 
                    gp->data.block_main, 
                    gp->data.block_main_size
                );
        
        ZIP_checkNeedlesDe(
            &de, 
            cd_off, 
            found_needles, 
            gp->file.abs_offset, 
            gp->file.size, 
            gp->file.handle, 
            gp->data.block_sub,
            gp->data.block_sub_size);
            

        if ( gp->info_level >= INFO_LEVEL_EXTENDED )
        {
            ZipFileRecord fr = { 0 };
            size_t dd_offset = (size_t)-1;

            s = ZIP_handleFileRecord(
                de.headerOffset, 
                gp,
                &fr);

            if ( s == 0)
            {
                if ( ZIP_usesDataDescritpor(&fr) )
                {
                    dd_offset = de.headerOffset + MIN_SIZE_OF_ZIP_RECORD + fr.fileNameLength + fr.extraFieldLength + de.compressedSize;
                    ZIP_fillFileRecordDataDescriptor(
                            dd_offset,
                            gp,
                            &fr
                        );
                }

                ZIP_printFileEntry(
                    &fr, 
                    i, 
                    gp->file.abs_offset + de.headerOffset, 
                    dd_offset, 
                    gp->file.size, 
                    gp->file.handle, 
                    gp->data.block_main,
                    gp->data.block_main_size);
            }
            s = 0;
        }

        cd_off += MIN_SIZE_OF_ZIP_DIR_ENTRY + de.fileNameLength + de.fileCommentLength + de.extraFieldLength;
        DPrint(" - abs_file_offset+offset: 0x%zx\n", gp->file.abs_offset + cd_off);
    }

    if ( isJar(found_needles) )
    {
        hd->headertype = HEADER_TYPE_JAR;
        hd->CPU_arch = ARCH_JAVA;
        hd->Machine = "Jar Archive";
        DPrint("Jar Archive\n");
    }
    else if ( found_needles[3] > 0 )
    {
        hd->headertype = HEADER_TYPE_WORD_DOC_X;
        hd->CPU_arch = ARCH_UNSUPPORTED;
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
        DPrint("DocX\n");
    }
    else if ( found_needles[4] > 0 )
    {
        hd->headertype = HEADER_TYPE_APK;
        hd->CPU_arch = ARCH_ANDROID;
        // TODO: find classes.dex and parse
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
        DPrint("APK\n");
    }
    else
    {
        hd->headertype = HEADER_TYPE_ZIP;
        hd->CPU_arch = ARCH_UNSUPPORTED;
        hd->Machine = architecture_names[ARCH_UNSUPPORTED];
        DPrint("ZIP\n");
    }

clean:
    FLeave();
}

//
// Read the tail of the file and scan backwards for 50 4B 05 06.
// Comment is uin16_t max bytes, so the search window is bounded.
//
static size_t ZIP_findEndLocator(size_t file_size, FILE* fp, uint8_t* block, size_t block_cb)
{
    FEnter();
    size_t max_scan = MIN_SIZE_OF_ZIP_END_LOCATOR + 0xFFFF;   // 22 + max comment
    size_t window = min(file_size, max_scan);
    size_t min_fo = file_size - window;
    size_t step;
    size_t fo;
    
    block_cb = min(block_cb, window);
    step = block_cb - (MAGIC_ZIP_BYTES_LN - 1);   // overlap by 3 bytes
    fo = file_size - block_cb;                  // top read position

    // read file window in block sized blocks
    while ( 1 )
    {
        // read a block
        size_t r = readFile(fp, fo, block_cb, block);
        if ( r < block_cb )
        {
            EPrint("Failed reading bytes!\n");
            break;
        }

        debug_info("fo: 0x%zx\n", fo);
        debug_info("bytes_read: 0x%zx\n", bytes_read);

        // walk backward; last match wins (handles a comment that embeds the signature)
        for ( size_t i = block_cb - MAGIC_ZIP_BYTES_LN; ; i-- )
        {
            if ( checkBytes(MAGIC_ZIP_END_LOCATOR_BYTES, MAGIC_ZIP_BYTES_LN, &block[i]) )
            {
                FLeave();
                return fo + i; // absolute EOCD offset
            }
            if ( i == 0 )
                break;
        }
        
        // break if min_fo has been scanned
        if ( fo == min_fo )
            break;

        // check min_fo boundary for next step
        if ( fo < min_fo + step )
            fo = min_fo;
        else
            fo -= step;
    }

    FLeave();
    return UINT64_MAX;
}

int ZIP_handleFileRecord(size_t offset,
                         PGlobalParams gp,
                         ZipFileRecord *fr)
{
    FEnter();
    int s = 0;
    uint8_t* ptr = NULL;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_RECORD;
    int errsv = 0;

    if ( !checkFileSpace(offset, gp->file.abs_offset, size_of_entry, gp->file.size) )
    {
        s = 1;
        goto clean;
    }
    debug_info("offset: 0x%zx\n", offset);

    size_t br = readFile(gp->file.handle, offset, gp->data.block_main_size, gp->data.block_main);
    errsv = errno;
    if ( errsv != 0 || br < size_of_entry )
    {
        s = 2;
        goto clean;
    }
    ptr = gp->data.block_main;
    debug_info("ptr: %p\n", ptr);
    DPrintMemCol8(ptr, size_of_entry, offset);

    s = ZIP_fillFileRecord(
        fr, 
        ptr);

clean:
    FLeave();
    return s;
}

int ZIP_fillFileRecord(ZipFileRecord* fr,
                        const uint8_t* ptr)
{
    FEnter();

    int s = 0;
    int i;

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

    FLeave();
    return s;
}

int ZIP_fillFileRecordDataDescriptor(size_t offset,
                         PGlobalParams gp,
                         ZipFileRecord *fr)
{
    FEnter();
    int s = 0;
    uint8_t* ptr = NULL;
    uint8_t size_of_entry = SIZE_OF_ZIP_DATA_DESCRIPTION;
    int errsv = 0;

    uint8_t* buffer = gp->data.block_sub;
    size_t buffer_cb = gp->data.block_sub_size;

    if ( !checkFileSpace(offset, gp->file.abs_offset, size_of_entry, gp->file.size) )
    {
        s = 1;
        goto clean;
    }
    debug_info("offset: 0x%zx\n", offset);

    size_t br = readFile(gp->file.handle, offset, buffer_cb, buffer);
    errsv = errno;
    if ( errsv != 0 || br < size_of_entry )
    {
        s = 2;
        goto clean;
    }
    ptr = buffer;
    debug_info("ptr: %p\n", ptr);
    DPrintMemCol8(ptr, size_of_entry, offset);

    if ( checkBytes(MAGIC_ZIP_DATA_DESCRIPTOR_BYTES, MAGIC_ZIP_BYTES_LN, &ptr[0]) )
    {
        fr->dataDescr.ddSignature[0] = GetIntXValueAtOffset(char, ptr, ZipDataDescriptionOffsets.signature + 0);
        fr->dataDescr.ddSignature[1] =  GetIntXValueAtOffset(char, ptr, ZipDataDescriptionOffsets.signature + 1);
        fr->dataDescr.ddSignature[2] =  GetIntXValueAtOffset(char, ptr, ZipDataDescriptionOffsets.signature + 2);
        fr->dataDescr.ddSignature[3] =  GetIntXValueAtOffset(char, ptr, ZipDataDescriptionOffsets.signature + 3);
        fr->dataDescr.ddCRC = GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.crc);
        fr->dataDescr.ddCompressedSize =  GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.compressedSize);
        fr->dataDescr.ddUncompressedSize =  GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.uncompressedSize);
    }
    else
    {
        fr->dataDescr.ddSignature[0] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[0];
        fr->dataDescr.ddSignature[1] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[1];
        fr->dataDescr.ddSignature[2] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[2];
        fr->dataDescr.ddSignature[3] = 0; // MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[3];
        fr->dataDescr.ddCRC = GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.crc - 4);
        fr->dataDescr.ddCompressedSize =  GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.compressedSize - 4);
        fr->dataDescr.ddUncompressedSize =  GetIntXValueAtOffset(uint32_t, ptr, ZipDataDescriptionOffsets.uncompressedSize - 4);
    }

clean:
    FLeave();
    return s;
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


int ZIP_handleDirEntry(size_t offset,
                            uint16_t* found_needles,
                            size_t abs_file_offset,
                            size_t file_size,
                            FILE* fp,
                            uint8_t* buffer,
                            size_t buffer_cb,
                            ZipDirEntry *de)
{
    FEnter();

    int s = 0;
    uint8_t* ptr;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_DIR_ENTRY;
    (void)found_needles;
    int errsv = 0;

    debug_info("offset: 0x%zx\n", offset);

    if ( !checkFileSpace(offset, abs_file_offset, size_of_entry, file_size) )
    {
        EPrint("offset out of file!\n");
        s = 1;
        goto clean;
    }

    size_t br = readFile(fp, offset, buffer_cb, buffer);
    errsv = errno;
    if ( errsv != 0 || br < size_of_entry )
    {
        s = 2;
        goto clean;
    }
    ptr = buffer;
    debug_info("ptr: %p\n", ptr);
    DPrintMemCol8(ptr, size_of_entry, offset);

    // check if offset points to good magic bytes
    if ( !checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, ptr) )
    {
        EPrint("Invalid Directory Entry magic!\n");
        s = 3;
        goto clean;
    };

    ZIP_fillDirEntry(de, ptr);

clean:
    FLeave();
    return s;
}

void ZIP_fillDirEntry(ZipDirEntry* de, const uint8_t* ptr)
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

//
// reads EOCD into block_main
//
int ZIP_fillEndLocator(ZipEndLocator* el,
                        size_t offset,
                        PGlobalParams gp)
{
    FEnter();
    int i;
    int errsv = 0;

    uint8_t* ptr = NULL;
    uint8_t size_of_entry = MIN_SIZE_OF_ZIP_END_LOCATOR;

    if ( !checkFileSpace(offset, gp->file.abs_offset, size_of_entry, gp->file.size) )
        return 1;

    size_t br = readFile(gp->file.handle, offset, gp->data.block_main_size, gp->data.block_main);
    errsv = errno;
    if ( errsv != 0 || br < size_of_entry )
        return 2;
    ptr = gp->data.block_main;
    debug_info("ptr: %p\n", ptr);

    for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
        el->signature[i] = (char)ptr[ZipEndLocatorOffsets.signature + i];
    el->diskNumber = GetIntXValueAtOffset(uint16_t, ptr, ZipEndLocatorOffsets.diskNumber);
    el->startDiskNumber = GetIntXValueAtOffset(uint16_t, ptr, ZipEndLocatorOffsets.startDiskNumber);
    el->entriesOnDisk = GetIntXValueAtOffset(uint16_t, ptr, ZipEndLocatorOffsets.entriesOnDisk);
    el->entriesInDirectory = GetIntXValueAtOffset(uint16_t, ptr, ZipEndLocatorOffsets.entriesInDirectory);
    el->directorySize = GetIntXValueAtOffset(uint32_t, ptr, ZipEndLocatorOffsets.directorySize);
    el->directoryOffset = GetIntXValueAtOffset(uint32_t, ptr, ZipEndLocatorOffsets.directoryOffset);
    el->commentLength = GetIntXValueAtOffset(uint16_t, ptr, ZipEndLocatorOffsets.commentLength);
    
    FLeave();
    return 0;
}

uint8_t ZIP_checkNameOfRecord(const char* name,
                              uint16_t frFileNameLength,
                              const char* expected)
{
    uint16_t i;

    if ( !name || !expected )
        return 0;

    if ( frFileNameLength != strlen(expected) )
        return 0;

    for ( i = 0; i < frFileNameLength; i++ )
    {
        if ( name[i] != expected[i] )
            return 0;
    }

    return 1;
}

uint8_t ZIP_nameHasFileType(const char* name,
                            uint16_t frFileNameLength,
                            const char* needle)
{
    int32_t i, j;
    int32_t end_i = frFileNameLength - (int32_t)strlen(needle);
    int32_t start_i = frFileNameLength - 1;
    int32_t start_j = (int32_t)strlen(needle) - 1;

    if ( end_i < 0 )
        return 0;
    if ( !name )
        return 0;

    for ( i = start_i, j=start_j; i >= end_i; i--, j-- )
    {
        if ( name[i] != needle[j] )
            return 0;
    }
    return 1;
}

uint8_t ZIP_nameStartsWith(const char* name,
                           uint16_t frFileNameLength,
                           const char* needle)
{
    int32_t i;
    int32_t end_i = (int32_t)strlen(needle);

    if ( end_i > frFileNameLength )
        return 0;
    if ( !name )
        return 0;

    for ( i = 0; i < end_i; i++ )
    {
        if ( name[i] != needle[i] )
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
uint8_t ZIP_checkNeedlesDe(ZipDirEntry* de,
                         size_t offset,
                         uint16_t* found_needles,
                         size_t abs_file_offset,
                         size_t file_size,
                         FILE* fp,
                         uint8_t* buffer,
                         size_t buffer_cb)
{
    size_t r_size;
    const char* needles[] = {
            "META-INF/",
            "META-INF/MANIFEST.MF",
            ".class",
            "word",
            "AndroidManifest.xml", // apk
    };
    char* name = NULL;
    size_t name_fo;
    size_t head_ln;

    if ( de->fileNameLength == 0 )
        return 1;

    if ( !checkFileSpace(offset, abs_file_offset, ZipDirEntryOffsets.fileName + de->fileNameLength, file_size) )
        return 0;

    name_fo = offset + abs_file_offset + ZipDirEntryOffsets.fileName;
    head_ln = min((size_t)de->fileNameLength, buffer_cb);

    // Always read from file.
    // block_l may be already overwritten
    r_size = readFile(fp, name_fo, head_ln, buffer);
    if ( r_size != head_ln )
        return 0;
    name = (char*)buffer;

    // prefix / full-name checks — operate on the head, must run BEFORE the tail read
    if ( ZIP_checkNameOfRecord(name, de->fileNameLength, needles[0]) ) // "META-INF/"
        found_needles[0]++;
    if ( ZIP_checkNameOfRecord(name, de->fileNameLength, needles[1]) ) // "META-INF/MANIFEST.MF"
        found_needles[1]++;
    if ( ZIP_nameStartsWith(name, de->fileNameLength, needles[3]) ) // "word"  (docx)
        found_needles[3]++;
    if ( ZIP_checkNameOfRecord(name, de->fileNameLength, needles[4]) ) // "AndroidManifest.xml" (apk)
        found_needles[4]++;

    // ends-with check — needs the tail for names longer than the buffer.
    // (clobbers `buffer`, so it comes last, after all head-based checks.)
    uint8_t is_class = 0;
    if ( de->fileNameLength <= head_ln )
    {
        is_class = ZIP_nameHasFileType(name, de->fileNameLength, needles[2]);   // ".class"
    }
    else
    {
        size_t tail_ln = buffer_cb;
        size_t tail_fo = name_fo + de->fileNameLength - tail_ln;
        r_size = readFile(fp, tail_fo, tail_ln, buffer);
        if ( r_size == tail_ln )
        {
            is_class = ZIP_nameHasFileType((char*)buffer, (uint16_t)tail_ln, needles[2]);
        }
    }
    if ( is_class )
        found_needles[2]++;

    return 1;
}

uint8_t isJar(const uint16_t found_needles[4])
{
    return (found_needles[0]>0 && found_needles[1]>0 && found_needles[2]>0)
           ||
           found_needles[2]>found_needles[3];
}

#endif
