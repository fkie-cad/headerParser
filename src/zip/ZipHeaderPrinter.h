#ifndef HEADER_PARSER_ZIP_HEADER_PRINTER_H
#define HEADER_PARSER_ZIP_HEADER_PRINTER_H

#include <stdio.h>

#include "../Globals.h"
#include "../utils/Helper.h"
#include "ZipHeader.h"

static void ZIP_printFileEntry(const ZipFileRecord* fr,
                               const unsigned char* ptr,
                               uint32_t idx,
                               uint64_t offset,
                               uint64_t dd_offset,
                               size_t file_size,
                               FILE* fp,
                               unsigned char* block_s);

static void ZIP_printDirEntry(const ZipDirEntry* r,
                              const unsigned char* ptr,
                              uint32_t idx,
                              uint64_t offset,
                              size_t file_size,
                              FILE* fp,
                              unsigned char* block_s);

static void ZIP_printEndLocator(const ZipEndLocator* r,
                                const unsigned char* ptr,
                                uint64_t offset,
                                size_t file_size,
                                FILE* fp,
                                unsigned char* block_s);

static const char* ZIP_getCompressionString(uint16_t type);



void ZIP_printFileEntry(const ZipFileRecord* fr,
                        const unsigned char* ptr,
                        uint32_t idx,
                        uint64_t offset,
                        uint64_t dd_offset,
                        size_t file_size,
                        FILE* fp,
                        unsigned char* block_s)
{
	uint16_t i;
	Zip_File_Recored_Offsets offsets = ZipFileRecoredOffsets;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_RECORD;
	uint8_t r_size;

	printf("Zip File Entry %u:\n", idx);
	printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets.signature, offset, 0), fr->signature[0], fr->signature[1], fr->signature[2], fr->signature[3]);
	printf(" - version.version%s: %f\n", fillOffset((uint64_t)offsets.version+ZipVersionOffsets.version, offset, 0), fr->version.version / 10.0);
	printf(" - version.hostOs%s: %u\n", fillOffset((uint64_t)offsets.version+ZipVersionOffsets.hostOs, offset, 0), fr->version.hostOs);
//	printf(" - frFlags: %u\n", r->frFlags);
	printf(" - flags%s:", fillOffset(offsets.flags, offset, 0));
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
	printf(" - compression%s: %s (%u)\n", fillOffset(offsets.compression, offset, 0), ZIP_getCompressionString(fr->compression), fr->compression);
	printf(" - compressedSize%s: 0x%x (%u)\n", fillOffset(offsets.compressedSize, offset, 0), fr->compressedSize, fr->compressedSize);
	printf(" - uncompressedSize%s: 0x%x (%u)\n", fillOffset(offsets.uncompressedSize, offset, 0), fr->uncompressedSize, fr->uncompressedSize);
	printf(" - fileNameLength%s: %u\n", fillOffset(offsets.fileNameLength, offset, 0), fr->fileNameLength);
	printf(" - extraFieldLength%s: %u\n", fillOffset(offsets.extraFieldLength, offset, 0), fr->extraFieldLength);
	printf(" - name%s: ", fillOffset(offsets.fileName, offset, 0));
//	for ( i = 0; i < r->fileNameLength; i++ )
//	{
//		printf("%c", ptr[ZipRecoredOffsets.fileName+i]);
//	}

	if ( fr->fileNameLength != 0 )
	{
		if ( !checkFileSpace(offset, 0, size_of_entry + fr->fileNameLength, file_size) )
			return;
		r_size = readStandardBlockIfLargeBlockIsExceeded(offset, 0, size_of_entry + fr->fileNameLength, block_s, fp);
		if ( r_size == 0 )
			return;
		else if ( r_size == 2 )
			ptr = &block_s[0];

		for ( i = 0; i < fr->fileNameLength; i++ )
		{
			printf("%c", ptr[ZipFileRecoredOffsets.fileName + i]);
		}
	}
	printf("\n");
	if ( hasFlag16(fr->flags, ZipFlagTypes.FLAG_DescriptorUsedMask) )
	{
		printf(" - dataDescr:\n");
		printf("   - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(ZipDataDescriptionOffsets.signature, dd_offset, 0), fr->dataDescr.ddSignature[0], fr->dataDescr.ddSignature[1], fr->dataDescr.ddSignature[2], fr->dataDescr.ddSignature[3]);
		printf("   - crc%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.crc, dd_offset, 0), fr->dataDescr.ddCRC, fr->dataDescr.ddCRC);
		printf("   - compressedSize%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.compressedSize, dd_offset, 0), fr->dataDescr.ddCompressedSize, fr->dataDescr.ddCompressedSize);
		printf("   - uncompressedSize%s: 0x%x (%u)\n", fillOffset(ZipDataDescriptionOffsets.uncompressedSize, dd_offset, 0), fr->dataDescr.ddUncompressedSize, fr->dataDescr.ddUncompressedSize);
	}
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
                       const unsigned char* ptr,
                       uint32_t idx,
                       uint64_t offset,
                       size_t file_size,
                       FILE* fp,
                       unsigned char* block_s)
{
	uint16_t i;
	Zip_Dir_Entry_Offsets offsets = ZipDirEntryOffsets;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_DIR_ENTRY;
	uint8_t r_size;

	printf("Zip Directory Entry %u:\n", idx);
	printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets.signature, offset, 0), r->signature[0], r->signature[1], r->signature[2], r->signature[3]);
	printf(" - versionMadeBy.version%s: %u\n", fillOffset(offsets.versionMadeBy + ZipVersionOffsets.version, offset, 0), r->versionMadeBy.version);
	printf(" - versionMadeBy.hostOs%s: %u\n", fillOffset(offsets.versionMadeBy + ZipVersionOffsets.hostOs, offset, 0), r->versionMadeBy.hostOs);
	printf(" - versionToExtract.version%s: %u\n", fillOffset(offsets.versionToExtract + ZipVersionOffsets.version, offset, 0), r->versionToExtract.version);
	printf(" - versionToExtract.hostOs%s: %u\n", fillOffset(offsets.versionToExtract + ZipVersionOffsets.hostOs, offset, 0), r->versionToExtract.hostOs);
	printf(" - flags%s:", fillOffset(offsets.flags, offset, 0));
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
	printf(" - compression%s: %u\n", fillOffset(offsets.compression, offset, 0), r->compression);
	printf(" - fileTime%s: %u\n", fillOffset(offsets.fileTime, offset, 0), r->fileTime);
	printf(" - fileDate%s: %u\n", fillOffset(offsets.fileDate, offset, 0), r->fileDate);
	printf(" - crc%s: %u\n", fillOffset(offsets.crc, offset, 0), r->crc);
	printf(" - compressedSize%s: %u\n", fillOffset(offsets.compressedSize, offset, 0), r->compressedSize);
	printf(" - uncompressedSize%s: %u\n", fillOffset(offsets.uncompressedSize, offset, 0), r->uncompressedSize);
	printf(" - fileNameLength%s: %u\n", fillOffset(offsets.fileNameLength, offset, 0), r->fileNameLength);
	printf(" - extraFieldLength%s: %u\n", fillOffset(offsets.extraFieldLength, offset, 0), r->extraFieldLength);
	printf(" - fileCommentLength%s: %u\n", fillOffset(offsets.fileCommentLength, offset, 0), r->fileCommentLength);
	printf(" - diskNumberStart%s: %u\n", fillOffset(offsets.diskNumberStart, offset, 0), r->diskNumberStart);
	printf(" - internalAttributes%s: %u\n", fillOffset(offsets.internalAttributes, offset, 0), r->internalAttributes);
	printf(" - externalAttributes%s: %u\n", fillOffset(offsets.externalAttributes, offset, 0), r->externalAttributes);
	printf(" - headerOffset%s: %u\n", fillOffset(offsets.headerOffset, offset, 0), r->headerOffset);
	printf(" - fileName%s: ", fillOffset(offsets.fileName, offset, 0));
	if ( r->fileNameLength != 0 )
	{
		if ( !checkFileSpace(offset, 0, size_of_entry + r->fileNameLength, file_size) )
			return;
		r_size = readStandardBlockIfLargeBlockIsExceeded(offset, 0, size_of_entry+r->fileNameLength, block_s, fp);
		if ( r_size == 0 )
			return;
		else if ( r_size == 2 )
			ptr = &block_s[0];

		for ( i = 0; i < r->fileNameLength; i++ )
		{
			printf("%c", ptr[ZipDirEntryOffsets.fileName + i]);
		}
	}
	printf("\n");
	printf(" - fileComment%s: ", fillOffset(offsets.fileComment, offset, 0));
	if ( r->fileCommentLength != 0 )
	{
		if ( !checkFileSpace(offset, 0, size_of_entry + r->fileCommentLength, file_size) )
			return;

		r_size = readStandardBlockIfLargeBlockIsExceeded(offset, 0, size_of_entry+r->fileCommentLength, block_s, fp);
		if ( r_size == 0 )
			return;
		else if ( r_size == 2 )
			ptr = &block_s[0];

		for ( i = 0; i < r->fileCommentLength; i++ )
		{
			printf("%c", ptr[ZipDirEntryOffsets.fileComment + i]);
		}
	}
	printf("\n");
}

void ZIP_printEndLocator(const ZipEndLocator* r,
                         const unsigned char* ptr,
                         uint64_t offset,
                         size_t file_size,
                         FILE* fp,
                         unsigned char* block_s)
{
	uint16_t i;
	Zip_End_Locator_Offsets offsets = ZipEndLocatorOffsets;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_END_LOCATOR;
	uint8_t r_size;

	printf("Zip End Locator:\n");
	printf(" - signature%s: %02x|%02x|%02x|%02x\n", fillOffset(offsets.signature, offset, 0), r->signature[0], r->signature[1], r->signature[2], r->signature[3]);
	printf(" - diskNumber%s: %u\n", fillOffset(offsets.diskNumber, offset, 0), r->diskNumber);
	printf(" - startDiskNumber%s: %u\n", fillOffset(offsets.startDiskNumber, offset, 0), r->startDiskNumber);
	printf(" - entriesOnDisk%s: %u\n", fillOffset(offsets.entriesOnDisk, offset, 0), r->entriesOnDisk);
	printf(" - entriesInDirectory%s: %u\n", fillOffset(offsets.entriesInDirectory, offset, 0), r->entriesInDirectory);
	printf(" - directorySize%s: %u\n", fillOffset(offsets.directorySize, offset, 0), r->directorySize);
	printf(" - directoryOffset%s: %u\n", fillOffset(offsets.directoryOffset, offset, 0), r->directoryOffset);
	printf(" - commentLength%s: %u\n", fillOffset(offsets.commentLength, offset, 0), r->commentLength);
	printf(" - comment%s: ", fillOffset(offsets.comment, offset, 0));
	if ( r->commentLength != 0 )
	{
		if ( !checkFileSpace(offset, 0, size_of_entry + r->commentLength, file_size) )
			return;
		r_size = readStandardBlockIfLargeBlockIsExceeded(offset, 0, size_of_entry+r->commentLength, block_s, fp);
		if ( r_size == 0 )
			return;
		else if ( r_size == 2 )
			ptr = &block_s[0];

		for ( i = 0; i < r->commentLength; i++ )
		{
			printf("%c", ptr[ZipEndLocatorOffsets.comment + i]);
		}
	}
	printf("\n");
}

#endif