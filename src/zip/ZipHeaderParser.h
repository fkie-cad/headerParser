#ifndef HEADER_PARSER_ZIP_HEADER_PARSER_H
#define HEADER_PARSER_ZIP_HEADER_PARSER_H

#include "../utils/common_fileio.h"
#include "../utils/Helper.h"
#include "../stringPool.h"
#include "../ArchitectureInfo.h"
#include "ZipHeader.h"
#include "ZipHeaderOffsets.h"
#include "ZipHeaderPrinter.h"



static void parseZip();
static uint64_t ZIPhandleFileRecord(uint64_t offset, uint16_t* found_needles, uint32_t record_count);
static uint8_t ZIPcheckNeedles(ZipFileRecord* r, uint64_t offset, uint16_t* found_needles, uint32_t record_count);
static uint64_t ZIPhandleDirEntry(uint64_t offset, uint16_t* found_needles, uint32_t record_count);
static uint64_t ZIPhandleEndLocator(uint64_t offset);
static uint8_t ZIPcheckNameOfRecord(const unsigned char* ptr, uint16_t frFileNameLength, const char* expected);
static size_t ZIPfillRecored(ZipFileRecord* fr, const unsigned char* ptr, uint64_t offset);
static void ZIPfillDirEntry(ZipDirEntry* de, const unsigned char* ptr);
static void ZIPfillEndLocator(ZipEndLocator* r, const unsigned char* ptr);
static uint64_t ZIPfindDataDescriptionOffset(uint64_t start_i, ZipFileRecord* fr);
static uint8_t ZIPusesDataDescritpor(const ZipFileRecord* fr);
static uint8_t ZIPnameHasFileType(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle);
static uint8_t ZIPnameStartsWith(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle);
static uint8_t isJar(const uint16_t found_needles[4]);



void parseZip()
{
	uint64_t offset = 0;
	uint32_t record_count = 0;
	uint32_t dir_count = 0;
	uint16_t found_needles[5] = {0};

	debug_info("parseZip\n");

	while ( 1 )
	{
		if ( !checkFileSpace(offset, abs_file_offset, MAGIC_ZIP_BYTES_LN, "MAGIC_ZIP_BYTES_LN") )
			break;
		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, MAGIC_ZIP_BYTES_LN, "MAGIC_ZIP_BYTES_LN"))
			break;

		debug_info("magic: %02x%02x%02x%02x\n", block_large[offset], block_large[offset+1], block_large[offset+2], block_large[offset+3]);
		debug_info("offset: 0x%lx\n", offset);
		debug_info("abs_file_offset: 0x%lx\n", abs_file_offset);

		if ( checkBytes(MAGIC_ZIP_FILE_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &block_large[offset]) )
		{
			debug_info("record: %u\n", record_count);
			offset = ZIPhandleFileRecord(offset, found_needles, record_count);
			if ( offset == UINT64_MAX )
				break;

			record_count++;
		}
		else if ( info_level == INFO_LEVEL_BASIC )
		{
			break;
		}
		else if ( checkBytes(MAGIC_ZIP_DIR_ENTRY_BYTES, MAGIC_ZIP_BYTES_LN, &block_large[offset]) )
		{
			debug_info("dir: %u\n", dir_count);
			offset = ZIPhandleDirEntry(offset, found_needles, dir_count);
			if ( offset == UINT64_MAX )
				break;

			dir_count++;
		}
		else if ( checkBytes(MAGIC_ZIP_END_LOCATOR_BYTES, MAGIC_ZIP_BYTES_LN, &block_large[offset]) )
		{
			debug_info("The end!\n");
			offset = ZIPhandleEndLocator(offset);
			break;
		}
		else
		{
			break;
		}

		if ( abs_file_offset + offset > file_size )
		{
			header_info("INFO: Reached end of file.\n");
			break;
		}
	}

	if ( isJar(found_needles) )
	{
		HD->headertype = HEADER_TYPE_JAR;
		HD->CPU_arch = ARCH_JAVA;
		HD->Machine = "Jar Archive";
	}
	else if ( found_needles[3] > 0 )
	{
		HD->headertype = HEADER_TYPE_WORD_DOC_X;
		HD->CPU_arch = ARCH_UNSUPPORTED;
		HD->Machine = architecture_names[ARCH_UNSUPPORTED];
	}
	else if ( found_needles[4] > 0 )
	{
		HD->headertype = HEADER_TYPE_APK;
		HD->CPU_arch = ARCH_ANDROID;
		// TODO: find classes.dex and parse
		HD->Machine = architecture_names[ARCH_UNSUPPORTED];
	}
	else
	{
		HD->headertype = HEADER_TYPE_ZIP;
		HD->CPU_arch = ARCH_UNSUPPORTED;
		HD->Machine = architecture_names[ARCH_UNSUPPORTED];
	}
}

uint64_t ZIPhandleFileRecord(uint64_t offset, uint16_t* found_needles, uint32_t record_count)
{
	ZipFileRecord fr = {0};
	unsigned char* ptr;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_RECORD;
	size_t dd_offset;

	if ( !checkFileSpace(offset, abs_file_offset, size_of_entry, "size_of_entry") )
		return UINT64_MAX;
	debug_info("offset: 0x%lx\n", offset);
	if ( !checkLargeBlockSpace(&offset, &abs_file_offset, size_of_entry, "size_of_entry") )
		return UINT64_MAX;

	ptr = &block_large[offset];

	dd_offset = ZIPfillRecored(&fr, ptr, offset);

	if ( info_level >= INFO_LEVEL_FULL )
		ZIPprintFileEntry(&fr, ptr, record_count, abs_file_offset + offset, dd_offset);

	ZIPcheckNeedles(&fr, offset, found_needles, record_count);

	debug_info(" - - - frDataDescr.ddCompressedSize: 0x%x (%u)\n", fr.dataDescr.ddCompressedSize, fr.dataDescr.ddCompressedSize);
	offset += size_of_entry + fr.compressedSize + fr.fileNameLength + fr.extraFieldLength;
//	offset += size_of_entry + ((fr.compressedSize > 0) ? fr.compressedSize : fr.uncompressedSize) + fr.fileNameLength + fr.extraFieldLength;
	debug_info(" - abs_file_offset+offset: 0x%lx + 0x%lx =  0x%lx\n", abs_file_offset, offset, (abs_file_offset+offset));
	if ( ZIPusesDataDescritpor(&fr) )
		offset = dd_offset + SIZE_OF_ZIP_DATA_DESCRIPTION - abs_file_offset;
//		offset += SIZE_OF_ZIP_DATA_DESCRIPTION;
//		if ( fr.compressedSize == 0 )
//			offset += fr.dataDescr.ddCompressedSize;

	debug_info(" - abs_file_offset+offset: 0x%lx + 0x%lx =  0x%lx\n", abs_file_offset, offset, (abs_file_offset+offset));
	debug_info(" - offset += dd_offset + SIZE_OF_ZIP_DATA_DESCRIPTION - abs_file_offset: 0x%lx + 0x%x - 0x%lx =  0x%lx\n",
			dd_offset, SIZE_OF_ZIP_DATA_DESCRIPTION, abs_file_offset, (dd_offset+ SIZE_OF_ZIP_DATA_DESCRIPTION- abs_file_offset));


	return offset;
}

size_t ZIPfillRecored(ZipFileRecord* fr, const unsigned char* ptr, uint64_t offset)
{
	size_t dd_offset = 0;
	int i;

	for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
		fr->signature[i] = ptr[ZipFileRecoredOffsets.signature + i];
	fr->version.version = *((uint8_t*) &ptr[ZipFileRecoredOffsets.version + ZipVersionOffsets.version]);
	fr->version.hostOs = *((uint8_t*) &ptr[ZipFileRecoredOffsets.version + ZipVersionOffsets.hostOs]);
	fr->flags = *((uint16_t*) &ptr[ZipFileRecoredOffsets.flags]);
	fr->compression = *((uint16_t*) &ptr[ZipFileRecoredOffsets.compression]);
	fr->compressedSize = *((uint32_t*) &ptr[ZipFileRecoredOffsets.compressedSize]);
	fr->uncompressedSize = *((uint32_t*) &ptr[ZipFileRecoredOffsets.uncompressedSize]);
	fr->fileNameLength = *((uint32_t*) &ptr[ZipFileRecoredOffsets.fileNameLength]);
	fr->extraFieldLength = *((uint32_t*) &ptr[ZipFileRecoredOffsets.extraFieldLength]);

//	debug_info(" - - frFlags: %u\n", r->frFlags);
//	debug_info(" - - frVersion.version: %u\n", r->frVersion.version);
//	debug_info(" - - frVersion.hostOs: %u\n", r->frVersion.hostOs);
//	debug_info(" - - frCompressedSize: %u\n", r->frCompressedSize);
//	debug_info(" - - frFileNameLength: %u\n", r->frFileNameLength);
//	debug_info(" - - frExtraFieldLength: %u\n", r->frExtraFieldLength);

	if ( ZIPusesDataDescritpor(fr) )
	{
		dd_offset = ZIPfindDataDescriptionOffset(offset, fr);
//		dd_offset = ZIPfindDataDescriptionOffset(offset + fr->fileNameLength + ZipFileRecoredOffsets.fileName);
		uint32_t r_size = readBlock(file_name, dd_offset);
		if ( r_size == 0 )
			return 0;
		debug_info(" - - dd_offset: 0x%lx\n", dd_offset);
		debug_info(" - - abs_file_offset +  dd_offset: 0x%lx\n", abs_file_offset + dd_offset);
		if ( dd_offset < UINT64_MAX )
		{
			ptr = &block_standard[0];

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
uint8_t ZIPusesDataDescritpor(const ZipFileRecord* fr)
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
uint64_t ZIPfindDataDescriptionOffset(uint64_t offset, ZipFileRecord* fr)
{
	uint64_t dd_offset;
	uint64_t f_offset;
	const unsigned char* ptr;
	uint32_t r_size;
	size_t bytes_searched = 0;

	if ( fr->compressedSize != 0 )
	{
		// if compressed size, dd should immediately follow ?
		dd_offset =  abs_file_offset + offset + MIN_SIZE_OF_ZIP_RECORD + fr->compressedSize + fr->fileNameLength + fr->extraFieldLength;

		r_size = readBlock(file_name, dd_offset);
		if ( r_size == 0 )
			return UINT64_MAX;
		ptr = &block_standard[0];

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

	r_size = readBlock(file_name, f_offset);
	if ( r_size == 0 )
		return UINT64_MAX;
	offset = 0;
	debug_info(" - - ZIPfindDataDescriptionOffset\n");
	debug_info(" - - - offset: 0x%lx\n", offset);
	debug_info(" - - - f_offset: 0x%lx\n", f_offset);

	while ( 1 )
	{
		if ( !checkStandardBlockSpace(&offset, &f_offset, SIZE_OF_ZIP_DATA_DESCRIPTION+4, "SIZE_OF_ZIP_DATA_DESCRIPTION") )
			return UINT64_MAX;

		ptr = &block_standard[offset];
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
			debug_info(" - - - - found 0x%lx\n", offset);
			return f_offset + offset;
		}

		offset++;
		bytes_searched++;
		if ( f_offset + SIZE_OF_ZIP_DATA_DESCRIPTION > file_size )
		{
			debug_info(" - - - - f_offset (%lu) + %u = (%lu) > file_size (%u)\n", f_offset, SIZE_OF_ZIP_DATA_DESCRIPTION, f_offset+3, file_size);
			break;
		}
	}
	return UINT64_MAX;
}

uint64_t ZIPhandleDirEntry(uint64_t offset, uint16_t* found_needles, uint32_t record_count)
{
	ZipDirEntry de;
	unsigned char* ptr;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_DIR_ENTRY;

	if ( !checkFileSpace(offset, abs_file_offset, size_of_entry, "size_of_entry") )
		return UINT64_MAX;
	if ( !checkLargeBlockSpace(&offset, &abs_file_offset, size_of_entry, "size_of_entry") )
		return UINT64_MAX;

	ptr = &block_large[offset];

	ZIPfillDirEntry(&de, ptr);

	if ( info_level >= INFO_LEVEL_FULL )
		ZIPprintDirEntry(&de, ptr, record_count, abs_file_offset + offset);

	offset += size_of_entry + de.fileNameLength + de.fileCommentLength + de.extraFieldLength;
	debug_info(" - abs_file_offset+offset: 0x%lx (%lu)\n", abs_file_offset+offset, abs_file_offset+offset);

	return offset;
}

void ZIPfillDirEntry(ZipDirEntry* de, const unsigned char* ptr)
{
	int i;

	for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
		de->signature[i] = ptr[ZipDirEntryOffsets.signature + i];
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

uint64_t ZIPhandleEndLocator(uint64_t offset)
{
	ZipEndLocator el;
	unsigned char* ptr;
	uint8_t size_of_entry = MIN_SIZE_OF_ZIP_END_LOCATOR;

	debug_info("ZIPhandleEndLocator\n");
	debug_info("offset: %lu\n", offset);

	if ( !checkFileSpace(offset, abs_file_offset, size_of_entry, "size_of_entry") )
		return UINT64_MAX;
	if ( !checkLargeBlockSpace(&offset, &abs_file_offset, size_of_entry, "size_of_entry"))
		return UINT64_MAX;

	ptr = &block_large[offset];

	ZIPfillEndLocator(&el, ptr);

	debug_info(" - abs_file_offset+offset: 0x%lx (%lu)\n", abs_file_offset+offset, abs_file_offset+offset);

	if ( info_level >= INFO_LEVEL_FULL )
		ZIPprintEndLocator(&el, ptr, abs_file_offset + offset);

	return offset;
}

void ZIPfillEndLocator(ZipEndLocator* r, const unsigned char* ptr)
{
	int i;

	for ( i = 0; i < MAGIC_ZIP_BYTES_LN; i++ )
		r->signature[i] = ptr[ZipEndLocatorOffsets.signature + i];
	r->diskNumber = *((uint16_t*) &ptr[ZipEndLocatorOffsets.diskNumber]);
	r->startDiskNumber = *((uint16_t*) &ptr[ZipEndLocatorOffsets.startDiskNumber]);
	r->entriesOnDisk = *((uint16_t*) &ptr[ZipEndLocatorOffsets.entriesOnDisk]);
	r->entriesInDirectory = *((uint16_t*) &ptr[ZipEndLocatorOffsets.entriesInDirectory]);
	r->directorySize = *((uint16_t*) &ptr[ZipEndLocatorOffsets.directorySize]);
	r->directoryOffset = *((uint16_t*) &ptr[ZipEndLocatorOffsets.directoryOffset]);
	r->commentLength = *((uint16_t*) &ptr[ZipEndLocatorOffsets.commentLength]);
}

uint8_t ZIPcheckNameOfRecord(const unsigned char* ptr, uint16_t frFileNameLength, const char* expected)
{
	uint16_t i;
	for ( i = 0; i < frFileNameLength; i++ )
	{
		if ( ptr[ZipFileRecoredOffsets.fileName + i] != expected[i] )
			return 0;
	}

	return 1;
}

uint8_t ZIPnameHasFileType(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle)
{
	uint16_t i, j;
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

uint8_t ZIPnameStartsWith(const unsigned char* ptr, uint16_t frFileNameLength, const char* needle)
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
 * @param offset uint64_t
 * @param found_needles uint16_t*
 * @param record_count uint32_t
 * @return uint64_t
 */
uint8_t ZIPcheckNeedles(ZipFileRecord* r, uint64_t offset, uint16_t* found_needles, uint32_t record_count)
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
	unsigned char* ptr = &block_large[offset];

	if ( r->fileNameLength != 0 )
	{
		if ( !checkFileSpace(offset, abs_file_offset, size_of_entry + r->fileNameLength, "sizeof RecordEntry + frFileNameLength") )
			return 0;
		i = readStandardBlockIfLargeBlockIsExceeded(offset, abs_file_offset, size_of_entry+r->fileNameLength, "sizeof RecordEntry + frFileNameLength");
		if ( i == 2 )
			ptr = &block_standard[0];
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
			if ( !ZIPcheckNameOfRecord(ptr, r->fileNameLength, needles[record_count]) )
				found_needles[record_count]++;
		}
		else
		{
			if ( ZIPnameHasFileType(ptr, r->fileNameLength, needles[2]) )
				found_needles[2]++;
			if ( ZIPnameStartsWith(ptr, r->fileNameLength, needles[3]) )
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
