#ifndef HEADER_PARSER_ZIP_HEADER_H
#define HEADER_PARSER_ZIP_HEADER_H

const unsigned char MAGIC_ZIP_DIR_ENTRY_BYTES[] = { 0x50, 0x4B, 0x01, 0x02 };
const unsigned char MAGIC_ZIP_FILE_ENTRY_BYTES[] = { 0x50, 0x4B, 0x03, 0x04 };
const unsigned char MAGIC_ZIP_END_LOCATOR_BYTES[] = { 0x50, 0x4B, 0x05, 0x06 };
const unsigned char MAGIC_ZIP_DATA_DESCRIPTOR_BYTES[] = { 0x50, 0x4B, 0x07, 0x08 };

const uint8_t MAGIC_ZIP_BYTES_LN = 4;

const int MIN_SIZE_OF_ZIP_RECORD = 0x1e;
const int MIN_SIZE_OF_ZIP_DIR_ENTRY = 0x2e;
const int MIN_SIZE_OF_ZIP_END_LOCATOR = 0x16;
const int SIZE_OF_ZIP_DATA_DESCRIPTION = 0x10;

const uint8_t ZIP_VS_1_0 = 0x0a;
const uint8_t ZIP_VS_2_0 = 0x14;

typedef enum {
	COMP_STORED    = 0,
	COMP_SHRUNK    = 1,
	COMP_REDUCED1  = 2,
	COMP_REDUCED2  = 3,
	COMP_REDUCED3  = 4,
	COMP_REDUCED4  = 5,
	COMP_IMPLODED  = 6,
	COMP_TOKEN     = 7,
	COMP_DEFLATE   = 8,
	COMP_DEFLATE64 = 9
} ZipCompressionType;

typedef struct ZipVersion {
	uint8_t version;
	uint8_t hostOs;
} ZipVersion;

typedef struct Zip_Flag_Types {
	uint16_t FLAG_Encrypted; //Bit 0: If set, indicates that the file is encrypted.
	uint16_t FLAG_CompressionFlagBit1;
	uint16_t FLAG_CompressionFlagBit2;
	uint16_t FLAG_DescriptorUsedMask;
	uint16_t FLAG_Reserved1;
	uint16_t FLAG_Reserved2;
	uint16_t FLAG_StrongEncrypted; //Bit 6: Strong encryption
	uint16_t FLAG_CurrentlyUnused1;
	uint16_t FLAG_CurrentlyUnused2;
	uint16_t FLAG_CurrentlyUnused3;
	uint16_t FLAG_CurrentlyUnused4;
	uint16_t FLAG_Utf8; // Bit 11: filename and comment encoded using UTF-8
	uint16_t FLAG_ReservedPKWARE1;
	uint16_t FLAG_CDEncrypted; // Bit 13: Used when encrypting the Central Directory to indicate selected data values in the Local Header are masked to hide their actual values.
	uint16_t FLAG_ReservedPKWARE2;
	uint16_t FLAG_ReservedPKWARE3;
} Zip_Flag_Types;

const Zip_Flag_Types ZipFlagTypes = {
	.FLAG_Encrypted             = 0x0001, //Bit 0: If set, indicates that the file is encrypted.
	.FLAG_CompressionFlagBit1   = 0x0002,
	.FLAG_CompressionFlagBit2   = 0x0004,
	.FLAG_DescriptorUsedMask    = 0x0008, // DataDescriptor Flag
	.FLAG_Reserved1             = 0x0010,
	.FLAG_Reserved2             = 0x0020,
	.FLAG_StrongEncrypted       = 0x0040, // Bit 6: Strong encryption
	.FLAG_CurrentlyUnused1      = 0x0080,
	.FLAG_CurrentlyUnused2      = 0x0100,
	.FLAG_CurrentlyUnused3      = 0x0200,
	.FLAG_CurrentlyUnused4      = 0x0400,
	.FLAG_Utf8                  = 0x0800, // Bit 11: filename and comment encoded using UTF-8
	.FLAG_ReservedPKWARE1       = 0x1000,
	.FLAG_CDEncrypted           = 0x2000, // Bit 13: Used when encrypting the Central Directory to indicate selected data values in the Local Header are masked to hide their actual values.
	.FLAG_ReservedPKWARE2       = 0x4000,
	.FLAG_ReservedPKWARE3       = 0x8000,
};

typedef struct ZipDataDescription {
	char ddSignature[4]; //0x08074b50
	uint32_t ddCRC;
	uint32_t ddCompressedSize;
	uint32_t ddUncompressedSize;
} ZipDataDescription;

typedef struct ZipFileRecored {
	char signature[4];    //0x04034b50
	ZipVersion version;
	uint16_t flags;
	uint16_t compression;
	uint16_t fileTime;
	uint16_t fileDate;
	uint32_t crc;
	uint32_t compressedSize;
	uint32_t uncompressedSize;
	uint16_t fileNameLength;
	uint16_t extraFieldLength;
	char* fileName;
	unsigned char* extraField;
	unsigned char* data;
//	It is byte aligned and immediately follows the last byte of compressed data.
//	Although not originally assigned a signature,
//	the value 0x08074b50 has commonly been adopted as a signature value for the data descriptor record.
//	Implementers SHOULD be aware that ZIP files MAY be encountered with or without this signature marking data descriptors
	ZipDataDescription dataDescr;
} ZipFileRecord;

typedef struct ZipDirEntry{
	char signature[4];
	ZipVersion versionMadeBy;
	ZipVersion versionToExtract;
	uint16_t flags;
	uint16_t compression;
	uint16_t fileTime;
	uint16_t fileDate;
	uint32_t crc;
	uint32_t compressedSize;
	uint32_t uncompressedSize;
	uint16_t fileNameLength;
	uint16_t extraFieldLength;
	uint16_t fileCommentLength;
	uint16_t diskNumberStart;
	uint16_t internalAttributes;
	uint32_t externalAttributes;
	uint32_t headerOffset;
	char* fileName;
	unsigned char* extraField;
	unsigned char* fileComment;
} ZipDirEntry;

typedef struct ZipEndLocator{
	char signature[4];    //0x06054b50
	uint16_t diskNumber;
	uint16_t startDiskNumber;
	uint16_t entriesOnDisk;
	uint16_t entriesInDirectory;
	uint32_t directorySize;
	uint32_t directoryOffset;
	uint16_t commentLength;
	char* comment;
} ZipEndLocator;

#endif
