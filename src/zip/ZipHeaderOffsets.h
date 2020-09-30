#ifndef HEADER_PARSER_ZIP_HEADER_OFFSETS_H
#define HEADER_PARSER_ZIP_HEADER_OFFSETS_H

typedef struct Zip_Data_Description_Offsets {
	uint8_t signature;
	uint8_t crc;
	uint8_t compressedSize;
	uint8_t uncompressedSize;
} Zip_Data_Description_Offsets;

const Zip_Data_Description_Offsets ZipDataDescriptionOffsets = {
		.signature = 0,
		.crc = 4,
		.compressedSize = 8,
		.uncompressedSize = 12,
};

typedef struct Zip_Version_Offsets {
	uint8_t version;
	uint8_t hostOs;
} Zip_Version_Offsets;

const Zip_Version_Offsets ZipVersionOffsets = {
	.version = 0,
	.hostOs = 1,
};

typedef struct Zip_File_Recored_Offsets {
	uint8_t signature;
	uint8_t version;
	uint8_t flags;
	uint8_t compression;
	uint8_t fileTime;
	uint8_t fileDate;
	uint8_t crc;
	uint8_t compressedSize;
	uint8_t uncompressedSize;
	uint8_t fileNameLength;
	uint8_t extraFieldLength;
	uint8_t fileName;
	uint8_t extraField; // ??
	uint8_t data; // comes after name
	uint8_t dataDescr; // comes after name
} Zip_File_Recored_Offsets;

const Zip_File_Recored_Offsets ZipFileRecoredOffsets = {
	.signature = 0,
	.version = 4,
	.flags = 6,
	.compression = 8,
	.fileTime = 10,
	.fileDate = 12,
	.crc = 14,
	.compressedSize = 18,
	.uncompressedSize = 22,
	.fileNameLength = 26,
	.extraFieldLength = 28,
	.fileName = 30,
	.extraField = 30, // ??
	.data = 30, // located after name
	.dataDescr = 30, // located after name
};

typedef struct Zip_Dir_Entry_Offsets {
	uint8_t signature;
	uint8_t versionMadeBy;
	uint8_t versionToExtract;
	uint8_t flags;
	uint8_t compression;
	uint8_t fileTime;
	uint8_t fileDate;
	uint8_t crc;
	uint8_t compressedSize;
	uint8_t uncompressedSize;
	uint8_t fileNameLength;
	uint8_t extraFieldLength;
	uint8_t fileCommentLength;
	uint8_t diskNumberStart;
	uint8_t internalAttributes;
	uint8_t externalAttributes;
	uint8_t headerOffset;
	uint8_t fileName;
	uint8_t extraField;
	uint8_t fileComment;
} Zip_Dir_Entry_Offsets;

const Zip_Dir_Entry_Offsets ZipDirEntryOffsets = {
	.signature = 0,
	.versionMadeBy = 4,
	.versionToExtract = 6,
	.flags = 8,
	.compression = 10,
	.fileTime = 12,
	.fileDate = 14,
	.crc = 16,
	.compressedSize = 20,
	.uncompressedSize = 24,
	.fileNameLength = 28,
	.extraFieldLength = 30,
	.fileCommentLength = 32,
	.diskNumberStart = 34,
	.internalAttributes = 36,
	.externalAttributes = 38,
	.headerOffset = 42,
	.fileName = 46,
	.extraField = 46,
	.fileComment = 46,
};

typedef struct Zip_End_Locator_Offsets {
	uint8_t signature;
	uint8_t diskNumber;
	uint8_t startDiskNumber;
	uint8_t entriesOnDisk;
	uint8_t entriesInDirectory;
	uint8_t directorySize;
	uint8_t directoryOffset;
	uint8_t commentLength;
	uint8_t comment;
} Zip_End_Locator_Offsets;

const Zip_End_Locator_Offsets ZipEndLocatorOffsets = {
	.signature = 0,
	.diskNumber = 4,
	.startDiskNumber = 6,
	.entriesOnDisk = 8,
	.entriesInDirectory = 10,
	.directorySize = 12,
	.directoryOffset = 16,
	.commentLength = 20,
	.comment = 22,
};

#endif
