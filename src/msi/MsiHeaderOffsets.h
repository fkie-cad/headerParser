#ifndef HEADER_PARSER_MSI_HEADER_OFFSETS_H
#define HEADER_PARSER_MSI_HEADER_OFFSETS_H

//typedef struct Zip_Data_Description_Offsets {
//	uint8_t ddSignature;
//	uint8_t ddCRC;
//	uint8_t ddCompressedSize;
//	uint8_t ddUncompressedSize;
//} Zip_Data_Description_Offsets;
//
//const Zip_Data_Description_Offsets ZipDataDescriptionOffsets = {
//		.ddSignature = 0,
//		.ddCRC = 4,
//		.ddCompressedSize = 8,
//		.ddUncompressedSize = 12,
//};
typedef struct MSI_Structured_Storage_Header_Offsets {
	uint16_t _abSig;
	uint16_t _clsid;
	uint16_t _uMinorVersion;
	uint16_t _uMajorVersion;
	uint16_t _uByteOrder;
	uint16_t _uSectorShift;
	uint16_t _uMiniSectorShift;
	uint16_t _usReserved;
	uint16_t _ulReserved1;
	uint16_t _csectDir;
	uint16_t _csectFat;
	uint16_t _sectDirStart;
	uint16_t _signature;
	uint16_t _ulMiniSectorCutoff;
	uint16_t _sectMiniFatStart;
	uint16_t _csectMiniFat;
	uint16_t _sectDifStart;
	uint16_t _csectDif;
	uint16_t _sectFat;
} MSI_Structured_Storage_Header_Offsets;

const MSI_Structured_Storage_Header_Offsets MSIStructuredStorageHeaderOffsets = {
	._abSig = 0x00,
	._clsid = 0x08,
	._uMinorVersion = 0x18,
	._uMajorVersion = 0x1a,
	._uByteOrder = 0x1c,
	._uSectorShift = 0x1e,
	._uMiniSectorShift = 0x20,
	._usReserved = 0x22,
	._ulReserved1 = 0x24,
	._csectDir = 0x28,
	._csectFat = 0x2c,
	._sectDirStart = 0x30,
	._signature = 0x34,
	._ulMiniSectorCutoff = 0x38,
	._sectMiniFatStart = 0x3c,
	._csectMiniFat = 0x40,
	._sectDifStart = 0x44,
	._csectDif = 0x48,
	._sectFat = 0x4c,
};

#endif
