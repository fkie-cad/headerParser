#ifndef HEADER_PARSER_MSI_HEADER_H
#define HEADER_PARSER_MSI_HEADER_H

#include <stdint.h>

#define MSI_SSH_AB_SIG_SIZE 8
#define MSI_SSH_CLS_ID_SIZE 16
#define MSI_SSH_SECT_FAT_SIZE 109
#define MSI_DIR_ENTRY_NAME_LN 0x40

const unsigned char MAGIC_MSI_BYTES[] = { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 };

const uint8_t MAGIC_MSI_BYTES_LN = 8;

const int SIZE_OF_MSI_HEADER = 512;
const uint32_t FREESECT = 0xFFFFFFFF; // denotes an unused sector
const uint32_t ENDOFCHAIN = 0xFFFFFFFE; // marks the last sector in a FAT chain
const uint32_t FATSECT = 0xFFFFFFFD; // marks a sector used to store part of the FAT

const uint32_t DIFSECT = 0xFFFFFFFC; // marks a sector used to store part of the DIFAT
const uint16_t MSI_INTEL_BYTE_ORDERING = 0xFFFE;

typedef struct MSIStructuredStorageHeader { // [offset from start (bytes), length (bytes)]
    uint8_t _abSig[MSI_SSH_AB_SIG_SIZE]; // [00H,08] {0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1} for current version
    uint8_t _clsid[MSI_SSH_CLS_ID_SIZE]; // [08H,16] reserved must be zero (WriteClassStg GetClassFile uses root directory class id)
    uint16_t _uMinorVersion; // [18H,02] minor version of the format: 33 is written by reference implementation
    uint16_t _uMajorVersion; // [1AH,02] major version of the dll/format: 3 for 512-byte sectors, 4 for 4 KB sectors
    uint16_t _uByteOrder; // [1CH,02] 0xFFFE: indicates Intel byte-ordering
    uint16_t _uSectorShift; // [1EH,02] size of sectors in power-of-two; typically 9 indicating 512-byte sectors
    uint16_t _uMiniSectorShift; // [20H,02] size of mini-sectors in power-of-two; typically 6 indicating 64-byte mini-sectors
    uint16_t _usReserved; // [22H,02] reserved, must be zero
    uint32_t _ulReserved1; // [24H,04] reserved, must be zero
    uint32_t _csectDir; // [28H,04] must be zero for 512-byte sectors, number of SECTs in directory chain for 4 KB sectors
    uint32_t _csectFat; // [2CH,04] number of SECTs in the FAT chain
    uint32_t _sectDirStart; // [30H,04] first SECT in the directory chain
    uint32_t _signature; // [34H,04] signature used for transactions; must be zero. The reference implementation does not support transactions
    uint32_t _ulMiniSectorCutoff; // [38H,04] maximum size for a mini stream; typically 4096 bytes
    uint32_t _sectMiniFatStart; // [3CH,04] first SECT in the MiniFAT chain
    uint32_t _csectMiniFat; // [40H,04] number of SECTs in the MiniFAT chain
    uint32_t _sectDifStart; // [44H,04] first SECT in the DIFAT chain
    uint32_t _csectDif; // [48H,04] number of SECTs in the DIFAT chain
    uint32_t _sectFat[MSI_SSH_SECT_FAT_SIZE]; // [4CH,436] the SECTs of first 109 FAT sectors
} MSIStructuredStorageHeader;

typedef struct MSIDirectoryEntry
{
    char DirectoryEntryName[MSI_DIR_ENTRY_NAME_LN];
    uint16_t DirectoryEntryNameLength;
    uint8_t ObjectType;
    uint8_t ColorFlag;
    uint32_t LeftSiblingID;
    uint32_t RightSiblingID;
    uint32_t ChildID;
    uint8_t CLSID[MSI_SSH_CLS_ID_SIZE];
    uint32_t StateBits;
    uint64_t CreationTime;
    uint64_t ModifiedTime;
    uint32_t StartingSectorLocation;
    uint64_t StreamSize;
} MSIDirectoryEntry;

#endif
