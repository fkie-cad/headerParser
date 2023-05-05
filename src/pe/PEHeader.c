#include "PEHeader.h"


const uint8_t MAGIC_PE_ARCHIV_BYTES[MAGIC_PE_ARCHIV_BYTES_LN] = { 0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E };

const uint8_t MAGIC_PE_BYTES[MAGIC_PE_BYTES_LN] = { 0x4D, 0x5A };

const uint8_t MAGIC_PE_SIGNATURE[MAGIC_PE_SIGNATURE_LN] = { 0x50, 0x45, 0x00, 0x00 };

const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN] = { 0x4E, 0x45 };

const uint8_t MAGIC_LE_SIGNATURE[MAGIC_LE_SIGNATURE_LN] = { 0x4C, 0x45 };

const uint8_t MAGIC_LX_SIGNATURE[MAGIC_LX_SIGNATURE_LN] = { 0x4C, 0x58 };

//const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN] = { 0x4E, 0x45, 0x05, 0x3C };

//const uint8_t MAGIC_NE_SIGNATURE[MAGIC_NE_SIGNATURE_LN] = { 0x4E, 0x45, 0x06, 0x01 };

const uint8_t MAGIC_DOS_STUB_BEGINNING[MAGIC_DOS_STUB_BEGINNING_LN] = { 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21 };

const char* ImageDirectoryEntryNames[IMAGE_DIRECTORY_ENTRY_NAMES_LN] = {
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "CERTIFICATE",
    "BASE_RELOC",
    "DEBUG",
    "ARCHITECTURE",
    "GLOBAL_PTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "CLR_RUNTIME_HEADER",
    "RESERVED",
};
