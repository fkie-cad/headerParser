#ifndef HEADER_PARSER_PE_OPTIONAL_HEADER_SIGNATURE_H
#define HEADER_PARSER_PE_OPTIONAL_HEADER_SIGNATURE_H

#include <stdint.h>

struct Pe_Optional_Header_Signature
{
    uint16_t IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    uint16_t IMAGE_ROM_OPTIONAL_HDR_MAGIC;
};

const struct Pe_Optional_Header_Signature PeOptionalHeaderSignature =
{
    0x10b, // 32 bit executable image
    0x20b, // 64 bit executable image
    0x107 // ROM image
};

#endif
