#ifndef HEADER_PARSER_PH_FLAGS_H
#define HEADER_PARSER_PH_FLAGS_H

#include <stdint.h>

struct Program_Header_Flags
{
    uint32_t PF_X; // Execute
    uint32_t PF_W; // Read
    uint32_t PF_R; // Write
    uint32_t PF_MASKOS; // Unspecified
    uint32_t PF_MASKPROC; // Unspecified
};

const struct Program_Header_Flags ProgramHeaderFlags = {
    .PF_X = 0x00000001,
    .PF_W = 0x00000002,
    .PF_R = 0x00000004,
    .PF_MASKOS = 0x0ff00000,
    .PF_MASKPROC = 0xf0000000
};

#endif