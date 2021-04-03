#ifndef HEADER_PARSER_ELF_PH_TYPES_H
#define HEADER_PARSER_ELF_PH_TYPES_H

#include <stdint.h>

struct Program_Header_Types
{
    uint32_t PT_NULL; // Program header table entry unused
    uint32_t PT_LOAD; // Loadable segment
    uint32_t PT_DYNAMIC; // Dynamic linking information
    uint32_t PT_INTERP; // Interpreter information
    uint32_t PT_NOTE; // Auxiliary information
    uint32_t PT_SHLIB; // reserved
    uint32_t PT_PHDR; // segment containing program header table itself
    uint32_t PT_TLS; // thread-local storage template segment
    uint32_t PT_LOOS; // Values in this inclusive range are reserved for operating system-specific semantics.
    uint32_t PT_HIOS;
    uint32_t PT_LOPROC;	// Values in this inclusive range are reserved for processor-specific semantics. If meanings are specified, the processor supplement explains them.
    uint32_t PT_HIPROC;
};

const struct Program_Header_Types ProgramHeaderTypes = {
    .PT_NULL = 0x00000000,
    .PT_LOAD = 0x00000001,
    .PT_DYNAMIC = 0x00000002,
    .PT_INTERP = 0x00000003,
    .PT_NOTE = 0x00000004,
    .PT_SHLIB = 0x00000005,
    .PT_PHDR = 0x00000006,
    .PT_TLS = 0x00000007,
    .PT_LOOS = 0x60000000,
    .PT_HIOS = 0x6FFFFFFF,
    .PT_LOPROC = 0x70000000,
    .PT_HIPROC = 0x7FFFFFFF,
};

#endif