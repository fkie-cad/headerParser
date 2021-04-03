#ifndef HEADER_PARSER_ELF_PH_P_TYPE_H
#define HEADER_PARSER_ELF_PH_P_TYPE_H

#include <stdint.h>

struct elf_ph_p_type
{
    uint32_t PT_NULL;
    uint32_t PT_LOAD;
    uint32_t PT_DYNAMIC;
    uint32_t PT_INTERP;
    uint32_t PT_NOTE;
    uint32_t PT_SHLIB;
    uint32_t PT_PHDR;
    uint32_t PT_LOOS;
    uint32_t PT_HIOS;
    uint32_t PT_LOPROC;
    uint32_t PT_HIPROC;
};

const struct elf_ph_p_type ElfPhPType = {
    .PT_NULL = 0x00000000,
    .PT_LOAD = 0x00000001,
    .PT_DYNAMIC = 0x00000002,
    .PT_INTERP = 0x00000003,
    .PT_NOTE = 0x00000004,
    .PT_SHLIB = 0x00000005,
    .PT_PHDR = 0x00000006,
    .PT_LOOS = 0x60000000,
    .PT_HIOS = 0x6FFFFFFF,
    .PT_LOPROC = 0x70000000,
    .PT_HIPROC = 0x7FFFFFFF
};

#endif
