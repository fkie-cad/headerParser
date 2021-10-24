#ifndef HEADER_PARSER_ELF_FILE_HEADER_H
#define HEADER_PARSER_ELF_FILE_HEADER_H

#include <stdint.h>

const unsigned char MAGIC_ELF_BYTES[4] = { 0x7F, 0x45, 0x4C, 0x46 };
enum ElfHeaderSizes { MAGIC_ELF_BYTES_LN = 4 };
typedef enum EiClass { ELFCLASSNONE, ELFCLASS32, ELFCLASS64 } EiClass;
typedef enum EiData { ELFDATANONE, ELFDATA2LSB, ELFDATA2MSB } EiData;

typedef struct Elf32FileHeader
{
    uint8_t EI_MAG0; // magic bytes
    uint8_t EI_MAG1;
    uint8_t EI_MAG2;
    uint8_t EI_MAG3;
    uint8_t EI_CLASS; // bitness
    uint8_t EI_DATA; // endian
    uint8_t EI_VERSION; // elf version
    uint8_t EI_OSABI; // target os
    uint8_t EI_ABIVERSION;
    uint8_t EI_PAD[7];
    uint16_t e_type;
    uint16_t e_machine; // instruction set architecture
    uint32_t e_version;
    uint32_t e_entry; // address where execution starts
    uint32_t e_phoff; // start of the program header table
    uint32_t e_shoff; // start of the section header table
    uint32_t e_flags;
    uint16_t e_ehsize; // size of this header
    uint16_t e_phentsize; // size of a program header table entry
    uint16_t e_phnum; // number of entries in the program header table
    uint16_t e_shentsize; // size of a section header table entry
    uint16_t e_shnum; // number of entries in the section header table
    uint16_t e_shstrndx; // index of the section header table entry that contains the section names
} Elf32FileHeader;

// The product of e_phentsize and e_phnum gives the ph table's size in bytes.
typedef struct Elf64FileHeader
{
    uint8_t EI_MAG0; // magic bytes
    uint8_t EI_MAG1;
    uint8_t EI_MAG2;
    uint8_t EI_MAG3;
    uint8_t EI_CLASS; // bitness
    uint8_t EI_DATA; // endian
    uint8_t EI_VERSION; // elf version
    uint8_t EI_OSABI; // target os
    uint8_t EI_ABIVERSION;
    uint8_t EI_PAD[7];
    uint16_t e_type;
    uint16_t e_machine; // instruction set architecture
    uint32_t e_version;
    uint64_t e_entry; // address where execution/program code starts
    uint64_t e_phoff; // start of the program header table
    uint64_t e_shoff; // start of the section header table
    uint32_t e_flags;
    uint16_t e_ehsize; // size of this header
    uint16_t e_phentsize; // size of a program header table entry
    uint16_t e_phnum; // number of entries in the program header table
    uint16_t e_shentsize; // size of a section header table entry
    uint16_t e_shnum; // number of entries in the section header table
    uint16_t e_shstrndx; // index of the section header table entry that contains the section names
} Elf64FileHeader;

#define ELF_SIZE_OF_FILE_HEADER_32 (sizeof(Elf32FileHeader))
#define ELF_SIZE_OF_FILE_HEADER_64 (sizeof(Elf64FileHeader))




// custom type to pass around
typedef struct _Elf_StringTables {
    uint32_t shstrtab_size;
    uint8_t* shstrtab;
    uint32_t strtab_size;
    uint8_t* strtab;
    uint32_t dynstr_size;
    uint8_t* dynstr;
} Elf_StringTables;

void cleanStrTabs(Elf_StringTables* t)
{
    if ( t->shstrtab )
        free(t->shstrtab);
    if ( t->strtab )
        free(t->strtab);
    if ( t->dynstr )
        free(t->dynstr);
}

#endif
