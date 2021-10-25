#ifndef HEADER_PARSER_ELF_HEADER_PARSER_H
#define HEADER_PARSER_ELF_HEADER_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../ArchitectureInfo.h"
#include "../HeaderData.h"
#include "../utils/Converter.h"
#include "../Globals.h"
#include "ElfEFlags.h"
#include "ElfFileHeader.h"
#include "ElfHeaderOffsets.h"
#include "ElfHeaderPrinter.h"
#include "ElfProgramHeader.h"
#include "ElfSectionHeader.h"
#include "ElfSectionHeaderFlags.h"
#include "ElfSectionParser.h"



static void parseELFHeader(
    PHeaderData hd, 
    PGlobalParams gp, 
    PElfParams elfp
);

static uint8_t Elf_readFileHeader(
    Elf64FileHeader* file_header,
    uint8_t* block_l,
    size_t start_file_offset,
    size_t file_size
);

static void Elf_fillHeaderDataWithFileHeader(
    const Elf64FileHeader* file_header,
    PHeaderData hd
);

static void Elf_readProgramHeaderTable(
    Elf64FileHeader* file_header,
    size_t* abs_file_offset,
    size_t start_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l
);

static uint8_t Elf_programHeaderOffsetsAreValid(
    const Elf64FileHeader* file_header,
    size_t start_file_offset,
    size_t file_size
);

static void Elf_readProgramHeaderTableEntries(
    const Elf64FileHeader* file_header,
    size_t* abs_file_offset,
    size_t start_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l
);

static ElfProgramHeaderOffsets Elf_getProgramHeaderOffsets(
    const Elf64FileHeader* file_header
);

static void Elf_readProgramHeaderTableEntry(
    const uint8_t* ptr,
    ElfProgramHeaderOffsets* ph_offsets,
    const Elf64FileHeader* file_header,
    Elf64ProgramHeader* ph
);

static uint8_t Elf_checkProgramHeaderTableEntry(
    Elf64ProgramHeader* ph,
    uint16_t idx,
    size_t start_file_offset,
    size_t file_size
);

static void Elf_readSectionHeaderTable(
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    PHeaderData hd
);

static uint32_t Elf_readSectionById(
    uint8_t** section,
    uint16_t index,
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t file_size,
    uint8_t* block_s,
    FILE* fp
);

int Elf_readSectionByNameType(
    const char* sec_name,
    uint32_t sec_type,
    Elf_StringTables *strtabs,
    uint8_t **section,
    uint32_t *section_size,
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t* block_l,
    FILE* fp
);

static
int Elf_getSectionTableEntryByNameType(
    const char* sec_name,
    uint32_t sec_type,
    Elf64SectionHeader *sht_entry,
    Elf_StringTables *strtabs,
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t* block_l,
    FILE* fp
);

static uint8_t Elf_sectionHeaderOffsetsAreValid(
    const Elf64FileHeader* file_header,
    size_t start_file_offset,
    size_t file_size
);

static void Elf_readSectionHeaderTableEntry(
    const uint8_t* ptr,
    ElfSectionHeaderOffsets* sh_offsets,
    const Elf64FileHeader* fh,
    Elf64SectionHeader* sh
);

static uint8_t Elf_checkSectionHeaderTableEntry(
    Elf64SectionHeader* sh,
    uint16_t idx,
    char* name,
    size_t start_file_offset,
    size_t file_size
);

static CodeRegionData Elf_fillCodeRegion(
    const Elf64SectionHeader* sh,
    const char* s_name
);

static uint8_t Elf_isExecutableSectionHeader(
    const Elf64SectionHeader* section_header
);

static uint8_t Elf_hasFlag(
    uint64_t present, 
    uint64_t expected
);

static void Elf_readSectionHeaderEntries(
    const Elf64FileHeader* fh,
    Elf_StringTables *strtabs,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint32_t ilevel,
    FILE* fp,
    uint8_t* block_l,
    PHeaderData hd
);

static void Elf_swapFileHeaderEntries(
    Elf64FileHeader* file_header
);

static uint64_t Elf_parseBitnessedValue(
    const Elf64FileHeader* fh,
    const uint8_t* ptr,
    uint8_t offset
);

static ElfSectionHeaderOffsets Elf_getSectionHeaderOffsets(
    const Elf64FileHeader* file_header
);
//void Elf_saveSection(const Elf64SectionHeader* sh, const char* s_name, uint16_t idx);



void parseELFHeader(
    PHeaderData hd, 
    PGlobalParams gp, 
    PElfParams elfp
)
{
    uint8_t* ptr;
    uint8_t bitness;
    uint8_t s;
    Elf64FileHeader file_header;
    memset(&file_header, 0, sizeof(file_header));
    ptr = &gp->block_large[0];

    hd->headertype = HEADER_TYPE_ELF;

    bitness = *(&ptr[Elf64FileHeaderOffsets.EI_CLASS]);

    if ( bitness != ELFCLASS32 && bitness != ELFCLASS64 )
    {
        header_error("ERROR: No valid EI_CLASS (bitness) found!\n");
        return;
    }

    s = Elf_readFileHeader(&file_header, gp->block_large, gp->start_file_offset, gp->file_size);
    if ( s != 0 ) return;

    Elf_fillHeaderDataWithFileHeader(&file_header, hd);
    if ( LIB_MODE == 0 && (elfp->info_level & INFO_LEVEL_ELF_FILE_H) )
        Elf_printFileHeader(&file_header, gp->start_file_offset);

    if ( LIB_MODE == 0 && (elfp->info_level & INFO_LEVEL_ELF_PROG_H) )
        Elf_readProgramHeaderTable(&file_header, &gp->abs_file_offset, gp->start_file_offset, gp->file_size, elfp->info_level, bitness, gp->fp, gp->block_large);

    Elf_readSectionHeaderTable(&file_header, gp->start_file_offset, &gp->abs_file_offset, gp->file_size, elfp->info_level, bitness, gp->fp, gp->block_large, gp->block_standard, hd);
}

uint8_t Elf_readFileHeader(Elf64FileHeader* file_header, uint8_t* block_l, size_t start_file_offset, size_t file_size)
{
    uint8_t* ptr;
    ElfFileHeaderOffsets fh_offsets;
    uint8_t ei_class;
    uint8_t header_size;

    ptr = &block_l[0];
    ei_class = *(&ptr[Elf64FileHeaderOffsets.EI_CLASS]);
    header_size = (ei_class == ELFCLASS32) ? ELF_SIZE_OF_FILE_HEADER_32 : ELF_SIZE_OF_FILE_HEADER_64;

    if ( !checkFileSpace(0, start_file_offset, header_size, file_size) )
        return 1;

    if ( ei_class == ELFCLASS32 ) fh_offsets = Elf32FileHeaderOffsets;
    else fh_offsets = Elf64FileHeaderOffsets;

    file_header->EI_MAG0 = MAGIC_ELF_BYTES[0];
    file_header->EI_MAG1 = MAGIC_ELF_BYTES[1];
    file_header->EI_MAG2 = MAGIC_ELF_BYTES[2];
    file_header->EI_MAG3 = MAGIC_ELF_BYTES[3];
    file_header->EI_CLASS = ei_class;
    file_header->EI_DATA = *(&ptr[fh_offsets.EI_DATA]);
    file_header->EI_VERSION = *(&ptr[fh_offsets.EI_VERSION]);
    file_header->EI_OSABI = *(&ptr[fh_offsets.EI_OSABI]);
    file_header->EI_ABIVERSION = *(&ptr[fh_offsets.EI_ABIVERSION]),
//	file_header->EI_PAD = {0,0,0,0;0,0,0},
    file_header->e_type = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_type);
    file_header->e_machine = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_machine);
    file_header->e_version = GetIntXValueAtOffset(uint32_t, ptr, fh_offsets.e_version);
    file_header->e_entry = Elf_parseBitnessedValue(file_header, ptr, fh_offsets.e_entry);
    file_header->e_phoff = Elf_parseBitnessedValue(file_header, ptr, fh_offsets.e_phoff);
    file_header->e_shoff = Elf_parseBitnessedValue(file_header, ptr, fh_offsets.e_shoff);
    file_header->e_flags = GetIntXValueAtOffset(uint32_t, ptr, fh_offsets.e_flags);
    file_header->e_ehsize = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_ehsize);
    file_header->e_phentsize = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_phentsize);
    file_header->e_phnum = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_phnum);
    file_header->e_shentsize = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_shentsize);
    file_header->e_shnum = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_shnum);
    file_header->e_shstrndx = GetIntXValueAtOffset(uint16_t, ptr, fh_offsets.e_shstrndx);

    if ( file_header->EI_DATA == ELFDATA2MSB )
    {
        Elf_swapFileHeaderEntries(file_header);
    }

    return 0;
}

void Elf_swapFileHeaderEntries(Elf64FileHeader* file_header)
{
    file_header->e_type = swapUint16(file_header->e_type);
    file_header->e_machine = swapUint16(file_header->e_machine);
    file_header->e_version = swapUint32(file_header->e_version);
    file_header->e_flags = swapUint32(file_header->e_flags);
    file_header->e_ehsize = swapUint16(file_header->e_ehsize);
    file_header->e_phentsize = swapUint16(file_header->e_phentsize);
    file_header->e_phnum = swapUint16(file_header->e_phnum);
    file_header->e_shentsize = swapUint16(file_header->e_shentsize);
    file_header->e_shnum = swapUint16(file_header->e_shnum);
    file_header->e_shstrndx = swapUint16(file_header->e_shstrndx);
}

void Elf_fillHeaderDataWithFileHeader(const Elf64FileHeader* file_header, PHeaderData hd)
{
    ArchitectureMapEntry* arch = getArchitecture(file_header->e_machine, elf_arch_id_mapper, elf_arch_id_mapper_size);

    if ( file_header->EI_CLASS == ELFCLASS32 ) hd->h_bitness = 32;
    else if ( file_header->EI_CLASS == ELFCLASS64 ) hd->h_bitness = 64;
    else hd->h_bitness = 0;
    hd->endian = file_header->EI_DATA;
    hd->CPU_arch = arch->arch_id;
    hd->Machine = arch->arch.name;
    hd->i_bitness = arch->bitness;

    if ( file_header->e_machine == EM_IA_64)
    {
        if ( !(file_header->e_flags & EF_IA_64_ABI64) )
        {
            hd->i_bitness = 32;
        }
    }
    else if ( arch->arch_id == ARCH_MIPS || arch->arch_id == ARCH_RISC || arch->arch_id == ARCH_RISC_V || arch->arch_id == ARCH_SPARC )
    {
        hd->i_bitness = hd->h_bitness;
    }
//  The 32-bit Intel Architecture defines no flags so e_flags is 0
}

/**
 * Read out the program header table.
 */
void Elf_readProgramHeaderTable(
    Elf64FileHeader* file_header,
    size_t* abs_file_offset,
    size_t start_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l
)
{
//    debug_info("Elf_readProgramHeaderTable.\n");

    if ( !Elf_programHeaderOffsetsAreValid(file_header, start_file_offset, file_size))
        return;

    Elf_readProgramHeaderTableEntries(file_header, abs_file_offset, start_file_offset, file_size, ilevel, bitness, fp, block_l);
}

uint8_t Elf_programHeaderOffsetsAreValid(
    const Elf64FileHeader* file_header,
    size_t start_file_offset,
    size_t file_size
)
{
//	size_t table_end = 0;
    if ( file_header->e_phnum < 1 )
    {
        header_info("INFO: The program header number is %u.\n", file_header->e_phnum);
        return 0;
    }
    if ( file_header->e_phoff == 0 )
    {
        header_info("INFO: The program header offset is 0.\n");
        return 0;
    }
    if ( start_file_offset + file_header->e_phoff > file_size )
    {
        header_info("INFO: The program header offset (0x%"PRIx64") is greater than file_size (0x%zu).\n",
                file_header->e_phoff, file_size);
        return 0;
    }
//	table_end = file_header->e_phoff + (file_header->e_phnum * file_header->e_phentsize);
//	if ( start_file_offset + table_end > file_size )
//	{
//		header_error("ERROR: end of program header table (%lu) > file_size (%u)!\n",
//			   table_end, file_size);
//		return 0;
//	}

    return 1;
}

/**
 * Loop through all program table entries.
 * TODO: merge with Elf_readProgramHeaderTable
 *
 * @param file_header
 * @param table_block
 */
void Elf_readProgramHeaderTableEntries(
    const Elf64FileHeader* file_header,
    size_t* abs_file_offset,
    size_t start_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l
)
{
    uint8_t* ptr = NULL;
    size_t offset = (size_t)file_header->e_phoff;
    uint16_t i = 0;
    *abs_file_offset = start_file_offset;

    ElfProgramHeaderOffsets ph_offsets = Elf_getProgramHeaderOffsets(file_header);
    Elf64ProgramHeader program_header;
    
    if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_PROG_H )
        printf("Program Header Table:\n");

    for ( i = 0; i < file_header->e_phnum; i++ )
    {
//        debug_info(" - %u / %u\n", (i + 1), file_header->e_phnum);

        if ( !checkFileSpace(offset, *abs_file_offset, file_header->e_phentsize, file_size) )
            return;

        if ( !checkLargeBlockSpace(&offset, abs_file_offset, file_header->e_phentsize, block_l, fp) )
            break;

        ptr = &block_l[offset];

        Elf_readProgramHeaderTableEntry(ptr, &ph_offsets, file_header, &program_header);
        
        if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_PROG_H )
            Elf_printProgramHeaderTableEntry(&program_header, i, file_header->e_phnum, *abs_file_offset+offset, bitness);

        if ( !Elf_checkProgramHeaderTableEntry(&program_header, i, start_file_offset, file_size))
        {
//			offset += file_header->e_shentsize;
//			continue;
        }

        offset += file_header->e_phentsize;
    }
    if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_PROG_H )
        printf("\n");
}

ElfProgramHeaderOffsets Elf_getProgramHeaderOffsets(
    const Elf64FileHeader* file_header
)
{
    if ( file_header->EI_CLASS == ELFCLASS32 )
        return Elf32ProgramHeaderOffsets;
    else
        return Elf64ProgramHeaderOffsets;
}

/**
 * Read the info provided by the section table.
 * Just gets the offset and size right now, cause no more is needed.
 *
 * @param ptr
 * @param sh_offsets
 * @param file_header
 * @param sh
 */
void Elf_readProgramHeaderTableEntry(
    const uint8_t* ptr,
    ElfProgramHeaderOffsets* ph_offsets,
    const Elf64FileHeader* file_header,
    Elf64ProgramHeader* ph
)
{
//	debug_info("\nElf_readProgramHeaderTableEntry()\n");
    ph->p_type = *((uint32_t*) &ptr[ph_offsets->p_type]);
    ph->p_flags = *((uint32_t*) &ptr[ph_offsets->p_flags]);

    if ( file_header->EI_DATA == ELFDATA2MSB )
    {
        ph->p_type = swapUint32(ph->p_type);
        ph->p_flags = swapUint32(ph->p_flags);
    }

    ph->p_offset = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_offset);
    ph->p_vaddr = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_vaddr);
    ph->p_paddr = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_paddr);
    ph->p_filesz = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_filesz);
    ph->p_memsz = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_memsz);
    ph->p_align = Elf_parseBitnessedValue(file_header, ptr, ph_offsets->p_align);
}

/**
 * Check for valid values.
 *
 * @param sh
 * @return
 */
uint8_t Elf_checkProgramHeaderTableEntry(
    Elf64ProgramHeader* ph,
    uint16_t idx,
    size_t start_file_offset,
    size_t file_size
)
{
    uint8_t valid = 1;
    char errors[ERRORS_BUFFER_SIZE] = {0};
    uint16_t offset = 0;

//	if ( ph->p_offset == 0 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - p_offset is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
//	if ( ph->p_filesz == 0 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - p_filesz is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
    if ( start_file_offset + ph->p_offset >= file_size )
    {
        snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - p_offset (0x%"PRIx64") is >= file_size (0x%zx)\n",
                 ph->p_offset, file_size);
        offset += (uint16_t)strlen(errors);
        valid = 0;
    }
    if ( start_file_offset + ph->p_offset + ph->p_filesz >= file_size )
    {
        snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset,
                 " - p_offset (0x%"PRIx64") + p_filesz (0x%"PRIx64") = (0x%"PRIx64") is >= file_size (0x%zx)\n",
                 ph->p_offset, ph->p_filesz, ph->p_offset + ph->p_filesz, file_size);
        offset += (uint16_t)strlen(errors);
        valid = 0;
    }
    errors[ERRORS_BUFFER_SIZE-1] = 0;

    if ( !valid && strlen(errors) )
    {
        header_info("INFO: Section %d has strange data\n", idx + 1);
        header_info("%s\n", errors);
    }

    return valid;
}

/**
 * Read out the section header table.
 *
 * @param fh
 */
void Elf_readSectionHeaderTable(
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint32_t ilevel,
    uint8_t bitness,
    FILE* fp,
    uint8_t* block_l,
    uint8_t* block_s,
    PHeaderData hd
)
{
//    debug_info("Elf_readSectionHeaderTable.\n");
    Elf_StringTables strtabs;
    int s = 0;

    memset(&strtabs, 0, sizeof(strtabs));

    if ( !Elf_sectionHeaderOffsetsAreValid(fh, start_file_offset, file_size) )
        return;

    // read section header string table
    strtabs.shstrtab_size = Elf_readSectionById(&strtabs.shstrtab, fh->e_shstrndx, fh, start_file_offset, file_size, block_s, fp);
    if ( !strtabs.shstrtab_size )
    {
        header_error("ERROR: Loading String Table failed.\n");
        goto clean;
    }
    strtabs.shstrtab[strtabs.shstrtab_size-1] = 0;

    // read string table, if needed
    if ( ilevel & ELF_LOAD_STRING_TABLE_FLAG )
    {
        s = Elf_readSectionByNameType(
                ".strtab", ElfSectionHeaderTypes.SHT_STRTAB,
                &strtabs,
                &strtabs.strtab, &strtabs.strtab_size,
                fh, start_file_offset, abs_file_offset, file_size, block_l, fp
        );
        if ( s != 0)
        {
            header_info("INFO: .strtab not found!\n");
//            goto clean;
        }
    }

    // read dyn string table, if needed
    if ( ilevel & ELF_LOAD_DYN_STRING_TABLE_FLAG )
    {
        s = Elf_readSectionByNameType(
                ".dynstr", ElfSectionHeaderTypes.SHT_STRTAB,
                &strtabs,
                &strtabs.dynstr, &strtabs.dynstr_size,
                fh, start_file_offset, abs_file_offset, file_size, block_l, fp
        );
        if ( s != 0)
        {
            header_info("INFO: .dynstr not found!\n");
//            goto clean;
        }
    }

    // read section headers
    // print if wanted and fill basic info
    Elf_readSectionHeaderEntries(fh, &strtabs, start_file_offset, abs_file_offset, file_size, ilevel, fp, block_l, hd);

    // print section info of set INFO_LEVEL_ELF_XX flags
#if defined(LIB_MODE) && LIB_MODE==0
    Elf64SectionHeader sht_entry;

    if ( ilevel & (INFO_LEVEL_ELF_SYM_TAB|INFO_LEVEL_ELF_SYM_TAB_EX) )
    {
        s = Elf_getSectionTableEntryByNameType(NULL, ElfSectionHeaderTypes.SHT_SYMTAB, &sht_entry, &strtabs, fh, start_file_offset, abs_file_offset, file_size, block_l, fp);
        if ( s == 0 )
            Elf_parseSymTab(strtabs.strtab, strtabs.strtab_size, start_file_offset, abs_file_offset, file_size, fp, &sht_entry, block_l, BLOCKSIZE, bitness, fh->EI_DATA, (ilevel&INFO_LEVEL_ELF_SYM_TAB_EX));
        else
            printf("No symbol table found.\n");
    }

    if ( ilevel & (INFO_LEVEL_ELF_DYN_SYM_TAB|INFO_LEVEL_ELF_DYN_SYM_TAB_EX) )
    {
        s = Elf_getSectionTableEntryByNameType(NULL, ElfSectionHeaderTypes.SHT_DYNSYM, &sht_entry, &strtabs, fh, start_file_offset, abs_file_offset, file_size, block_l, fp);
        if ( s == 0 )
            Elf_parseSymTab(strtabs.dynstr, strtabs.dynstr_size, start_file_offset, abs_file_offset, file_size, fp, &sht_entry, block_l, BLOCKSIZE, bitness, fh->EI_DATA, (ilevel&INFO_LEVEL_ELF_DYN_SYM_TAB_EX));
        else
            printf("No dynamic symbol table found.\n");
    }
#endif 

clean:
    cleanStrTabs(&strtabs);

    memset(&strtabs, 0, sizeof(strtabs));
}

int Elf_readSectionByNameType(
    const char* sec_name,
    uint32_t sec_type,
    Elf_StringTables *strtabs,
    uint8_t **section,
    uint32_t *section_size,
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t* block_l,
    FILE* fp
)
{
    int s;
    Elf64SectionHeader sht_entry;

    s = Elf_getSectionTableEntryByNameType(
            sec_name, sec_type,
            &sht_entry,
            strtabs, fh,
            start_file_offset, abs_file_offset, file_size, block_l, fp
        );
    if ( s != 0 )
        return s;

    if ( !checkFileSpace((size_t)sht_entry.sh_offset, start_file_offset, (size_t)sht_entry.sh_size, file_size) )
        return -5;

    sht_entry.sh_offset += start_file_offset;

    *section_size = (uint32_t)readFileA(fp, (size_t)sht_entry.sh_offset, (size_t)sht_entry.sh_size, section);
    if ( *section_size == 0)
        return -6;

    return s;
}

int Elf_getSectionTableEntryByNameType(
    const char* sec_name,
    uint32_t sec_type,
    Elf64SectionHeader *sht_entry,
    Elf_StringTables *strtabs,
    const Elf64FileHeader* fh,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint8_t* block_l,
    FILE* fp
)
{
    int s = -1;
    uint16_t i;
    size_t offset = 0;
    uint8_t* ptr = NULL;
    size_t size;
    size_t table_start;
    char* s_name;
    int found = 0;

    if ( sec_name == NULL && sec_type == (uint32_t)-1 )
        return -1;
    if ( !checkFileSpace((size_t)fh->e_shoff, start_file_offset, fh->e_shentsize, file_size) )
        return -1;

    // read new large block to ease up offsetting
    table_start = start_file_offset + (size_t)fh->e_shoff;
    size = readFile(fp, table_start, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return -2;

    *abs_file_offset = table_start;
    ElfSectionHeaderOffsets sh_offsets = Elf_getSectionHeaderOffsets(fh);
    CodeRegionData code_region_data;

    for ( i = 0; i < fh->e_shnum; i++ )
    {
//        debug_info(" - %u / %u\n", (i + 1), fh->e_shnum);
        found = 0;

        if ( !checkFileSpace(offset, *abs_file_offset, fh->e_shentsize, file_size))
        {
            s = -3;
            break;
        }

        if ( !checkLargeBlockSpace(&offset, abs_file_offset, fh->e_shentsize, block_l, fp) )
        {
            s = -4;
            break;
        }

        ptr = &block_l[offset];

        Elf_readSectionHeaderTableEntry(ptr, &sh_offsets, fh, sht_entry);

        s_name = ( sht_entry->sh_name < strtabs->shstrtab_size-1 ) ? (char*) &strtabs->shstrtab[sht_entry->sh_name] : "";

        if ( sec_name != NULL && strcmp(s_name, sec_name) == 0 )
            found += 1;
        if ( sec_type != (uint32_t)-1 && sec_type == sht_entry->sh_type )
            found += 1;

        if ( ( found == 1 && (sec_name == NULL || sec_type == (uint32_t)-1 ))
            ||
             (found == 2 && (sec_name != NULL && sec_type != (uint32_t)-1 ) )
            )
        {
            s = 0;
            break;
        }

        offset += fh->e_shentsize;
    }

    return s;
}

uint8_t Elf_sectionHeaderOffsetsAreValid(
    const Elf64FileHeader* file_header,
    size_t start_file_offset,
    size_t file_size
)
{
    size_t table_end = 0;
    if ( file_header->e_shnum < 1 )
    {
        header_info("INFO: The section header number is %u.\n", file_header->e_shnum);
        return 0;
    }
    if ( file_header->e_shoff == 0 )
    {
        header_info("INFO: The section header offset is 0.\n");
        return 0;
    }
    if ( start_file_offset + file_header->e_shoff > file_size )
    {
        header_info("INFO: The section header offset (0x%"PRIx64") > file_size (0x%zu).\n",
                file_header->e_shoff, file_size);
        return 0;
    }
    table_end = (size_t)file_header->e_shoff + (file_header->e_shnum * file_header->e_shentsize);
    if ( start_file_offset + table_end > file_size )
    {
        header_error("ERROR: end of section header table (0x%zx) > file_size (0x%zx)!\n",
               table_end, file_size);
        return 0;
    }

    return 1;
}

/**
 * Loop through all section table entries.
 *
 * @param fh
 * @param shstrtab
 * @param shstrtab_size
 */
void Elf_readSectionHeaderEntries(
    const Elf64FileHeader* fh,
    Elf_StringTables *strtabs,
    size_t start_file_offset,
    size_t* abs_file_offset,
    size_t file_size,
    uint32_t ilevel,
    FILE* fp,
    uint8_t* block_l,
    PHeaderData hd
)
{
    uint8_t* ptr = NULL;
    char* s_name;
    size_t offset = 0;
    uint16_t i = 0;
    size_t size = 0;
    size_t table_start;

    if ( !checkFileSpace((size_t)fh->e_shoff, start_file_offset, fh->e_shentsize, file_size) )
        return;

    // read new large block to ease up offsetting
    table_start = start_file_offset + (size_t)fh->e_shoff;
    size = readFile(fp, table_start, BLOCKSIZE_LARGE, block_l);
    if ( size == 0 )
        return;

    *abs_file_offset = table_start;
    ElfSectionHeaderOffsets sh_offsets = Elf_getSectionHeaderOffsets(fh);
    Elf64SectionHeader sht_entry;
    CodeRegionData code_region_data;

    if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_SEC_H )
        printf("Section Header Table:\n");

    for ( i = 0; i < fh->e_shnum; i++ )
    {
//        debug_info(" - %u / %u\n", (i + 1), fh->e_shnum);

        if ( !checkFileSpace(offset, *abs_file_offset, fh->e_shentsize, file_size) )
            return;

        if ( !checkLargeBlockSpace(&offset, abs_file_offset, fh->e_shentsize, block_l, fp) )
            break;

        ptr = &block_l[offset];

        Elf_readSectionHeaderTableEntry(ptr, &sh_offsets, fh, &sht_entry);

        s_name = ( sht_entry.sh_name < strtabs->shstrtab_size-1 ) ? (char*) &strtabs->shstrtab[sht_entry.sh_name] : "";

        if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_SEC_H )
            Elf_printSectionHeaderTableEntry(&sht_entry, i, fh->e_shnum, s_name, *abs_file_offset+offset, hd->h_bitness);

        if ( !Elf_checkSectionHeaderTableEntry(&sht_entry, i, s_name, start_file_offset, file_size) )
        {
//			offset += fh->e_shentsize;
//			continue;
        }

//        debug_info(" - - name %s\n", s_name);

        if ( Elf_isExecutableSectionHeader(&sht_entry) )
        {
            code_region_data = Elf_fillCodeRegion(&sht_entry, s_name);
            addCodeRegionDataToHeaderData(&code_region_data, hd);
        }

//		if ( ilevel == INFO_LEVEL_ELF_SAVE_SEC )
//			Elf_saveSection(&sht_entry, s_name, i);

        offset += fh->e_shentsize;
    }
    if ( LIB_MODE == 0 && ilevel & INFO_LEVEL_ELF_SEC_H )
        printf("\n");
}

/**
 * Loads a section into a buffer.
 *
 * @param sht_block uint8_t* section header table block
 * @param section uint8_t** section block to fill
 * @param index uint16_t
 * @param fh Elf64FileHeader*
 * @return uint32_t the size or 0 if it fails
 */
uint32_t Elf_readSectionById(uint8_t** section,
                                    uint16_t index,
                                    const Elf64FileHeader* fh,
                                    size_t start_file_offset,
                                    size_t file_size,
                                    uint8_t* block_s,
                                    FILE* fp
                                    )
{
    uint8_t* ptr;
    size_t size;
    size_t sh_size;
    size_t table_start;
    size_t e_offset;
    size_t sh_offset;

    // get section info
    ElfSectionHeaderOffsets sh_offsets = Elf_getSectionHeaderOffsets(fh);
    table_start = (size_t)fh->e_shoff;
    e_offset = table_start + index * fh->e_shentsize;

    if ( !checkFileSpace(e_offset, start_file_offset, fh->e_shentsize, file_size) )
        return 0;

//	size = readBlock(file_name, e_offset+start_file_offset);
    size = readFile(fp, (size_t)(e_offset+start_file_offset), BLOCKSIZE, block_s);
    if ( size == 0 )
        return 0;

    ptr = &block_s[0];

    sh_offset = (size_t)Elf_parseBitnessedValue(fh, ptr, sh_offsets.sh_offset);
    sh_size = (size_t)Elf_parseBitnessedValue(fh, ptr, sh_offsets.sh_size);

    // read section
    if ( !checkFileSpace(sh_offset, start_file_offset, sh_size, file_size) )
        return 0;

    sh_offset += start_file_offset;

    size = readFileA(fp, (size_t)sh_offset, sh_size, section);

    return (uint32_t)size;
}

ElfSectionHeaderOffsets Elf_getSectionHeaderOffsets(const Elf64FileHeader* file_header)
{
    if ( file_header->EI_CLASS == ELFCLASS32 )
        return Elf32SectionHeaderOffsets;
    else
        return Elf64SectionHeaderOffsets;
}

/**
 * Read the info provided by the section table.
 * Just gets the offset and size right now, cause no more is needed.
 *
 * @param ptr uint8_t*
 * @param sh_offsets ElfSectionHeaderOffsets*
 * @param fh Elf64FileHeader*
 * @param sh Elf64SectionHeader*
 */
void Elf_readSectionHeaderTableEntry(const uint8_t* ptr, ElfSectionHeaderOffsets* sh_offsets, const Elf64FileHeader* fh, Elf64SectionHeader* sh)
{
    sh->sh_offset = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_offset);
    sh->sh_size = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_size);

    sh->sh_flags = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_flags);
    sh->sh_addr = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_addr);
    sh->sh_addralign = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_addralign);
    sh->sh_entsize = Elf_parseBitnessedValue(fh, ptr, sh_offsets->sh_entsize);

    sh->sh_name = GetIntXValueAtOffset(uint32_t, ptr, sh_offsets->sh_name);
    sh->sh_type = GetIntXValueAtOffset(uint32_t, ptr, sh_offsets->sh_type);
    sh->sh_link = GetIntXValueAtOffset(uint32_t, ptr, sh_offsets->sh_link);
    sh->sh_info = GetIntXValueAtOffset(uint32_t, ptr, sh_offsets->sh_info);

    if ( fh->EI_DATA == ELFDATA2MSB )
    {
        sh->sh_name = swapUint32(sh->sh_name);
        sh->sh_type = swapUint32(sh->sh_type);
        sh->sh_link = swapUint32(sh->sh_link);
        sh->sh_info = swapUint32(sh->sh_info);
    }
}

uint64_t Elf_parseBitnessedValue(const Elf64FileHeader* fh, const uint8_t* ptr, uint8_t offset)
{
    uint64_t value;

    if ( fh->EI_CLASS == ELFCLASS32 )
    {
        value = *((uint32_t*) &ptr[offset]);

        if ( fh->EI_DATA == ELFDATA2MSB )
        {
            value = swapUint32((uint32_t)value);
        }
    }
    else
    {
        value = *((uint64_t*) &ptr[offset]);

        if ( fh->EI_DATA == ELFDATA2MSB )
        {
            value = swapUint64(value);
        }
    }

    return value;
}

/**
 * Check for valid values.
 *
 * @param sh
 * @return
 */
uint8_t Elf_checkSectionHeaderTableEntry(Elf64SectionHeader* sh, uint16_t idx, char* name, size_t start_file_offset, size_t file_size)
{
    uint8_t valid = 1;
    char errors[ERRORS_BUFFER_SIZE] = {0};
    uint16_t offset = 0;

    if ( sh->sh_type == ElfSectionHeaderTypes.SHT_NULL )
        return valid;

//	if ( sh->sh_offset == 0 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - sh_offset is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
    if ( start_file_offset + sh->sh_offset > file_size )
    {
        snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - sh_offset (0x%"PRIx64") is > file_size (0x%zu)\n",
                 sh->sh_offset, file_size);
        offset += (uint16_t)strlen(errors);
        valid = 0;
    }
//	if ( sh->sh_size == 0 )
//	{
////		errors[1] = "sh_size is 0.";
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - sh_size is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
    if ( !(Elf_hasFlag(sh->sh_flags, ElfSectionHeaderFlags.SHF_ALLOC & ElfSectionHeaderFlags.SHF_WRITE)
            && sh->sh_type == ElfSectionHeaderTypes.SHT_NOBITS )
        && start_file_offset + sh->sh_offset + sh->sh_size > file_size )
    {
        snprintf(&errors[offset], ERRORS_BUFFER_SIZE,
                 " - sh_offset (0x%"PRIx64") + sh_size (0x%"PRIx64") = (0x%"PRIx64") is > file_size (0x0x%zu)\n",
                 sh->sh_offset, sh->sh_size, sh->sh_offset + sh->sh_size, file_size);
        offset += (uint16_t)strlen(errors);
        valid = 0;
    }

    if ( !valid && strlen(errors) )
    {
        header_info("INFO: Section %d (\"%s\") has strange data\n", idx + 1, name);
        header_info("%s\n", errors);
    }

    return valid;
}

uint8_t Elf_isExecutableSectionHeader(const Elf64SectionHeader* section_header)
{
    return Elf_hasFlag(section_header->sh_flags, ElfSectionHeaderFlags.SHF_EXECINSTR);
}

uint8_t Elf_hasFlag(uint64_t present, uint64_t expected)
{
    uint32_t mask = (uint32_t)expected & (uint32_t)present;
    return mask == expected;
}

/**
 * Fill code region info in the HeaderData object.
 *
 * @param sh
 */
CodeRegionData Elf_fillCodeRegion(const Elf64SectionHeader* sh, const char* s_name)
{
    uint64_t sh_end = 0;
    size_t s_name_size = 0;
    size_t name_buf_size = 0;
    char* __restrict name = NULL;
    CodeRegionData code_region_data;

    memset(&code_region_data, 0, sizeof(code_region_data));

    sh_end = sh->sh_offset + sh->sh_size;
    s_name_size = strnlen(s_name, MAX_SIZE_OF_SECTION_NAME);
    name_buf_size = s_name_size + 1;

    name = (char*) calloc(name_buf_size, sizeof(char));
    if (name)
    {
        strncpy(name, s_name, s_name_size);
        code_region_data.name = name;
    }

    code_region_data.start = sh->sh_offset;
    code_region_data.end = sh_end;

    return code_region_data;
}

//void Elf_saveSection(const Elf64SectionHeader* sh, const char* s_name, uint16_t idx)
//{
//	uint64_t section_end_offset = sh->sh_offset + sh->sh_size;
//
//	if ( sh->sh_type == ElfSectionHeaderTypes.SHT_NULL )
//		return;
//
//	if ( section_end_offset > file_size )
//	{
//		if ( !Elf_hasFlag(sh->sh_flags, ElfSectionHeaderFlags.SHF_ALLOC) )
//		{
//			header_info("INFO: Could not save section \"%s\": Section end (%lu) > file_size (%lu)\n",
//					s_name, section_end_offset, file_size);
//		}
//		return;
//	}
//
//	uint8_t* section = NULL;
//	uint32_t size = readCharArrayFile(file_name, &section, sh->sh_offset, section_end_offset);
//	uint32_t size = readFileA(file_name, sh->sh_offset, section_end_offset, &section);
//	if ( size )
//	{
//		char section_file_name[PATH_MAX+1] = {0};
////		uint64_t max_file_name_ln = PATH_MAX - strlen(s_name) - 1;
//		uint64_t max_file_name_ln = PATH_MAX - 6; // uint16_t + "-"
//		if ( strlen(file_name) > max_file_name_ln )
//		{
//			strncpy(section_file_name, file_name, max_file_name_ln);
////			snprintf(&section_file_name[max_file_name_ln], PATH_MAX-max_file_name_ln, "%s%s", "-", s_name);
//			snprintf(&section_file_name[max_file_name_ln], PATH_MAX-max_file_name_ln, "%s%u", "-", idx);
//		}
//		else
//		{
////			snprintf(section_file_name, PATH_MAX, "%s%s%s", file_name, "-", s_name);
//			snprintf(section_file_name, PATH_MAX, "%s%s%u", file_name, "-", idx);
//		}
//
//		printf("section_file_name: %s\n", section_file_name);
//
//		FILE* file = fopen(section_file_name, "wb");
//		fwrite(section, 1, sh->sh_size, file);
//
//		free(section);
//	}
//}

#endif
