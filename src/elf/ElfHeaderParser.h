#ifndef HEADER_PARSER_ELF_HEADER_PARSER_H
#define HEADER_PARSER_ELF_HEADER_PARSER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "../ArchitectureInfo.h"
#include "../HeaderData.h"
#include "../utils/Converter.h"
#include "../Globals.h"
#include "ElfFileHeader.h"
#include "ElfHeaderOffsets.h"
#include "ElfHeaderPrinter.h"
#include "ElfProgramHeader.h"
#include "ElfSectionHeader.h"
#include "ElfSectionHeaderFlags.h"



static void parseELFHeader();
static uint8_t readElfFileHeader(Elf64FileHeader* file_header);
static void readElfProgramHeaderTable(Elf64FileHeader* file_header);
static unsigned char programHeaderOffsetsAreValid(const Elf64FileHeader* file_header);
static void readElfProgramHeaderTableEntries(const Elf64FileHeader* file_header);
static ElfProgramHeaderOffsets getElfProgramHeaderOffsets(const Elf64FileHeader* file_header);
static void readElfProgramHeaderTableEntry(const unsigned char* ptr, ElfProgramHeaderOffsets* ph_offsets, const Elf64FileHeader* file_header, Elf64ProgramHeader* ph);
static unsigned char checkElfProgramHeaderTableEntry(Elf64ProgramHeader* ph, uint16_t idx);
static void readElfSectionHeaderTable(const Elf64FileHeader* file_header);
static uint32_t loadElfSectionHeaderTable(unsigned char** section, uint16_t index, const Elf64FileHeader* fh);
static unsigned char sectionHeaderOffsetsAreValid(const Elf64FileHeader* file_header);
static void readElfSectionHeaderTableEntry(const unsigned char* ptr, ElfSectionHeaderOffsets* sh_offsets, const Elf64FileHeader* fh, Elf64SectionHeader* sh);
static unsigned char checkElfSectionHeaderTableEntry(Elf64SectionHeader* sh, uint16_t idx, char* name);
static CodeRegionData fillElfCodeRegion(const Elf64SectionHeader* sh, const char* s_name);
static uint8_t isExecutableSectionHeader(const Elf64SectionHeader* section_header);
static uint8_t hasELFFlag(uint64_t present, uint64_t expected);
static void readElfSectionHeaderEntries(const Elf64FileHeader* fh, unsigned char* string_table, uint64_t string_table_size);
static void swapElfFileHeaderEntries(Elf64FileHeader* file_header);
static void fillHeaderDataWithElfFileHeader(const Elf64FileHeader* file_header);
static uint64_t parseElfBitnessedValue(const Elf64FileHeader* fh, const unsigned char* ptr, uint8_t offset);
static ElfSectionHeaderOffsets getElfSectionHeaderOffsets(const Elf64FileHeader* file_header);
//void saveSection(const Elf64SectionHeader* sh, const char* s_name, uint16_t idx);



void parseELFHeader()
{
	unsigned char* ptr;
	uint8_t bitness;
	uint8_t s;
	Elf64FileHeader file_header;
	memset(&file_header, 0, sizeof(file_header));
	ptr = &block_large[0];

	HD->headertype = HEADER_TYPE_ELF;

	bitness = *(&ptr[Elf64FileHeaderOffsets.EI_CLASS]);

	if ( bitness != ELFCLASS32 && bitness != ELFCLASS64 )
	{
		header_error("ERROR: No valid EI_CLASS (bitness) found!\n");
		return;
	}

	s = readElfFileHeader(&file_header);
	if ( s != 0 ) return;

	fillHeaderDataWithElfFileHeader(&file_header);
	if ( info_level >= INFO_LEVEL_FULL )
		printElfFileHeader(&file_header);

	if ( info_level >= INFO_LEVEL_FULL )
		readElfProgramHeaderTable(&file_header);

	readElfSectionHeaderTable(&file_header);
}

uint8_t readElfFileHeader(Elf64FileHeader* file_header)
{
	unsigned char* ptr;
	ElfFileHeaderOffsets fh_offsets;
	uint8_t ei_class;
	uint8_t header_size;

	ptr = &block_large[0];
	ei_class = *(&ptr[Elf64FileHeaderOffsets.EI_CLASS]);
	header_size = (ei_class == ELFCLASS32) ? ELF_SIZE_OF_FILE_HEADER_32 : ELF_SIZE_OF_FILE_HEADER_64;

	if ( !checkFileSpace(0, start_file_offset, header_size, "File header size") )
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
	file_header->e_type = *((uint16_t*) &ptr[fh_offsets.e_type]);
	file_header->e_machine = *((uint16_t*) &ptr[fh_offsets.e_machine]);
	file_header->e_version = *((uint32_t*) &ptr[fh_offsets.e_version]);
	file_header->e_entry = parseElfBitnessedValue(file_header, ptr, fh_offsets.e_entry);
	file_header->e_phoff = parseElfBitnessedValue(file_header, ptr, fh_offsets.e_phoff);
	file_header->e_shoff = parseElfBitnessedValue(file_header, ptr, fh_offsets.e_shoff);
	file_header->e_flags = *((uint32_t*) &ptr[fh_offsets.e_flags]);
	file_header->e_ehsize = *((uint16_t*) &ptr[fh_offsets.e_ehsize]);
	file_header->e_phentsize = *((uint16_t*) &ptr[fh_offsets.e_phentsize]);
	file_header->e_phnum = *((uint16_t*) &ptr[fh_offsets.e_phnum]);
	file_header->e_shentsize = *((uint16_t*) &ptr[fh_offsets.e_shentsize]);
	file_header->e_shnum = *((uint16_t*) &ptr[fh_offsets.e_shnum]);
	file_header->e_shstrndx = *((uint16_t*) &ptr[fh_offsets.e_shstrndx]);

	if ( file_header->EI_DATA == ELFDATA2MSB )
	{
		swapElfFileHeaderEntries(file_header);
	}

	return 0;
}

void swapElfFileHeaderEntries(Elf64FileHeader* file_header)
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

void fillHeaderDataWithElfFileHeader(const Elf64FileHeader* file_header)
{
	ArchitectureMapEntry* arch = getArchitecture(file_header->e_machine, elf_arch_id_mapper, elf_arch_id_mapper_size);

	if ( file_header->EI_CLASS == ELFCLASS32 ) HD->bitness = 32;
	else HD->bitness = 64;
	HD->endian = file_header->EI_DATA;
	HD->CPU_arch = arch->arch_id;
	HD->Machine = arch->arch.name;
}

/**
 * Read out the program header table.
 */
void readElfProgramHeaderTable(Elf64FileHeader* file_header)
{
	debug_info("readElfProgramHeaderTable.\n");

	if ( !programHeaderOffsetsAreValid(file_header))
		return;

	readElfProgramHeaderTableEntries(file_header);
}

unsigned char programHeaderOffsetsAreValid(const Elf64FileHeader* file_header)
{
//	uint64_t table_end = 0;
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
		header_info("INFO: The program header offset (%lu) is greater than file_size (%u).\n",
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
 * TODO: merge with readElfProgramHeaderTable
 *
 * @param file_header
 * @param table_block
 */
void readElfProgramHeaderTableEntries(const Elf64FileHeader* file_header)
{
	unsigned char* ptr = NULL;
	uint64_t offset = file_header->e_phoff;
	uint16_t i = 0;
	abs_file_offset = start_file_offset;

	ElfProgramHeaderOffsets ph_offsets = getElfProgramHeaderOffsets(file_header);
	Elf64ProgramHeader program_header;

	if ( info_level >= INFO_LEVEL_FULL )
		printf("Program Header Table:\n");

	for ( i = 0; i < file_header->e_phnum; i++ )
	{
		debug_info(" - %u / %u\n", (i + 1), file_header->e_phnum);

		if ( !checkFileSpace(offset, abs_file_offset, file_header->e_phentsize, "ph entry size") )
			return;

		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, file_header->e_phentsize, "ph entry size") )
			break;

		ptr = &block_large[offset];

		readElfProgramHeaderTableEntry(ptr, &ph_offsets, file_header, &program_header);

		if ( info_level >= INFO_LEVEL_FULL )
			printElfProgramHeaderTableEntry(&program_header, i, file_header->e_phnum, abs_file_offset+offset);

		if ( !checkElfProgramHeaderTableEntry(&program_header, i))
		{
//			offset += file_header->e_shentsize;
//			continue;
		}

		offset += file_header->e_phentsize;
	}
	if ( info_level >= INFO_LEVEL_FULL )
		printf("\n");
}

ElfProgramHeaderOffsets getElfProgramHeaderOffsets(const Elf64FileHeader* file_header)
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
void readElfProgramHeaderTableEntry(const unsigned char* ptr, ElfProgramHeaderOffsets* ph_offsets,
									const Elf64FileHeader* file_header, Elf64ProgramHeader* ph)
{
//	debug_info("\nreadElfProgramHeaderTableEntry()\n");
	ph->p_type = *((uint32_t*) &ptr[ph_offsets->p_type]);
	ph->p_flags = *((uint32_t*) &ptr[ph_offsets->p_flags]);

	if ( file_header->EI_DATA == ELFDATA2MSB )
	{
		ph->p_type = swapUint32(ph->p_type);
		ph->p_flags = swapUint32(ph->p_flags);
	}

	ph->p_offset = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_offset);
	ph->p_vaddr = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_vaddr);
	ph->p_paddr = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_paddr);
	ph->p_filesz = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_filesz);
	ph->p_memsz = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_memsz);
	ph->p_align = parseElfBitnessedValue(file_header, ptr, ph_offsets->p_align);
}

/**
 * Check for valid values.
 *
 * @param sh
 * @return
 */
unsigned char checkElfProgramHeaderTableEntry(Elf64ProgramHeader* ph, uint16_t idx)
{
	unsigned char valid = 1;
	char errors[ERRORS_BUFFER_SIZE] = {0};
	uint16_t offset = 0;

//	if ( ph->p_offset == 0 )
//	{
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - p_offset is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
	if ( ph->p_filesz == 0 )
	{
		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - p_filesz is 0\n");
		offset += strlen(errors);
		valid = 0;
	}
	if ( start_file_offset + ph->p_offset > file_size )
	{
		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset, " - p_offset (%lu) is > file_size (%u)\n",
				 ph->p_offset, file_size);
		offset += strlen(errors);
		valid = 0;
	}
	if ( start_file_offset + ph->p_offset + ph->p_filesz > file_size )
	{
		snprintf(&errors[offset], ERRORS_BUFFER_SIZE-offset,
				 " - ph_offset (%lu) + ph_size (%lu) = (%lu) is > file_size (%u)\n",
				 ph->p_offset, ph->p_filesz, ph->p_offset + ph->p_filesz, file_size);
		offset += strlen(errors);
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
 * @param file_header
 */
void readElfSectionHeaderTable(const Elf64FileHeader* file_header)
{
	debug_info("readElfSectionHeaderTable.\n");
	uint32_t string_table_size = 0;
	unsigned char* string_table = NULL;

	if ( !sectionHeaderOffsetsAreValid(file_header) )
		return;

	// read string table
	string_table_size = loadElfSectionHeaderTable(&string_table, file_header->e_shstrndx, file_header);
	if ( !string_table_size )
	{
		header_error("ERROR: Loading String Table failed.\n");
		return;
	}
	string_table[string_table_size-1] = 0;

	readElfSectionHeaderEntries(file_header, string_table, string_table_size);

	free(string_table);
}

unsigned char sectionHeaderOffsetsAreValid(const Elf64FileHeader* file_header)
{
	uint64_t table_end = 0;
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
		header_info("INFO: The section header offset (%lu) > file_size (%u).\n",
				file_header->e_shoff, file_size);
		return 0;
	}
	table_end = file_header->e_shoff + (file_header->e_shnum * file_header->e_shentsize);
	if ( start_file_offset + table_end > file_size )
	{
		header_error("ERROR: end of section header table (%lu) > file_size (%u)!\n",
			   table_end, file_size);
		return 0;
	}

	return 1;
}

/**
 * Loop through all section table entries.
 *
 * @param fh
 * @param string_table
 * @param string_table_size
 */
void readElfSectionHeaderEntries(const Elf64FileHeader* fh, unsigned char* string_table, uint64_t string_table_size)
{
	unsigned char* ptr = NULL;
	char* s_name;
	uint64_t offset = 0;
	uint16_t i = 0;
	uint32_t size = 0;
	uint64_t table_start;

	if ( !checkFileSpace(fh->e_shoff, start_file_offset, fh->e_shentsize, "e_shentsize") )
		return;

	// read new large block to ease up offsetting
	table_start = start_file_offset + fh->e_shoff;
	size = readLargeBlock(file_name, table_start);
	if ( size == 0 )
		return;

	abs_file_offset = table_start;
	ElfSectionHeaderOffsets sh_offsets = getElfSectionHeaderOffsets(fh);
	Elf64SectionHeader sht_entry;
	CodeRegionData code_region_data;

	if ( info_level >= INFO_LEVEL_FULL )
		printf("Section Header Table:\n");

	for ( i = 0; i < fh->e_shnum; i++ )
	{
		debug_info(" - %u / %u\n", (i + 1), fh->e_shnum);

		if ( !checkFileSpace(offset, abs_file_offset, fh->e_shentsize, "e_shentsize") )
			return;

		if ( !checkLargeBlockSpace(&offset, &abs_file_offset, fh->e_shentsize, "e_shentsize") )
			break;

		ptr = &block_large[offset];

		readElfSectionHeaderTableEntry(ptr, &sh_offsets, fh, &sht_entry);

		s_name = ( sht_entry.sh_name < string_table_size-1 ) ? (char*) &string_table[sht_entry.sh_name] : "";

		if ( info_level >= INFO_LEVEL_FULL )
			printElfSectionHeaderTableEntry(&sht_entry, i, fh->e_shnum, s_name, abs_file_offset+offset);

		if ( !checkElfSectionHeaderTableEntry(&sht_entry, i, s_name) )
		{
//			offset += fh->e_shentsize;
//			continue;
		}

		debug_info(" - - name %s\n", s_name);

		if ( isExecutableSectionHeader(&sht_entry) )
		{
			code_region_data = fillElfCodeRegion(&sht_entry, s_name);
			addCodeRegionDataToHeaderData(&code_region_data, HD);
		}

//		if ( info_level == INFO_LEVEL_EXTENDED )
//			saveSection(&sht_entry, s_name, i);

		offset += fh->e_shentsize;
	}
	if ( info_level >= INFO_LEVEL_FULL )
		printf("\n");
}

/**
 * Loads a section into a buffer.
 *
 * @param sht_block unsigned char* section header table block
 * @param section unsigned char** section block to fill
 * @param index uint16_t
 * @param fh Elf64FileHeader*
 * @return uint32_t the size or 0 if it fails
 */
uint32_t loadElfSectionHeaderTable(unsigned char** section, uint16_t index, const Elf64FileHeader* fh)
{
	unsigned char* ptr;
	uint32_t size = 0;
	uint64_t sh_end = 0;
	uint64_t sh_size = 0;
	uint64_t table_start;
	uint64_t e_offset;
	uint64_t sh_offset;

	// get section info
	ElfSectionHeaderOffsets sh_offsets = getElfSectionHeaderOffsets(fh);
	table_start = fh->e_shoff;
	e_offset = table_start + index * fh->e_shentsize;

	if ( !checkFileSpace(e_offset, start_file_offset, fh->e_shentsize, "fh->e_shentsize") )
		return 0;

	size = readBlock(file_name, e_offset+start_file_offset);
	if ( size == 0 )
		return 0;

	ptr = &block_standard[0];

	sh_offset = parseElfBitnessedValue(fh, ptr, sh_offsets.sh_offset);
	sh_size = parseElfBitnessedValue(fh, ptr, sh_offsets.sh_size);
	sh_end = sh_offset + sh_size;

	// read section
	if ( !checkFileSpace(sh_offset, start_file_offset, sh_size, "sh_size") )
		return 0;

	sh_offset += start_file_offset;
	sh_end += start_file_offset;

	size = readCharArrayFile(file_name, section, sh_offset, sh_end);

	return size;
}

ElfSectionHeaderOffsets getElfSectionHeaderOffsets(const Elf64FileHeader* file_header)
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
 * @param ptr unsigned char*
 * @param sh_offsets ElfSectionHeaderOffsets*
 * @param fh Elf64FileHeader*
 * @param sh Elf64SectionHeader*
 */
void readElfSectionHeaderTableEntry(const unsigned char* ptr, ElfSectionHeaderOffsets* sh_offsets,
									const Elf64FileHeader* fh, Elf64SectionHeader* sh)
{
	sh->sh_offset = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_offset);
	sh->sh_size = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_size);

	sh->sh_flags = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_flags);
	sh->sh_addr = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_addr);
	sh->sh_addralign = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_addralign);
	sh->sh_entsize = parseElfBitnessedValue(fh, ptr, sh_offsets->sh_entsize);

	sh->sh_name = *((uint32_t*) &ptr[sh_offsets->sh_name]);
	sh->sh_type = *((uint32_t*) &ptr[sh_offsets->sh_type]);
	sh->sh_link = *((uint32_t*) &ptr[sh_offsets->sh_link]);
	sh->sh_info = *((uint32_t*) &ptr[sh_offsets->sh_info]);

	if ( fh->EI_DATA == ELFDATA2MSB )
	{
		sh->sh_name = swapUint32(sh->sh_name);
		sh->sh_type = swapUint32(sh->sh_type);
		sh->sh_link = swapUint32(sh->sh_link);
		sh->sh_info = swapUint32(sh->sh_info);
	}
}

uint64_t parseElfBitnessedValue(const Elf64FileHeader* fh, const unsigned char* ptr, uint8_t offset)
{
	uint64_t value;

	if ( fh->EI_CLASS == ELFCLASS32 )
	{
		value = *((uint32_t*) &ptr[offset]);

		if ( fh->EI_DATA == ELFDATA2MSB )
		{
			value = swapUint32(value);
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
unsigned char checkElfSectionHeaderTableEntry(Elf64SectionHeader* sh, uint16_t idx, char* name)
{
	unsigned char valid = 1;
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
		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - sh_offset (%lu) is > file_size (%u)\n",
				 sh->sh_offset, file_size);
		offset += strlen(errors);
		valid = 0;
	}
//	if ( sh->sh_size == 0 )
//	{
////		errors[1] = "sh_size is 0.";
//		snprintf(&errors[offset], ERRORS_BUFFER_SIZE, " - sh_size is 0\n");
//		offset += strlen(errors);
//		valid = 0;
//	}
	if ( !(hasELFFlag(sh->sh_flags, ElfSectionHeaderFlags.SHF_ALLOC & ElfSectionHeaderFlags.SHF_WRITE)
			&& sh->sh_type == ElfSectionHeaderTypes.SHT_NOBITS )
		&& start_file_offset + sh->sh_offset + sh->sh_size > file_size )
	{
		snprintf(&errors[offset], ERRORS_BUFFER_SIZE,
				 " - sh_offset (%lu) + sh_size (%lu) = (%lu) is > file_size (%u)\n",
				 sh->sh_offset, sh->sh_size, sh->sh_offset + sh->sh_size, file_size);
		offset += strlen(errors);
		valid = 0;
	}

	if ( !valid && strlen(errors) )
	{
		header_info("INFO: Section %d (\"%s\") has strange data\n", idx + 1, name);
		header_info("%s\n", errors);
	}

	return valid;
}

uint8_t isExecutableSectionHeader(const Elf64SectionHeader* section_header)
{
	return hasELFFlag(section_header->sh_flags, ElfSectionHeaderFlags.SHF_EXECINSTR);
}

uint8_t hasELFFlag(uint64_t present, uint64_t expected)
{
	uint32_t mask = (uint32_t)expected & (uint32_t)present;
	return mask == expected;
}

/**
 * Fill code region info in the HeaderData object.
 *
 * @param sh
 */
CodeRegionData fillElfCodeRegion(const Elf64SectionHeader* sh, const char* s_name)
{
	uint64_t sh_end = 0;
	size_t s_name_size = 0;
	size_t name_size = 0;
	char* __restrict name = NULL;
	CodeRegionData code_region_data;

	memset(&code_region_data, 0, sizeof(code_region_data));

	sh_end = sh->sh_offset + sh->sh_size;
	s_name_size = strnlen(s_name, MAX_SIZE_OF_SECTION_NAME);
	name_size = s_name_size + 1;

	name = (char*) calloc(name_size, sizeof(char));
	if (name)
	{
		strncpy(name, s_name, s_name_size);
		code_region_data.name = name;
	}

	code_region_data.start = sh->sh_offset;
	code_region_data.end = sh_end;

	return code_region_data;
}

//void saveSection(const Elf64SectionHeader* sh, const char* s_name, uint16_t idx)
//{
//	uint64_t section_end_offset = sh->sh_offset + sh->sh_size;
//
//	if ( sh->sh_type == ElfSectionHeaderTypes.SHT_NULL )
//		return;
//
//	if ( section_end_offset > file_size )
//	{
//		if ( !hasELFFlag(sh->sh_flags, ElfSectionHeaderFlags.SHF_ALLOC) )
//		{
//			header_info("INFO: Could not save section \"%s\": Section end (%lu) > file_size (%lu)\n",
//					s_name, section_end_offset, file_size);
//		}
//		return;
//	}
//
//	unsigned char* section = NULL;
//	uint32_t size = readCharArrayFile(file_name, &section, sh->sh_offset, section_end_offset);
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
