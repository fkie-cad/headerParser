#ifndef HEADER_PARSER_PE_HEADER_SECTION_NAME_RESOLUTION_H
#define HEADER_PARSER_PE_HEADER_SECTION_NAME_RESOLUTION_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PEHeader.h"
#include "../Globals.h"
#include "../utils/Helper.h"

void PEgetRealName(const char* short_name, char** real_name, PECoffFileHeader* coff_header);
int PEgetNameOfStringTable(const char* short_name, char** real_name, PECoffFileHeader* coff_header);
int PEloadStringTable(PECoffFileHeader* coff_header);
uint32_t PEgetSizeOfStringTable(uint64_t ptr_to_string_table);

uint8_t PEisStringTableOffset(const char* short_name);

unsigned char *string_table = NULL;
uint32_t size_of_string_table = 0;

/**
 * If name is an offset (/xx), load the name from the string table.
 * Otherwise copy the short name into a string.
 * !! Allocates memory. The Caller has to free it !!!
 *
 * @param short_name
 * @param real_name
 * @param coff_header
 */
void PEgetRealName(const char* short_name, char** real_name, PECoffFileHeader* coff_header)
{
	size_t s_name_size = 0;
	size_t name_size = 0;
	int s = 0;

	debug_info("PEgetRealName");
	debug_info(" - raw name: %s\n",short_name);
	if ( PEisStringTableOffset(short_name) )
	{
		s = PEgetNameOfStringTable(short_name, real_name, coff_header);
		if ( s == 0 ) return;
	}

	s_name_size = strnlen(short_name, IMAGE_SIZEOF_SHORT_NAME);
	name_size = s_name_size+1;

	*real_name = (char*) calloc(name_size, sizeof(char));
	strncpy(*real_name, short_name, s_name_size);
}

uint8_t PEisStringTableOffset(const char* short_name)
{
	int i;
	if ( short_name[0] != '/' )
		return 0;

	for ( i = 1; i < IMAGE_SIZEOF_SHORT_NAME; i++ )
	{
		if ( short_name[i] == 0 )
			break;

		if ( short_name[i] < MIN_ASCII_INT || short_name[i] > MAX_ASCII_INT )
			return 0;
	}

	return 1;
}

int PEgetNameOfStringTable(const char* short_name, char** real_name, PECoffFileHeader* coff_header)
{
	size_t s_name_size = 0;
	size_t name_size = 0;
	int s = 0;
	uint32_t name_offset = 0;
	uint32_t max_name_ln = 0;

	if ( string_table == NULL )
	{
		s = PEloadStringTable(coff_header);
		if ( s != 0  || string_table == NULL )
			return 1;
	}
	name_offset = strtoul((&short_name[1]), NULL, 10);
	debug_info(" - - name_offset: %u\n", name_offset);
	debug_info(" - - size_of_string_table: %u\n", size_of_string_table);
	debug_info(" - - long name: %s\n", &string_table[name_offset]);

	if ( name_offset >= size_of_string_table - 1 )
	{
		header_info("INFO: offset to string table (%u) > size of string table (%u\n", name_offset, size_of_string_table);
		return 2;
	}

	max_name_ln = size_of_string_table - name_offset;
	if ( max_name_ln > MAX_SIZE_OF_SECTION_NAME ) max_name_ln = MAX_SIZE_OF_SECTION_NAME;

	s_name_size = strnlen((const char*)(&string_table[name_offset]), max_name_ln);
	name_size = s_name_size+1;

	*real_name = (char*) calloc(name_size, sizeof(char));
	strncpy(*real_name, (const char*)(&string_table[name_offset]), s_name_size);

	return 0;
}

int PEloadStringTable(PECoffFileHeader* coff_header)
{
	uint32_t size = 0;
	uint64_t ptr_to_string_table = (uint64_t)coff_header->PointerToSymbolTable + (coff_header->NumberOfSymbols * SIZE_OF_SYM_ENT);
	uint64_t end_of_string_table = 0;

	debug_info(" - - ptr to symbol table: 0x%X\n", coff_header->PointerToSymbolTable);
	debug_info(" - - number of symbols: %u\n", coff_header->NumberOfSymbols);
	debug_info(" - - pointer to string table: %lu\n", ptr_to_string_table);

	if ( coff_header->PointerToSymbolTable == 0 || coff_header->NumberOfSymbols == 0 || ptr_to_string_table == 0 )
		return 3;

	size_of_string_table = PEgetSizeOfStringTable(ptr_to_string_table);
	if ( size_of_string_table == 0 )
		return 4;

	end_of_string_table = ptr_to_string_table + size_of_string_table;
	debug_info(" - - size of string table: %u\n", size_of_string_table);
	debug_info(" - - end_of_string_table: %lu\n", end_of_string_table);
	if ( size_of_string_table == 0 )
		return 1;

	ptr_to_string_table += start_file_offset;
	end_of_string_table += start_file_offset;

	size = readCharArrayFile(file_name, &string_table, ptr_to_string_table, end_of_string_table);
	if ( !size )
	{
		prog_error("Read String Table failed.\n");
		return 2;
	}

	return 0;
}

uint32_t PEgetSizeOfStringTable(uint64_t ptr_to_string_table)
{
	uint32_t size_of_table = 0;
	uint32_t size;
	uint64_t end_of_size_info = ptr_to_string_table + PE_STRING_TABLE_SIZE_INFO_SIZE;

	if ( start_file_offset + end_of_size_info > file_size )
	{
		header_info("INFO: Image size info (%lu) is written beyond file_size (%u)\n", start_file_offset + end_of_size_info, file_size);
		return 0;
	}

	size = readBlock(file_name, start_file_offset + ptr_to_string_table);

	if ( !size )
	{
		prog_error("Read String Table Size Info failed.\n");
		return 0;
	}

	size_of_table = *((uint32_t*) &block_standard[0]);

	return size_of_table;
}

#endif