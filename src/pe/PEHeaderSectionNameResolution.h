#ifndef HEADER_PARSER_PE_HEADER_SECTION_NAME_RESOLUTION_H
#define HEADER_PARSER_PE_HEADER_SECTION_NAME_RESOLUTION_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PEHeader.h"
#include "../Globals.h"
#include "../utils/Helper.h"
#include "../utils/common_fileio.h"

void PE_getRealName(const char* short_name,
                    char** real_name,
                    PECoffFileHeader* coff_header,
                    size_t start_file_offset,
                    size_t file_size,
                    FILE* fp,
                    unsigned char* block_s,
                    PStringTable st);
int PE_getNameOfStringTable(const char* short_name,
                            char** real_name,
                            PECoffFileHeader* coff_header,
                            size_t start_file_offset,
                            size_t file_size,
                            FILE* fp,
                            unsigned char* block_s,
                            PStringTable st);
int PE_loadStringTable(PECoffFileHeader* coff_header,
                       size_t start_file_offset,
                       size_t file_size,
                       FILE* fp,
                       unsigned char* block_s,
                       PStringTable st);
uint32_t PE_getSizeOfStringTable(size_t ptr_to_string_table,
                                 size_t start_file_offset,
                                 size_t file_size,
                                 FILE* fp,
                                 unsigned char* block_s);

uint8_t PE_isStringTableOffset(const char* short_name);



/**
 * If name is an offset (/xx), load the name from the string table.
 * Otherwise copy the short name into a string.
 * !! Allocates memory. The Caller has to free it !!!
 *
 * @param short_name
 * @param real_name
 * @param coff_header
 */
void PE_getRealName(const char* short_name,
                    char** real_name,
                    PECoffFileHeader* coff_header,
                    size_t start_file_offset,
                    size_t file_size,
                    FILE* fp,
                    unsigned char* block_s,
                    PStringTable st)
{
    size_t s_name_size = 0;
    size_t name_size = 0;
    int s = 0;

    DPrint("PE_getRealName");
    DPrint(" - raw name: %s\n",short_name);
    if ( PE_isStringTableOffset(short_name) )
    {
        s = PE_getNameOfStringTable(short_name, real_name, coff_header, start_file_offset, file_size, fp, block_s, st);
        if ( s == 0 ) return;
    }

    s_name_size = strnlen(short_name, IMAGE_SIZEOF_SHORT_NAME);
    name_size = s_name_size+1;

    *real_name = (char*) calloc(name_size, sizeof(char));
    strncpy(*real_name, short_name, s_name_size);
}

/**
 * Check if short name is a string table offset (/xx).
 *
 * @param short_name
 * @return
 */
uint8_t PE_isStringTableOffset(const char* short_name)
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

int PE_getNameOfStringTable(const char* short_name,
                            char** real_name,
                            PECoffFileHeader* coff_header,
                            size_t start_file_offset,
                            size_t file_size,
                            FILE* fp,
                            unsigned char* block_s,
                            PStringTable st)
{
    size_t s_name_size = 0;
    size_t name_buf_size = 0;
    int s = 0;
    uint32_t name_offset = 0;
    uint32_t max_name_ln = 0;

    if ( st->strings == NULL )
    {
        s = PE_loadStringTable(coff_header, start_file_offset, file_size, fp, block_s, st);
        if ( s != 0  || st->strings == NULL )
            return 1;
    }
    name_offset = strtoul((&short_name[1]), NULL, 10);
    DPrint(" - - name_offset: %u\n", name_offset);
    DPrint(" - - size_of_string_table: %u\n", st->size);
    DPrint(" - - long name: %s\n", &st->strings[name_offset]);

    if ( name_offset >= st->size - 1 )
    {
        header_info("INFO: offset to string table (%u) > size of string table (%u\n", name_offset, st->size);
        return 2;
    }

    max_name_ln = st->size - name_offset;
    if ( max_name_ln > MAX_SIZE_OF_SECTION_NAME )
        max_name_ln = MAX_SIZE_OF_SECTION_NAME;

    s_name_size = strnlen((const char*)(&st->strings[name_offset]), max_name_ln);
    name_buf_size = s_name_size+1;

    *real_name = (char*) calloc(name_buf_size, sizeof(char));
    strncpy(*real_name, (const char*)(&st->strings[name_offset]), s_name_size);

    return 0;
}

int PE_loadStringTable(PECoffFileHeader* coff_header,
                       size_t start_file_offset,
                       size_t file_size,
                       FILE* fp,
                       unsigned char* block_s,
                       PStringTable st)
{
    size_t size = 0;
    size_t ptr_to_string_table = (size_t)coff_header->PointerToSymbolTable + (coff_header->NumberOfSymbols * SIZE_OF_SYM_ENT);
    size_t end_of_string_table = 0;

    DPrint(" - - ptr to symbol table: 0x%X\n", coff_header->PointerToSymbolTable);
    DPrint(" - - number of symbols: %u\n", coff_header->NumberOfSymbols);
    DPrint(" - - pointer to string table: 0x%zx\n", ptr_to_string_table);

    if ( coff_header->PointerToSymbolTable == 0 || coff_header->NumberOfSymbols == 0 || ptr_to_string_table == 0 )
        return 3;

    st->size = PE_getSizeOfStringTable(ptr_to_string_table, start_file_offset, file_size, fp, block_s);
    if ( st->size == 0 )
        return 4;

    end_of_string_table = ptr_to_string_table + st->size;
    DPrint(" - - size of string table: %u\n", st->size);
    DPrint(" - - end_of_string_table: 0x%zx\n", end_of_string_table);
    if ( st->size == 0 )
        return 1;

    ptr_to_string_table += start_file_offset;
    end_of_string_table += start_file_offset;

//	size = readCharArrayFile(fp, &st->strings, ptr_to_string_table, end_of_string_table);
    size = readFileA(fp, (size_t)ptr_to_string_table, (size_t)end_of_string_table, &st->strings);
    if ( !size )
    {
        prog_error("Read String Table failed.\n");
        return 2;
    }

    return 0;
}

uint32_t PE_getSizeOfStringTable(size_t ptr_to_string_table, size_t start_file_offset, size_t file_size, FILE* fp, unsigned char* block_s)
{
    uint32_t size_of_table = 0;
    size_t size;
    size_t end_of_size_info = ptr_to_string_table + PE_STRING_TABLE_SIZE_INFO_SIZE;

    if ( start_file_offset + end_of_size_info > file_size )
    {
        header_info("INFO: Image size info (0x%zx) is written beyond file_size (0x%zx)\n", start_file_offset + end_of_size_info, file_size);
        return 0;
    }

//	size = readCustomBlock(file_name, start_file_offset + ptr_to_string_table, BLOCKSIZE, block_s);
    size = readFile(fp, (size_t)(start_file_offset + ptr_to_string_table), BLOCKSIZE, block_s);

    if ( !size )
    {
        prog_error("Read String Table Size Info failed.\n");
        return 0;
    }

    size_of_table = *((uint32_t*) &block_s[0]);

    return size_of_table;
}

#endif